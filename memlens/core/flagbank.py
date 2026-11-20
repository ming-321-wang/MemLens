"""
MemLens · 旗标聚合台（跨产物找 flag）

## 为什么要单独一层

内存取证夺旗题里，flag 可能出现在**任何**插件产出里：命令行、环境变量、剪贴板、
网络回包、注册表值、进程内存块……逐个插件结果去翻是低效的。这里把案件内**全部记录**
用统一的正则过一遍，按"值"聚合去重，并保留出处与偏移，一次性给出候选清单。

## 噪声控制（这条是实测踩出来的）

第一版把"任意 `前缀{...}`"也当成候选，结果 `E:\\vol_easy.vmem` 一案里：
`memstrings.ioc` 一个插件就产出 15.9 万条记录，旗标页被
`keyword.control.io` / `keys.cc` / `github.com` / `http://opensource.org/licenses/MIT`
之类灌满（300 条候选里真答案在第 1 条，后面全废）。

因此聚合规则收紧为：
  * **只有 `memstrings.flag` 的结构化行**才当作"确定命中"（它自带 encoding/decoded/offset）；
  * 其它插件的记录**只认主模式**（`flag{`/`ctf{`/`key{` 这类），不跑宽松模式；
  * `疑似` 类候选默认不进结论条，且总量封顶；
  * 排序：明文 → 解码出 flag → 其它编码 → 疑似。
"""

from __future__ import annotations

import json
import re
from typing import Any

#: 主模式：形态明确的 flag（大小写不敏感）
MAIN_RE = re.compile(
    r"(?i)\b(?:flag|ctf|key|qsnctf|nssctf|sctf|dasctf|moectf|hgame|n1ctf|buuctf)\{[^{}\r\n]{1,300}\}"
)
#: 宽松模式：任意前缀 `xxx{...}`（默认只用于字节扫描结果，且降级排序）
LOOSE_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_]{1,15}\{[ -~]{6,200}\}")

#: 宽松命中的噪声前缀（模板语言 / JS 关键字 / i18n）
STOPWORDS = frozenset("""
else if elseif for while do switch case default break continue function return
var let const new typeof instanceof try catch finally throw class extends import
export async await this super null true false undefined i18n i18nraw
textdirection localize translate mathit mathrm keyword
""".split())
_GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}")
_PREFIX_RE = re.compile(r"(?i)^(flag|ctf|key|qsnctf|nssctf|sctf|dasctf|moectf|hgame|n1ctf|buuctf)\{")
#: 宽松候选里这些字符说明它是代码/JSON 片段，不是 flag
_BAD_CHARS_RE = re.compile(r'[\s"\\/<>]')


def _kind(value: str) -> str:
    """'明文' 只有一种定义：`flag{`/`ctf{`/`key{`… 开头。"""
    return "明文" if _PREFIX_RE.match(value) else "疑似"


def _loose_ok(value: str) -> bool:
    prefix = value.split("{", 1)[0]
    if prefix.lower() in STOPWORDS:
        return False
    if _GUID_RE.search(value) or _BAD_CHARS_RE.search(value):
        return False
    return True


def collect(store: Any, case_id: str, *, limit: int = 300,
            include_loose: bool = False, loose_cap: int = 50) -> list[dict[str, Any]]:
    """
    汇总案件内所有记录里的 flag 候选（已去重、已排序）。

    Args:
        include_loose: 是否连"任意前缀{...}"的疑似候选一起收（界面上的「宽松模式」）
        loose_cap: 疑似候选的数量上限（防止模板噪声淹没真答案）
    """
    hits: dict[str, dict[str, Any]] = {}

    def add(value: str, source: str, *, offset: Any = None, ctx: str = "",
            decoded: str = "", kind: str | None = None, count: int = 1) -> None:
        value = value.strip()
        if not value or len(value) > 320:
            return
        item = hits.get(value)
        if item is None:
            item = hits[value] = {
                "value": value,
                "kind": kind or _kind(value),
                "sources": [],
                "count": 0,
                "offset": None,
                "offset_hex": "",
                "ctx": "",
                "decoded": decoded,
            }
        item["count"] = int(item["count"]) + max(int(count or 1), 1)
        if source not in item["sources"]:
            item["sources"].append(source)
        if ctx and not item["ctx"]:
            item["ctx"] = ctx
        if decoded and not item["decoded"]:
            item["decoded"] = decoded
        if item["offset"] is None and isinstance(offset, int):
            item["offset"] = offset
            item["offset_hex"] = f"0x{offset:X}"

    loose_seen = 0
    for rec, plugin in store.records_with_source(case_id, limit=2_000_000,
                                                skip_plugins=("intel.", "memlens.")):
        if not isinstance(rec, dict):
            continue
        # ---------- ① 字节扫描的结构化命中：确定度最高 ----------
        if plugin.startswith("memstrings.flag"):
            value = str(rec.get("value") or "")
            enc = str(rec.get("encoding") or "")
            decoded = str(rec.get("decoded") or "")
            if not value:
                continue
            if enc.startswith("明文") or decoded:
                add(value, plugin, offset=rec.get("offset"),
                    ctx=str(rec.get("ctx_ascii") or "")[:200], decoded=decoded,
                    kind="明文" if enc.startswith("明文") else _kind(value),
                    count=int(rec.get("count") or 1))
            elif include_loose and _loose_ok(value):
                add(value, plugin, offset=rec.get("offset"),
                    ctx=str(rec.get("ctx_ascii") or "")[:200],
                    decoded=decoded, kind="疑似", count=int(rec.get("count") or 1))
            continue

        # ---------- ② 其它插件：只认主模式（不跑宽松，避免 15 万条 IOC 灌爆）----------
        blob = json.dumps(rec, ensure_ascii=False, default=str)
        if "{" not in blob:
            continue
        for m in MAIN_RE.finditer(blob):
            add(m.group(0), plugin)
        if include_loose:
            for m in LOOSE_RE.finditer(blob):
                text = m.group(0)
                if not _loose_ok(text):
                    continue
                if _PREFIX_RE.match(text):
                    continue                    # 主模式已经收过了
                if loose_seen >= loose_cap:
                    break
                loose_seen += 1
                add(text, plugin, kind="疑似")

    def rank(item: dict[str, Any]) -> tuple:
        kind = item["kind"]
        offset = item["offset"] if isinstance(item["offset"], int) else 1 << 62
        if kind == "明文":
            top = 0
        elif item.get("decoded"):
            top = 1
        elif kind == "疑似":
            top = 3
        else:
            top = 2
        return (top, -int(item["count"]), offset)

    return sorted(hits.values(), key=rank)[:limit]


def best(store: Any, case_id: str) -> dict[str, Any] | None:
    """最可能的那一条（给界面做"结论条"用）。"""
    got = collect(store, case_id, limit=1, include_loose=False)
    return got[0] if got else None
