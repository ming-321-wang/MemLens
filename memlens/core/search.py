r"""
MemLens · 跨产物检索引擎

## 为什么要有这个

取证分析员的日常动作不是"看表"，而是**问问题**：

    这个 IP 在哪儿出现过？
    这个域名跟哪个进程有关？
    哪些记录里提到了 xxx？

Volatility 有 `-f`/`--grep`，Wireshark 有 display filter，grep 有全文检索。
没有这些，看���只能是"人肉 Ctrl+F"，一张表几千行根本翻不动。

本模块把这件事变成**工具能力**，而不是让人手工翻。

## 覆盖范围

    scope=records     中间证据表 records（所有产物的每一行，JSON 全字段）
    scope=findings    检测器结论 findings
    scope=timeline    时间线事件
    scope=raw         产物原始文件内容（按字节流扫描，可选正则）
    scope=container   **加密容器 / 磁盘镜像内部**的文件内容
                      （VeraCrypt 卷 → exFAT → 逐文件扫，不落盘）

## 语法

    普通词      全文匹配（大小写不敏感）
    "带空格"    精确短语
    key:value   按字段过滤（records 用列名，如 pid:1234 / name:cmd.exe）
    /regex/     正则（需开 regex=True 或用 /…/ 包裹）
    -word       排除词

多个条件用空格分隔，是 AND 关系。
"""

from __future__ import annotations

import dataclasses
import json
import re
import time
from pathlib import Path
from typing import Any, Iterable, Iterator

#: 单条命中的上下文长度
CONTEXT = 120

#: 默认返回条数上限
DEFAULT_LIMIT = 200


@dataclasses.dataclass
class SearchHit:
    """一条命中。"""

    scope: str                 # records / findings / timeline / raw / container
    source: str                # 产物名 / 规则 ID / 事件来源
    case_id: str = ""
    row_no: int | None = None
    field: str = ""
    value: str = ""
    context: str = ""
    ts: str = ""
    offset: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope, "source": self.source, "case_id": self.case_id,
            "row_no": self.row_no, "field": self.field,
            "value": self.value[:400], "context": self.context[:600],
            "ts": self.ts, "offset": self.offset,
        }


# ─────────────────────────────────────────────────────── 查询解析
class Query:
    """把用户输入拆成：短语 / 字段过滤 / 排除词 / 正则。"""

    def __init__(self, text: str, *, regex: bool = False) -> None:
        self.raw = text or ""
        self.regex = regex
        self.terms: list[str] = []
        self.filters: list[tuple[str, str]] = []
        self.excludes: list[str] = []
        self.pattern: re.Pattern | None = None
        self._parse()

    def _parse(self) -> None:
        text = self.raw.strip()
        if not text:
            return
        # 正则：/.../ 包裹
        m = re.fullmatch(r"/(.*)/([a-z]*)", text, re.S)
        if m:
            flags = re.I if ("i" in m.group(2)) else 0
            try:
                self.pattern = re.compile(m.group(1), flags)
                return
            except re.error:
                pass
        # 拆词（保留 "引号短语"）
        for tok in re.findall(r'"[^"]+"|\S+', text):
            neg = False
            if tok.startswith("-") and len(tok) > 1:
                neg = True
                tok = tok[1:]
            if tok.startswith('"') and tok.endswith('"') and len(tok) >= 2:
                tok = tok[1:-1]
            if ":" in tok and not tok.startswith(":"):
                k, _, v = tok.partition(":")
                if k and v:
                    self.filters.append((k.lower(), v))
                    continue
            if neg:
                self.excludes.append(tok.lower())
            else:
                self.terms.append(tok)

    @property
    def needles(self) -> list[str]:
        return [t.lower() for t in self.terms if t]

    def matches_text(self, text: str) -> bool:
        if not text:
            return False
        low = text.lower()
        if self.pattern is not None:
            if not self.pattern.search(text):
                return False
        else:
            for n in self.needles:
                if n not in low:
                    return False
        for x in self.excludes:
            if x in low:
                return False
        return True

    def filter_ok(self, fields: dict[str, Any]) -> bool:
        for k, v in self.filters:
            got = fields.get(k)
            if got is None:
                return False
            if str(got).lower() != v.lower():
                # 也允许"包含"式匹配，便于 name:cmd 命中 cmd.exe
                if v.lower() not in str(got).lower():
                    return False
        return True

    def describe(self) -> str:
        bits = []
        if self.pattern is not None:
            bits.append(f"正则 /{self.pattern.pattern}/")
        if self.terms:
            bits.append("词 " + " AND ".join(self.terms))
        for k, v in self.filters:
            bits.append(f"{k}={v}")
        for x in self.excludes:
            bits.append(f"-{x}")
        return "  ".join(bits) or "(空查询)"


# ─────────────────────────────────────────────────────── 上下文
def _context(text: str, pos: int, needle_len: int) -> str:
    s = max(0, pos - CONTEXT // 2)
    e = min(len(text), pos + needle_len + CONTEXT // 2)
    out = text[s:e].replace("\n", " ").replace("\r", " ")
    if s > 0:
        out = "…" + out
    if e < len(text):
        out = out + "…"
    return out


def _snippet(text: str, q: Query) -> str:
    """给出一条可读上下文（尽量定位到命中位置）。"""
    low = text.lower()
    pos = -1
    if q.pattern is not None:
        m = q.pattern.search(text)
        pos = m.start() if m else -1
    else:
        for n in q.needles:
            p = low.find(n)
            if p >= 0 and (pos < 0 or p < pos):
                pos = p
    if pos < 0:
        return text[:CONTEXT].replace("\n", " ")
    nlen = q.needles[0].__len__() if q.needles else 8
    return _context(text, pos, nlen)


# ─────────────────────────────────────────────────────── 数据库检索
def search_records(store: Any, case_id: str, q: Query, *,
                   limit: int = DEFAULT_LIMIT) -> list[SearchHit]:
    """检索中间证据表（records）。"""
    from sqlalchemy import select
    from memlens.storage import models as M

    out: list[SearchHit] = []
    stmt = select(M.records.c.artifact_id, M.records.c.row_no,
                  M.records.c.data, M.records.c.ts_utc,
                  M.records.c.name, M.records.c.remote, M.records.c.pid,
                  M.records.c.evidence_no)
    with store.engine.connect() as conn:          # ★ SQLAlchemy 2.x 必须用连接上下文
        rows = conn.execute(stmt).fetchall()
    art_map = {}
    try:
        for a in store.list_artifacts(case_id):
            art_map[a["artifact_id"]] = a
    except Exception:
        pass
    for r in rows:
        art_id = r[0]
        art = art_map.get(art_id)
        # ★ 只有**指定了案件**才按案件过滤；
        #   未指定时是"全库检索"，若还按 art.case_id != "" 过滤，
        #   会把所有属于具体案件的记录全部丢掉（实测：命中 0 条）。
        if case_id:
            if art is None or art.get("case_id") not in (None, case_id):
                continue
        try:
            data = json.loads(r[2]) if isinstance(r[2], str) else (r[2] or {})
        except Exception:
            data = {"_raw": str(r[2])}
        if not isinstance(data, dict):
            data = {"_value": str(data)}
        if not q.filter_ok(data):
            continue
        # ★ 匹配面 = 键 + 值。
        #   只匹配值的话，搜 "pid" 命中不了任何带 pid 列的记录，
        #   写 `cmd.exe -pid` 这种排除式也会失效（实测）。
        #   统一成"键值都在检索面内"，行为与 grep 一致、可预期。
        blob = " ".join(f"{k} {v}" for k, v in data.items())
        if not q.matches_text(blob):
            continue
        hit_field = ""
        hit_value = ""
        for k, v in data.items():
            if q.matches_text(str(v)):
                hit_field = str(k)
                hit_value = str(v)
                break
        out.append(SearchHit(
            scope="records",
            source=(art or {}).get("plugin", art_id),
            case_id=case_id, row_no=r[1], field=hit_field, value=hit_value,
            context=_snippet(blob, q), ts=r[3] or "",
        ))
        if len(out) >= limit:
            break
    return out


def search_findings(store: Any, case_id: str, q: Query, *,
                    limit: int = DEFAULT_LIMIT) -> list[SearchHit]:
    """检索检测器结论。"""
    from sqlalchemy import select
    from memlens.storage import models as M

    stmt = select(M.findings.c.rule_id, M.findings.c.detector, M.findings.c.title,
                  M.findings.c.description, M.findings.c.severity,
                  M.findings.c.category, M.findings.c.created_at,
                  M.findings.c.finding_id)
    if case_id:
        stmt = stmt.where(M.findings.c.case_id == case_id)
    out: list[SearchHit] = []
    with store.engine.connect() as conn:
        frows = conn.execute(stmt).fetchall()
    for r in frows:
        blob = " ".join(str(x) for x in (r[2], r[3], r[4], r[5]))
        if not q.matches_text(blob):
            continue
        out.append(SearchHit(scope="findings", source=r[0] or r[1] or "",
                              case_id=case_id, row_no=r[7],
                              field="title", value=str(r[2]),
                              context=_snippet(blob, q), ts=r[6] or ""))
        if len(out) >= limit:
            break
    return out


def search_timeline(store: Any, case_id: str, q: Query, *,
                    limit: int = DEFAULT_LIMIT) -> list[SearchHit]:
    """检索时间线事件。"""
    from sqlalchemy import select
    from memlens.storage import models as M

    stmt = select(M.timeline_events.c.ts_utc, M.timeline_events.c.source,
                  M.timeline_events.c.category, M.timeline_events.c.title,
                  M.timeline_events.c.detail, M.timeline_events.c.event_id)
    if case_id:
        stmt = stmt.where(M.timeline_events.c.case_id == case_id)
    out: list[SearchHit] = []
    with store.engine.connect() as conn:
        trows = conn.execute(stmt).fetchall()
    for r in trows:
        blob = " ".join(str(x) for x in (r[1], r[2], r[3], r[4]))
        if not q.matches_text(blob):
            continue
        out.append(SearchHit(scope="timeline", source=str(r[1] or r[2] or ""),
                              case_id=case_id, row_no=r[5], field="title",
                              value=str(r[3]), context=_snippet(blob, q),
                              ts=str(r[0] or "")))
        if len(out) >= limit:
            break
    return out


# ─────────────────────────────────────────────────────── 二进制扫描
def scan_bytes(data: bytes, q: Query, *, source: str = "raw",
               case_id: str = "", limit: int = 200,
               regex: bool = False) -> list[SearchHit]:
    """在字节流里检索（可打印文本）。"""
    if regex:
        q = Query(q.raw, regex=True)
    out: list[SearchHit] = []
    if q.pattern is not None:
        for m in q.pattern.finditer(data):
            out.append(SearchHit(scope="raw", source=source, case_id=case_id,
                                 field="", value="",
                                 context=_context(data[m.start():m.start() + 80].decode("latin-1", "replace"), 0, 0),
                                 offset=m.start()))
            if len(out) >= limit:
                break
        return out
    low = data.lower()
    for n in q.needles:
        start = 0
        while True:
            i = low.find(n.encode("latin-1"), start)
            if i < 0:
                break
            out.append(SearchHit(scope="raw", source=source, case_id=case_id,
                                 field="", value=n,
                                 context=_context(data[i:i + 240].decode("latin-1", "replace"), 0, 0),
                                 offset=i))
            start = i + max(1, len(n))
            if len(out) >= limit:
                return out
    return out


def scan_file(path: str | Path, q: Query, *, source: str = "",
              case_id: str = "", limit: int = 200,
              chunk: int = 8 << 20, regex: bool = False) -> list[SearchHit]:
    """流式扫描文件（不整文件读进内存）。"""
    if regex:
        q = Query(q.raw, regex=True)
    p = Path(path)
    out: list[SearchHit] = []
    if not p.is_file():
        return out
    needles = [n.encode("latin-1") for n in q.needles]
    pat = q.pattern
    with p.open("rb") as f:
        pos = 0
        prev = b""
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            data = prev + buf
            base = pos - len(prev)
            if pat is not None:
                for m in pat.finditer(data.decode("latin-1", "replace")):
                    out.append(SearchHit(scope="raw", source=source or p.name,
                                         case_id=case_id, value="",
                                         context=_context(m.group(0), 0, 0),
                                         offset=base + m.start()))
                    if len(out) >= limit:
                        return out
            else:
                low = data.lower()
                for n in needles:
                    st = 0
                    while True:
                        i = low.find(n, st)
                        if i < 0:
                            break
                        out.append(SearchHit(scope="raw", source=source or p.name,
                                             case_id=case_id, value=n.decode(),
                                             context=_context(data[i:i + 240].decode("latin-1", "replace"), 0, 0),
                                             offset=base + i))
                        st = i + max(1, len(n))
                        if len(out) >= limit:
                            return out
            prev = data[-256:]
            pos += len(buf)
    return out


# ─────────────────────────────────────────────────────── 容器内检索
def scan_container(vol: Any, fs: Any, ent: dict, q: Query, *,
                   source: str = "", case_id: str = "",
                   limit: int = 200, chunk: int = 8 << 20,
                   regex: bool = False) -> list[SearchHit]:
    """
    在加密卷内的某个文件里流式检索。

    不把文件落盘，直接从解密卷里按簇读，命中即返回。
    """
    if regex:
        q = Query(q.raw, regex=True)
    out: list[SearchHit] = []
    needles = [n.encode("latin-1") for n in q.needles]
    pat = q.pattern
    total = ent["data_len"]
    # 逐簇读
    done = 0
    prev = b""
    base_off = 0
    if ent.get("no_fat_chain"):
        start = fs.cluster_offset(ent["first_cluster"])
        while done < total and len(out) < limit:
            n = min(chunk, total - done)
            data = vol.read(start + done, n)
            hits = _scan_buf(data, q, needles, pat, base_off, source, case_id,
                             limit - len(out))
            out.extend(hits)
            done += n
            base_off += n
            if not data:
                break
    else:
        idx = 0
        for c in fs.chain(ent["first_cluster"]):
            if len(out) >= limit:
                break
            blk = fs.read_cluster(c)
            if not blk:
                break
            take = min(len(blk), total - done)
            data = prev + blk[:take]
            hits = _scan_buf(data, q, needles, pat, base_off, source, case_id,
                             limit - len(out))
            out.extend(hits)
            base_off += take
            done += take
            prev = blk[-256:]
            idx += 1
    return out


def _scan_buf(data: bytes, q: Query, needles: list[bytes], pat, base_off: int,
              source: str, case_id: str, limit: int) -> list[SearchHit]:
    out: list[SearchHit] = []
    if pat is not None:
        txt = data.decode("latin-1", "replace")
        for m in pat.finditer(txt):
            out.append(SearchHit(scope="container", source=source, case_id=case_id,
                                 value="", context=_context(m.group(0), 0, 0),
                                 offset=base_off + m.start()))
            if len(out) >= limit:
                break
        return out
    low = data.lower()
    for n in needles:
        st = 0
        while True:
            i = low.find(n, st)
            if i < 0:
                break
            out.append(SearchHit(scope="container", source=source, case_id=case_id,
                                 value=n.decode("latin-1", "replace"),
                                 context=_context(data[i:i + 240].decode("latin-1", "replace"), 0, 0),
                                 offset=base_off + i))
            st = i + max(1, len(n))
            if len(out) >= limit:
                return out
    return out


# ─────────────────────────────────────────────────────── 统一入口
def search(store: Any, case_id: str, text: str, *,
           scopes: Iterable[str] = ("records", "findings", "timeline"),
           regex: bool = False, limit: int = DEFAULT_LIMIT) -> dict[str, Any]:
    """统一检索入口。"""
    q = Query(text, regex=regex)
    t0 = time.time()
    hits: list[SearchHit] = []
    scopes = list(scopes)
    if "records" in scopes:
        hits += search_records(store, case_id, q, limit=limit)
    if "findings" in scopes:
        hits += search_findings(store, case_id, q, limit=limit)
    if "timeline" in scopes:
        hits += search_timeline(store, case_id, q, limit=limit)
    return {
        "query": q.raw,
        "parsed": q.describe(),
        "scopes": scopes,
        "count": len(hits),
        "elapsed": round(time.time() - t0, 3),
        "hits": [h.to_dict() for h in hits[:limit]],
    }
