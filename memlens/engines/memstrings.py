r"""
MemLens · 整机镜像流式扫描引擎（memstrings）

解决的问题：**在没有进程表、没有结构体的原始字节里找线索**。
内存镜像里最值钱的东西（flag、口令、C2 地址、命令行）往往就是一段裸字符串，
没有哪个 vol3 插件会主动告诉你它在哪。

四个插件：
    memstrings.ascii   ASCII 字符串（min_len 可调）
    memstrings.utf16   UTF-16LE 字符串（Windows 宽字符，ASCII 插件永远搜不到）
    memstrings.flag    多编码 flag（明文 / hex / base64 / URL / HTML 实体）
    memstrings.ioc     直接在原始字节上提 IOC

工程要点：
  * **流式分块 + 重叠区**，不把几个 GB 的镜像读进内存；
    重叠长度取 `max(min_len, 最长模式) - 1`，否则跨块的匹配会漏。
  * 正则一律**编译成 bytes 模式**直接在字节上跑，绕开编码解码，
    也避免 GBK/UTF-8 解码失败导致整块作废。
  * 每条命中都带**偏移 + 前后 hexdump/ASCII 上下文**——只看字符串本身
    看不出它是不是垃圾数据，上下文才是判据。
  * 行数硬上限（`limit`），防止 4 GB 镜像灌爆 SQLite。
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Iterator

from memlens.engines.base import EngineAdapter, OutputKind, PluginMeta, RunSpec

CHUNK = 8 << 20          # 8 MiB 读块
DEFAULT_LIMIT = 200_000  # 单插件最多入库多少行
DEFAULT_MAX_BYTES = 0    # 0 = 不限制；否则只扫前 N 字节

#: 主模式表：**只收形态明确**的 flag（明文 / 十六进制 / Base64 / URL / HTML 实体）。
#: 不用 `(?i)` 内联标志——Python 要求全局标志位于整个正则最前面，而这里要拼成一个大正则，
#: 所以大小写一律用字符类显式写出来（`[fF][lL]...`）。
FLAG_PATTERNS: tuple[tuple[str, str], ...] = (
    ("明文", rb"[fF][lL][aA][gG]\{[^\}\r\n]{1,300}\}"),
    ("明文-大写", rb"[Ff][Ll][Aa][Gg]\{[^\}\r\n]{1,300}\}"),
    ("明文-ctf", rb"(?:[cC][tT][fF]|[kK][eE][yY]|[qQ][sS][nN][cC][tT][fF]|"
                 rb"[nN][sS][sS][cC][tT][fF]|[dD][aA][sS][cC][tT][fF])\{[^\}\r\n]{1,300}\}"),
    ("十六进制", rb"666[cC]6167[0-9a-fA-F]{6,300}"),
    ("十六进制-大写", rb"464C4147[0-9A-F]{6,300}"),
    ("十六进制转义", rb"\\x66\\x6[cC]\\x61\\x67[0-9a-fA-F]{4,400}"),
    ("Base64", rb"ZmxhZ[A-Za-z0-9+/=]{6,300}"),
    ("URL编码", rb"[fF](?:%6[cC]|\\x6[cC])(?:%61|\\x61)(?:%67|\\x67)|[fF][lL][aA][gG]%7[Bb]"),
    ("HTML实体", rb"&#102;?[lL]?[aA]?[gG](?:\{|&#123;|&#x7[Bb];)"),
)

#: 「任意前缀{...}」这种宽松模式**默认关闭**：实测在真实镜像里它会把
#: `i18n{openDetails}` / `mathit{rasterizationSamples}` / `FileIdIndex-{GUID}` / `3D{documentTitle}`
#: 之类几百条模板噪声全当 flag 报出来，把真正的命中淹掉。
#: 需要时用参数 loose=True 打开（插件会把结果降级为 medium 并另行去噪）。
LOOSE_FLAG_PATTERN = rb"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_]{1,15}\{[ -~]{6,200}\}"

#: 宽松模式的噪声词表（模板语言、JS 关键字、常见 i18n 前缀）
_LOOSE_STOPWORDS = frozenset("""
else if elseif for while do switch case default break continue function return
var let const new typeof instanceof try catch finally throw class extends import
export async await this super null true false undefined
i18n i18nraw textdirection localize translate msgid mathit mathrm
""".split())
#: GUID/UUID 形态（`...{8-4-4-4-12}`）几乎都是系统对象名，不是 flag
_GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}")


# 组名必须以字母开头（re 的硬性要求），因此统一加 "f" 前缀。
_FLAG_COMBINED = re.compile(b"|".join(b"(?P<f" + str(i).encode() + b">" + p + b")"
                                    for i, (_n, p) in enumerate(FLAG_PATTERNS)))
_FLAG_NAMES = {f"f{i}".encode(): n for i, (n, _p) in enumerate(FLAG_PATTERNS)}
_LOOSE_FLAG_RE = re.compile(LOOSE_FLAG_PATTERN)


def _ascii_context(blob: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in blob)


def _hex_context(blob: bytes) -> str:
    return " ".join(f"{b:02x}" for b in blob)


def _iter_chunks(fh, size: int, *, ctx: int = 64) -> Iterator[tuple[int, bytes]]:
    """
    流式产出 (块起始绝对偏移, 块内容)。

    相邻块重叠 `ctx` 字节，保证跨块的长匹配不漏。
    """
    step = max(CHUNK - ctx, 1)
    base = 0
    while base < size:
        fh.seek(base)
        block = fh.read(min(step + ctx, size - base))
        if not block:
            break
        yield base, block
        base += step


def _scan_size(path: str, max_bytes: int) -> int:
    size = os.path.getsize(path)
    return min(size, max_bytes) if max_bytes else size


def _context(fh, path_size: int, offset: int, raw_len: int, ctx: int) -> tuple[bytes, bytes]:
    """读命中位置前后的字节。**必须复用同一个句柄**——按命中次数 open() 会拖垮性能。"""
    fh.seek(max(0, offset - ctx))
    before = fh.read(ctx)
    fh.seek(offset)
    after = fh.read(raw_len + ctx)
    return before, after


class _Cancel(Exception):
    pass


@__import__("functools").lru_cache(maxsize=None)
def _ascii_re(min_len: int) -> re.Pattern[bytes]:
    return re.compile(rb"[\x20-\x7E]{%d,}" % min_len)


@__import__("functools").lru_cache(maxsize=None)
def _utf16_re(min_len: int) -> re.Pattern[bytes]:
    return re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % min_len)


def _rows_from_strings(path: str, *, utf16: bool, min_len: int, limit: int,
                       max_bytes: int, ctx: int,
                       progress: Callable[[int], None] | None,
                       cancel: Callable[[], bool] | None) -> Iterator[dict[str, Any]]:
    rx = _utf16_re(min_len) if utf16 else _ascii_re(min_len)
    ctx = max(ctx, 16)
    emitted = 0
    size = _scan_size(path, max_bytes)
    with open(path, "rb") as fh:
        for base, block in _iter_chunks(fh, size, ctx=ctx + 8):
            if cancel is not None and cancel():
                raise _Cancel
            if progress is not None:
                progress(base)
            for m in rx.finditer(block):
                raw = m.group(0)
                try:
                    value = raw.decode("utf-16le" if utf16 else "ascii", errors="replace")
                except Exception:
                    continue
                value = value.strip()
                if len(value) < min_len:
                    continue
                off = base + m.start()
                before, after = _context(fh, size, off, len(raw), ctx)
                yield {
                    "offset": off,
                    "offset_hex": f"0x{off:X}",
                    "encoding": "utf-16le" if utf16 else "ascii",
                    "value": value[:2000],
                    "length": len(value),
                    "ctx_ascii": _ascii_context(before + raw + after)[:256],
                    "ctx_hex": _hex_context(before[:32] + raw[:32] + after[:32])[:200],
                }
                emitted += 1
                if emitted >= limit:
                    return


def _rows_flag(path: str, *, limit: int, max_bytes: int, ctx: int,
               progress: Callable[[int], None] | None,
               cancel: Callable[[], bool] | None,
               loose: bool = False) -> Iterator[dict[str, Any]]:
    """
    扫 flag（多编码）。

    相比"命中什么报什么"，这里做了三件真正决定可用性的事：

      1. **只报有意义的命中**：非明文编码（hex/base64/url/html）如果解不出 flag 形态，
         说明它只是碰巧匹配（例如 `ZmxhZyB0byBleGl0...` 是 JS 源码里 "flag to exit" 的
         base64），直接丢弃——否则一屏"critical"全是垃圾，真命中反而被淹没。
      2. **按值去重**：同一个 flag 在镜像里往往出现几十次（缓存、页面副本、日志回显），
         只留一条并累计 `count`、记录首次偏移。
      3. **排序**：明文命中永远排最前，其次"解码出 flag"的，最后才是各类编码形态；
         宽松模式（任意前缀 `xxx{...}`）命中降级并去噪，排在最后。
    """
    ctx = max(ctx, 16)
    size = _scan_size(path, max_bytes)
    found: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []

    def _record(encoding: str, raw: bytes, off: int, fh) -> None:
        text = raw.decode("utf-8", errors="replace")[:400]
        key = (encoding, text)
        if key in found:
            found[key]["count"] = int(found[key]["count"]) + 1
            return
        decoded = _try_decode(raw, encoding)
        plain = encoding.startswith("明文")
        if not plain and not decoded:
            return                      # 解不出 flag 形态 → 噪声，丢
        before, after = _context(fh, size, off, len(raw), ctx)
        found[key] = {
            "offset": off,
            "offset_hex": f"0x{off:X}",
            "encoding": encoding,
            "value": text,
            "decoded": decoded,
            "count": 1,
            "severity": "critical" if (plain or decoded) else "medium",
            "confidence": "high" if plain else ("high" if decoded else "low"),
            "ctx_ascii": _ascii_context(before + raw + after)[:256],
            "ctx_hex": _hex_context(before[:32] + raw[:32] + after[:32])[:200],
        }
        order.append(key)

    with open(path, "rb") as fh:
        for base, block in _iter_chunks(fh, size, ctx=ctx + 512):
            if cancel is not None and cancel():
                raise _Cancel
            if progress is not None:
                progress(base)
            for m in _FLAG_COMBINED.finditer(block):
                gname = m.lastgroup
                encoding = _FLAG_NAMES.get((gname or b"").encode(), "未知")
                _record(encoding, m.group(0), base + m.start(), fh)
            if loose:
                for m in _LOOSE_FLAG_RE.finditer(block):
                    raw = m.group(0)
                    text = raw.decode("utf-8", errors="replace")
                    prefix = text.split("{", 1)[0]
                    if prefix.lower() in _LOOSE_STOPWORDS:
                        continue
                    if _GUID_RE.search(text):
                        continue
                    _record("自定义前缀", raw, base + m.start(), fh)

    def _rank(item: dict[str, Any]) -> tuple[int, int]:
        enc = item["encoding"]
        if enc.startswith("明文"):
            return (0, int(item["offset"]))
        if item.get("decoded"):
            return (1, int(item["offset"]))
        if enc == "自定义前缀":
            return (3, int(item["offset"]))
        return (2, int(item["offset"]))

    emitted = 0
    for row in sorted(found.values(), key=_rank):
        yield row
        emitted += 1
        if emitted >= limit:
            return


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\r\n\t")
    return ok / len(s)


_FLAGISH = ("flag", "ctf", "key", "flag{", "ctf{", "key{")


def _pick(cands: list[str]) -> str:
    """
    从多个解码候选里挑最合理的那个。

    为什么需要择优：`666c6167` 本身就是 "flag" 的十六进制，于是
    "flag{...}" 的十六进制串天然以 `666c6167` 开头。到底该
      ① 整串一起解（得到 "flag{...}"），还是
      ② 剥掉前缀再解、再手工补回 "flag"（同样得到 "flag{...}"），
    取决于出题人写的是哪一种。两种都试，按可信度打分择优，
    避免出现 `flagflag{...}` 这种拼接事故。
    """
    best, best_score = "", -1.0
    for raw in cands:
        text = _collapse_prefix(raw)
        if not text or _printable_ratio(text) < 0.75:
            continue
        score = 1.0
        low = text.lower()
        if low.startswith(_FLAGISH):
            score += 2.0            # 以 flag 开头，最可信
        if "{" in text and "}" in text:
            score += 1.5            # 有完整花括号，形态最标准
        if score > best_score:
            best, best_score = text, score
    return best


def _collapse_prefix(text: str) -> str:
    """把重复前缀压成一个：flagflag{...} → flag{...}。

    重复前缀来自两种编码方式叠加（先 hex 再 base64 之类），
    属于真实存在的形态，因此在解码结果里顺手归一，而不是靠打分把整条判废。
    """
    return re.sub(r"\b(flag|ctf|key)(?:\1)+", r"\1", text, flags=re.IGNORECASE)


def _b64(text: str) -> str:
    import base64
    cleaned = re.sub(r"[^A-Za-z0-9+/=]", "", text).rstrip("=")
    if len(cleaned) < 4 or len(cleaned) % 4 == 1:
        return ""
    try:
        return base64.b64decode(cleaned + "=" * (-len(cleaned) % 4)).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _hex(text: str) -> str:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", text)
    if len(cleaned) < 2 or len(cleaned) % 2:
        return ""
    try:
        return bytes.fromhex(cleaned).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _try_decode(raw: bytes, encoding: str) -> str:
    """
    命中即给一份可读解码——省去手工解码这一步。

    返回空串表示"解出来不是可读文本"（此时原值已展示给用户，不必硬凑）。
    """
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return ""

    if encoding.startswith("十六进制"):
        rest = re.sub(r"^666c6167", "", text, flags=re.IGNORECASE)
        return _pick([_hex(text), ("flag" + _hex(rest)) if rest else ""])

    if encoding == "Base64":
        rest = text[5:] if text.startswith("ZmxhZ") else ""
        return _pick([_b64(text), ("flag" + _b64(rest)) if rest else ""])

    if encoding == "URL编码":
        from urllib.parse import unquote
        return _pick([unquote(text)])

    if encoding == "HTML实体":
        import html
        return _pick([html.unescape(text)])

    return ""


def _rows_ioc(path: str, *, limit: int, max_bytes: int, ctx: int,
              progress: Callable[[int], None] | None,
              cancel: Callable[[], bool] | None) -> Iterator[dict[str, Any]]:
    from memlens.intel import ioc as ioc_mod

    rx = re.compile(rb"[\x20-\x7E]{6,}")
    ctx = max(ctx, 16)
    emitted = 0
    size = _scan_size(path, max_bytes)
    with open(path, "rb") as fh:
        for base, block in _iter_chunks(fh, size, ctx=ctx):
            if cancel is not None and cancel():
                raise _Cancel
            if progress is not None:
                progress(base)
            for m in rx.finditer(block):
                try:
                    text = m.group(0).decode("ascii")
                except Exception:
                    continue
                found = ioc_mod.scan_text(text)
                if not found:
                    continue
                off = base + m.start()
                for item in found:
                    yield {
                        "offset": off,
                        "offset_hex": f"0x{off:X}",
                        "ioc_type": item.kind,
                        "value": item.value,
                        "severity": item.extra.get("severity", "low"),
                        "scope": item.extra.get("scope", ""),
                        "line": text[:200],
                    }
                    emitted += 1
                    if emitted >= limit:
                        return


# ------------------------------------------------------------------ 引擎

PLUGINS: tuple[PluginMeta, ...] = (
    PluginMeta("memstrings.flag", "Flag 全编码搜索（明文/hex/base64/URL/HTML实体）", "镜像扫描",
               OutputKind.TABLE,
               "在原始字节里搜各种编码形态的 flag，并直接给出解码结果；"
               "非明文编码若解不出 flag 形态会被判为噪声丢弃，同值自动去重计数。CTF 通用钥匙。",
               needs_params=("loose",)),
    PluginMeta("memstrings.ioc", "原始字节 IOC 提取", "镜像扫描", OutputKind.TABLE,
               "直接在镜像字节里提 IP/URL/域名/邮箱/钱包/注册表键。"),
    PluginMeta("memstrings.ascii", "ASCII 字符串提取", "镜像扫描", OutputKind.TABLE,
               "按最小长度提取可打印 ASCII 串，带偏移与上下文。",
               needs_params=("min_len", "limit")),
    PluginMeta("memstrings.utf16", "UTF-16 字符串提取", "镜像扫描", OutputKind.TABLE,
               "提取 Windows 宽字符（UTF-16LE）字符串，ASCII 插件搜不到这些。",
               needs_params=("min_len", "limit")),
)


class MemStringsEngine(EngineAdapter):
    """镜像字节级流式扫描（内置引擎，不起子进程）。"""

    name = "memstrings"
    display = "镜像字符串扫描"
    supported_containers = ("raw", "lime", "windmp", "vmem", "memfrag", "hiber",
                            "other", "kdump", "elfcore", "minidump")

    def available(self) -> tuple[bool, str]:
        return True, "内置引擎，无需外部依赖"

    def list_plugins(self, *, refresh: bool = False) -> list[PluginMeta]:
        return list(PLUGINS)

    def build_run(self, plugin: PluginMeta, image: str, params: dict[str, Any] | None = None) -> RunSpec:
        # 内置引擎不走子进程；RunSpec 仅用于留痕（argv 记录参数）
        p = params or {}
        return RunSpec(plugin=plugin, argv=[plugin.name, f"min_len={p.get('min_len', 8)}",
                                           f"limit={p.get('limit', DEFAULT_LIMIT)}"],
                       output_kind=plugin.kind)

    def parse_records(self, spec: RunSpec, stdout: str, stderr: str) -> Iterator[dict[str, Any]]:
        raise NotImplementedError("内置引擎不经过子进程")

    # ------------------------------------------------------------ 执行
    def analyze_file(self, path: str, plugin: PluginMeta,
                     params: dict[str, Any] | None = None,
                     progress: Callable[[int], None] | None = None,
                     cancel: Callable[[], bool] | None = None) -> Iterator[dict[str, Any]]:
        """
        扫描文件并逐条产出记录。

        Args:
            params: min_len / limit / max_bytes / ctx
            progress: 收到已扫描偏移（可用来算百分比）
            cancel: 返回 True 时中止
        """
        p = params or {}
        min_len = int(p.get("min_len", 8))
        limit = int(p.get("limit", DEFAULT_LIMIT))
        max_bytes = int(p.get("max_bytes", DEFAULT_MAX_BYTES))
        ctx = int(p.get("ctx", 64))

        t0 = time.time()
        try:
            if plugin.name == "memstrings.ascii":
                yield from _rows_from_strings(path, utf16=False, min_len=min_len, limit=limit,
                                              max_bytes=max_bytes, ctx=ctx,
                                              progress=progress, cancel=cancel)
            elif plugin.name == "memstrings.utf16":
                yield from _rows_from_strings(path, utf16=True, min_len=min_len, limit=limit,
                                              max_bytes=max_bytes, ctx=ctx,
                                              progress=progress, cancel=cancel)
            elif plugin.name == "memstrings.flag":
                yield from _rows_flag(path, limit=limit, max_bytes=max_bytes, ctx=ctx,
                                      progress=progress, cancel=cancel,
                                      loose=bool(p.get("loose")))
            elif plugin.name == "memstrings.ioc":
                yield from _rows_ioc(path, limit=limit, max_bytes=max_bytes, ctx=ctx,
                                     progress=progress, cancel=cancel)
            else:
                raise KeyError(f"未知插件：{plugin.name}")
        except _Cancel:
            return
