# -*- coding: utf-8 -*-
"""MemLens · 文件雕刻（file carving）

从磁盘镜像/未分配空间里按文件签名"抠"出对象（JPEG/PNG/PDF/ZIP/…），是
CarveScope 具备而 MemLens 之前缺失的能力。这里是纯签名实现（零依赖）：

    header   —— 文件头魔数（可带 alt_headers）
    footer   —— 文件尾魔数（exact_end=True 时用于定界）
    min/max  —— 尺寸约束
    exact_end—— 找尾魔数定界；找不到尾魔数时退到"下一个同型头"或 max_size

对大区域按块扫描、跨块拼接，避免把整个镜像读进内存。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterator


@dataclass(frozen=True)
class CarveRule:
    name: str
    header: bytes
    footer: bytes | None = None
    alt_headers: tuple[bytes, ...] = ()
    min_size: int = 64
    max_size: int = 64 * 1024 * 1024
    extensions: tuple[str, ...] = ()
    exact_end: bool = False

    @property
    def headers(self) -> tuple[bytes, ...]:
        return (self.header,) + self.alt_headers


@dataclass
class CarveHit:
    rule: str
    start: int
    end: int
    size: int
    header: bytes
    confidence: int = 85
    note: str = ""
    data: bytes = field(default=b"", repr=False)


# ───────────────────────────────────────────────────────── 20 条规则
CARVE_RULES: tuple[CarveRule, ...] = (
    CarveRule("jpeg", b"\xff\xd8\xff", footer=b"\xff\xd9", min_size=256, max_size=64 << 20,
              extensions=(".jpg", ".jpeg"), exact_end=True),
    CarveRule("png", b"\x89PNG\r\n\x1a\n", footer=b"IEND\xaeB`\x82", min_size=64, max_size=64 << 20,
              extensions=(".png",), exact_end=True),
    CarveRule("gif", b"GIF8", footer=b"\x00\x3b", min_size=64, max_size=64 << 20,
              extensions=(".gif",), exact_end=True),
    CarveRule("pdf", b"%PDF-", footer=b"%%EOF", min_size=256, max_size=64 << 20,
              extensions=(".pdf",), exact_end=True),
    CarveRule("zip", b"PK\x03\x04", footer=b"PK\x05\x06", min_size=64, max_size=256 << 20,
              extensions=(".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt"), exact_end=True),
    CarveRule("gzip", b"\x1f\x8b", footer=b"\x00\x00", min_size=18, max_size=32 << 20,
              extensions=(".gz", ".tgz")),
    CarveRule("elf", b"\x7fELF", min_size=64, max_size=64 * 1024, extensions=(".elf", ".so", ".bin")),
    CarveRule("pe", b"MZ", min_size=64, max_size=64 * 1024, extensions=(".exe", ".dll", ".sys")),
    CarveRule("bmp", b"BM", min_size=26, max_size=64 << 20, extensions=(".bmp", ".dib")),
    CarveRule("wav", b"RIFF", min_size=24, max_size=64 << 20, extensions=(".wav",)),
    CarveRule("sqlite", b"SQLite format 3\x00", min_size=512, max_size=256 << 20,
              extensions=(".sqlite", ".db", ".sqlite3")),
    CarveRule("tiff", b"II*\x00", min_size=64, max_size=64 << 20, extensions=(".tif", ".tiff"),
              alt_headers=(b"MM\x00*",)),
    CarveRule("rar", b"Rar!\x1a\x07\x00", min_size=20, max_size=64 * 1024, extensions=(".rar",)),
    CarveRule("rar5", b"Rar!\x1a\x07\x01\x00", min_size=26, max_size=64 << 20, extensions=(".rar",)),
    CarveRule("au", b".snd", min_size=24, max_size=64 << 20, extensions=(".au",)),
    CarveRule("wma", b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c",
              min_size=30, max_size=256 << 20, extensions=(".wma", ".asf", ".wmv")),
    CarveRule("pcx", b"\x0a\x05\x01", min_size=128, max_size=256 << 20, extensions=(".pcx",),
              alt_headers=(b"\x0a\x00\x01", b"\x0a\x02\x01", b"\x0a\x03\x01", b"\x0a\x04\x01")),
    CarveRule("mp3", b"ID3", min_size=1024, max_size=64 << 20, extensions=(".mp3",)),
    CarveRule("sevenzip", b"7z\xbc\xaf\x27\x1c", min_size=32, max_size=256 << 20, extensions=(".7z",)),
    CarveRule("mp4", b"\x00\x00\x00\x18ftyp", min_size=64, max_size=256 << 20,
              extensions=(".mp4", ".m4a", ".m4v", ".mov"),
              alt_headers=tuple(n.to_bytes(4, "big") + b"ftyp"
                                for n in (0x14, 0x1C, 0x20, 0x24, 0x28))),
)

_RULE_BY_NAME = {r.name: r for r in CARVE_RULES}


def _find_any(data: bytes, rules: list[CarveRule]) -> dict[bytes, int]:
    """找到 data 里每个头魔数的最早出现位置（跨规则，返回 {magic: idx}）。"""
    out: dict[bytes, int] = {}
    for r in rules:
        for h in r.headers:
            if h not in out:
                i = data.find(h)
                if i >= 0:
                    out[h] = i
    return out


def _read_range(read: Callable[[int, int], bytes], start: int, end: int,
                chunk: int = 4 << 20) -> bytes:
    out = bytearray()
    off = start
    while off < end:
        blk = read(off, min(chunk, end - off))
        if not blk:
            break
        out.extend(blk)
        off += len(blk)
    return bytes(out)


def carve_region(read: Callable[[int, int], bytes], base: int, length: int,
                 names: list[str] | None = None, window: int = 32 << 20,
                 overlap: int = 1 << 16) -> Iterator[CarveHit]:
    """在 [base, base+length) 上按签名雕刻（窗口化，内存有界）。

    read(off,n)->bytes 是绝对偏移读取（内部已含 base）。
    结果按 start 升序，去重（同一绝对起点只出一份）。
    """
    rules = [r for r in CARVE_RULES if not names or r.name in names]
    headers = [(h, r) for r in rules for h in r.headers]
    if not rules or length <= 0:
        return
    emitted: set[int] = set()
    pos = base
    while pos < base + length:
        end = min(pos + window, base + length)
        data = _read_range(read, pos, end)
        if not data:
            break
        cands: list[CarveHit] = []
        for h, r in headers:
            i = 0
            while True:
                j = data.find(h, i)
                if j < 0:
                    break
                i = j + 1
                abs_start = pos + j
                if abs_start in emitted:
                    continue
                # 定界：footer（exact_end）→ 下一个同型头 → max_size 截断
                e = -1
                if r.footer and r.exact_end:
                    k = data.find(r.footer, j + r.min_size)
                    if k >= 0:
                        e = pos + k + len(r.footer)
                if e < 0:
                    nxt = None
                    for hh, rr in headers:
                        if rr is r:
                            m = data.find(hh, j + 1)
                            if m >= 0 and (nxt is None or m < nxt):
                                nxt = m
                    if nxt is not None:
                        e = pos + nxt
                if e < 0:
                    e = min(abs_start + r.max_size, end)
                size = e - abs_start
                if r.min_size <= size <= r.max_size:
                    cands.append(CarveHit(
                        r.name, abs_start, e, size, h,
                        note="footer" if (r.footer and r.exact_end and
                                          abs_start + r.min_size <= e - len(r.footer)) else "cap"))
                    emitted.add(abs_start)
        cands.sort(key=lambda c: c.start)
        yield from cands
        if end >= base + length:
            break
        pos = end - overlap


def carve_bytes(data: bytes, names: list[str] | None = None) -> list[CarveHit]:
    """对内存块雕刻（小样本用）。"""
    def _read(off: int, n: int) -> bytes:
        if off < 0:
            return b""
        return data[off:off + n]

    return list(carve_region(_read, 0, len(data), names))


def formats() -> list[dict[str, Any]]:
    return [
        {"name": r.name, "extensions": list(r.extensions),
         "min_size": r.min_size, "max_size": r.max_size,
         "has_footer": r.footer is not None, "exact_end": r.exact_end}
        for r in CARVE_RULES
    ]


__all__ = ["CARVE_RULES", "CarveRule", "CarveHit", "carve_region",
           "carve_bytes", "formats", "_RULE_BY_NAME"]
