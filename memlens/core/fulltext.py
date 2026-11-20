# -*- coding: utf-8 -*-
"""MemLens · 跨编码全文检索（新增 · CarveScope 同类能力）

在镜像/卷的字节流里按**多编码**（UTF-8 / UTF-16LE / UTF-16BE / GBK / ASCII）
同时查找一个关键词，返回每个命中的偏移、编码与上下文，供挂载页/命令行复用。

与 XFS.find_contents（单编码、仅 UTF-8 语义）不同，这里是**字节级多编码
扫描**：对每个编码把关键词编码成字节串，在流里 find，命中按偏移去重
（同偏移取"更优"编码：非 ASCII > GBK > UTF-16 > UTF-8 > ASCII）。
"""

from __future__ import annotations

import codecs
from typing import Any, Callable, Iterator

_ENCODINGS = ("utf-8", "utf-16le", "utf-16be", "gbk", "ascii")


def encode_keyword(text: str, encodings: list[str] | None = None) -> list[tuple[str, bytes]]:
    """把关键词编码成各编码的字节串。返回 [(enc, bytes)]，跳过编不出的。"""
    encs = encodings or list(_ENCODINGS)
    out: list[tuple[str, bytes]] = []
    for enc in encs:
        try:
            out.append((enc, text.encode(enc)))
        except (UnicodeEncodeError, LookupError):
            continue
    return out


def _quality(enc: str) -> int:
    # 命中质量：非 ASCII 编码优先级更高（更可能是"真实"多字节匹配）
    return {"utf-16le": 3, "utf-16be": 3, "gbk": 2, "utf-8": 1, "ascii": 0}.get(enc, 1)


def search_region(read: Callable[[int, int], bytes], base: int, length: int,
                  keyword: str, encodings: list[str] | None = None,
                  limit: int = 200, window: int = 8 << 20,
                  overlap: int = 1 << 16) -> list[dict[str, Any]]:
    """在 [base, base+length) 扫描 keyword 的多编码出现。

    read(off,n)->bytes 是绝对偏移读取。返回 [{offset, enc, context, quality}]，
    按 offset 升序，去重（同偏移保留最高质量编码）。
    """
    if not keyword:
        return []
    pats = encode_keyword(keyword, encodings)
    if not pats:
        return []
    max_pat = max(len(b) for _, b in pats)
    seen: dict[int, dict[str, Any]] = {}
    pos = base
    while pos < base + length:
        end = min(pos + window, base + length)
        data = bytearray()
        off = pos
        while off < end:
            blk = read(off, min(4 << 20, end - off))
            if not blk:
                break
            data.extend(blk)
            off += len(blk)
        for enc, pat in pats:
            if not pat:
                continue
            i = 0
            while True:
                j = data.find(pat, i)
                if j < 0:
                    break
                i = j + 1
                abs_off = pos + j
                if abs_off < base:
                    continue
                if abs_off in seen:
                    if _quality(enc) > seen[abs_off]["quality"]:
                        seen[abs_off]["enc"] = enc
                        seen[abs_off]["quality"] = _quality(enc)
                    continue
                ctx = data[max(0, j - 40):j + len(pat) + 40]
                seen[abs_off] = {"offset": abs_off, "enc": enc,
                                 "context": ctx.decode("utf-8", "replace"),
                                 "quality": _quality(enc)}
        if end >= base + length:
            break
        pos = end - overlap
        if len(seen) >= limit * 4:
            break
    hits = sorted(seen.values(), key=lambda h: h["offset"])
    return hits[:limit]


def search_volume(vol: Any, keyword: str, encodings: list[str] | None = None,
                  limit: int = 200) -> list[dict[str, Any]]:
    """在挂载卷上全文检索。vol 需有 _abs_read / offset / size。"""
    read = getattr(vol, "_abs_read", None) or getattr(vol, "read", None)
    base = getattr(vol, "offset", 0)
    size = getattr(vol, "size", 0)
    if read is None:
        return []
    return search_region(read, base, size, keyword, encodings, limit)


def search_image(mount: Any, keyword: str, vol: int = 0,
                 encodings: list[str] | None = None, limit: int = 200) -> list[dict[str, Any]]:
    """在挂载对象的指定卷（或全部卷）检索。"""
    if vol:
        v = next((x for x in mount.volumes if x.index == vol), None)
        return search_volume(v, keyword, encodings, limit) if v else []
    out: list[dict[str, Any]] = []
    for v in mount.volumes:
        out.extend(search_volume(v, keyword, encodings, limit))
    out.sort(key=lambda h: h["offset"])
    return out[:limit]


__all__ = ["search_region", "search_volume", "search_image", "encode_keyword",
           "_ENCODINGS"]
