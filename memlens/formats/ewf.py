r"""
MemLens · EWF（E01/EWF）分段与压缩块解析

## 真实格式（2025 平航杯 `window.e01` 实测反推）

EWF 文件不是"一堆 chunk 头"，而是**节链 + 每节内一串 zlib 流**：

    文件头
        signature[8]        "EVF\x09\x0d\x0a\xff\x00"
        fields_start(1)     0x01
        segment_number(1)
        fields_end(2)       0x0000
        reserved(1)         0x00
    节链（反复）
        name[16]            NUL 填充的定长节名：header / disk / sectors / table / table2 …
        u64  next_offset    下一节的**绝对文件偏移**
        u64  section_len    本节总长（下一节 − 本节起点）
        byte data[…]

`window.e01` 的节链实测：

    header(139) → header(265) → disk(1393) → sectors(248180441)
        → table → table2 → sectors → table → table2 → … （每段一组）

## 数据怎么取

`sectors` 节里是**连续的 zlib 流**（不是带 chunk 头的块）：
解压完第一个流，zlib 的 `unused_data` **紧接着就是下一个流的 `78 01`**。
每流解压出 32,768 字节 = 64 个扇区。把这些流解压结果依次拼接，
就是**逻辑扇区数据**。

`table` / `table2` 节是 chunk 偏移表（u32，高位是压缩标志），
用于随机定位；顺序读取时不需要它。

## 支持直接跑在加密卷上

`reader` 参数让本模块可以**不落盘**直接读容器里的 E01
（55 GB 的检材没必要先解到磁盘）。
"""

from __future__ import annotations

import struct
import zlib
from typing import Any, Iterator

#: 节名固定长度（NUL 填充）
NAME_LEN = 16

#: 文件头长度（signature 8 + 1 + 1 + 2 + 1）
FILE_HEADER_LEN = 13

#: 每节头长度（name[16] + u64 + u64）
SECTION_HEADER_LEN = NAME_LEN + 16


class EwfError(RuntimeError):
    """EWF 解析失败。"""


class EwfReader:
    """
    EWF 读取器。

    可以吃两种输入：
      · 真实文件路径（``path=``）
      · 任意能按偏移读的字节源（``reader=``），用于直接读加密卷里的文件
    """

    def __init__(self, path: str | None = None, *, reader: Any = None) -> None:
        if reader is None and not path:
            raise EwfError("需要 path 或 reader")
        self.path = path
        self.reader = reader
        self._fh = open(path, "rb") if path else None
        if self._fh:
            self._fh.seek(0, 2)
            self.size = self._fh.tell()
            self._fh.seek(0)
        else:
            self.size = int(getattr(reader, "size", 0))
        self.sections: list[dict[str, Any]] = []
        self._streams: list[dict[str, Any]] = []      # 压缩流索引
        self._scan_sections()

    # ------------------------------------------------------------ 底层读
    def _read(self, off: int, n: int) -> bytes:
        if off < 0 or n <= 0:
            return b""
        if self._fh:
            self._fh.seek(off)
            return self._fh.read(n)
        return self.reader.read(off, n)

    # ------------------------------------------------------------ 节链
    def _scan_sections(self) -> None:
        """按 name[16] + u64 next + u64 len 遍历节链。"""
        pos = FILE_HEADER_LEN
        seen: set[int] = set()
        while pos + SECTION_HEADER_LEN <= self.size and pos not in seen:
            seen.add(pos)
            hdr = self._read(pos, SECTION_HEADER_LEN)
            if len(hdr) < SECTION_HEADER_LEN:
                break
            name = hdr[:NAME_LEN].rstrip(b"\x00").decode("ascii", "replace")
            next_off, sec_len = struct.unpack_from("<QQ", hdr, NAME_LEN)
            if not name:
                break
            self.sections.append({
                "name": name, "offset": pos,
                "data_offset": pos + SECTION_HEADER_LEN,
                "length": sec_len, "next_offset": next_off,
                "data_size": max(0, sec_len - SECTION_HEADER_LEN),
            })
            if sec_len <= 0:
                break
            nxt = next_off if next_off > pos else pos + sec_len
            pos = nxt

    # ------------------------------------------------------------ 压缩流
    def _scan_streams(self) -> None:
        """
        扫出 `sectors` 节里的 zlib 流。

        每节内：从 data_offset 起，跳过开头的少量填充字节，
        之后是**首尾相接**的 zlib 流（解压后 unused_data 直接就是下一流）。
        """
        for sec in self.sections:
            if sec["name"] not in ("sectors", "data"):
                continue
            head = self._read(sec["data_offset"], 64)
            i = 0
            while i + 1 < len(head):
                if head[i] == 0x78 and head[i + 1] in (0x01, 0x9C, 0xDA):
                    break
                i += 1
            if i + 1 >= len(head):
                continue
            self._streams.append({
                "section": sec["name"], "section_offset": sec["offset"],
                "data_offset": sec["data_offset"] + i,
                "size": sec["data_size"] - i,
            })

    def _stream_blocks(self, st: dict[str, Any]) -> Iterator[bytes]:
        """解压一节里的所有 zlib 流，逐块产出。"""
        base = st["data_offset"]
        remaining = st["size"]
        while remaining > 0:
            blob = self._read(base, min(remaining, 8 << 20))
            if not blob:
                return
            try:
                d = zlib.decompressobj()
                out = d.decompress(blob)
                leftover = d.unused_data
            except zlib.error:
                return
            if out:
                yield out
            if not leftover:
                return
            # 下一个流紧接在 unused_data 开头
            base += len(blob) - len(leftover)
            remaining -= len(blob) - len(leftover)

    # ------------------------------------------------------------ 读取
    def read_at(self, offset: int, length: int) -> bytes:
        """
        按**逻辑偏移**读数据（跨压缩块拼接）。

        逻辑偏移 = 解压后所有块的字节流位置。
        """
        if not self._streams:
            self._scan_streams()
        out = bytearray()
        pos = 0
        want = offset + length
        for st in self._streams:
            for block in self._stream_blocks(st):
                n = len(block)
                if pos + n <= offset:
                    pos += n
                    continue
                if pos >= want:
                    return bytes(out[:length])
                s = max(0, offset - pos)
                e = min(n, want - pos)
                out += block[s:e]
                pos += n
                if len(out) >= length:
                    return bytes(out[:length])
        return bytes(out[:length])

    def logical_size(self) -> int:
        """逻辑数据总长（= 解压后总字节数）。"""
        if not self._streams:
            self._scan_streams()
        total = 0
        for st in self._streams:
            for block in self._stream_blocks(st):
                total += len(block)
        return total

    # ------------------------------------------------------------ 摘要
    def summary(self) -> dict[str, Any]:
        if not self._streams:
            self._scan_streams()
        return {
            "base": str(self.path or "reader"),
            "file_size": self.size,
            "section_count": len(self.sections),
            "sections": [s["name"] for s in self.sections[:24]],
            "data_sections": len(self._streams),
            "compression": "zlib" if self._streams else "",
        }

    def records(self) -> Iterator[dict[str, Any]]:
        s = self.summary()
        yield {"项目": "文件", "值": s["base"], "说明": "EWF"}
        yield {"项目": "文件大小", "值": f"{s['file_size']:,}", "说明": "字节"}
        yield {"项目": "节数", "值": str(s["section_count"]), "说明": ""}
        yield {"项目": "数据节数", "值": str(s["data_sections"]), "说明": "sectors/data"}
        yield {"项目": "压缩", "值": s["compression"], "说明": ""}
        names: list[str] = []
        for sec in self.sections:
            if sec["name"] not in names:
                names.append(sec["name"])
        yield {"项目": "节名", "值": ", ".join(names), "说明": "去重"}
        for sec in self.sections[:12]:
            yield {"项目": "节", "值": f"{sec['name']} @ {sec['offset']:,}",
                   "说明": f"长 {sec['length']:,}"}

    def close(self) -> None:
        if self._fh:
            try:
                self._fh.close()
            except Exception:
                pass

    def __enter__(self) -> "EwfReader":
        return self

    def __exit__(self, *a) -> None:
        self.close()
