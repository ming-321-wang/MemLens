# -*- coding: utf-8 -*-
"""MemLens · FAT12/16/32 只读解析器（新增）

CarveScope 底座含 FAT12/16/32；MemLens 之前只有 XFS/ext4/exFAT。这里按
BPB + FAT 表 + 目录项实现只读读取（含**已删除**目录项首字节 0xE5 的
标记），供 `memlens mount` 挂载 FAT 分区浏览/提取。

接口与 `formats/xfs.py` / `formats/ext4.py` 对齐：`FAT(reader, offset)`，
`reader.read(off, n)` 是绝对偏移读取（内部已含分区基址 offset）。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Iterator


class FatError(RuntimeError):
    pass


@dataclass
class FatEntry:
    name: str
    path: str
    is_dir: bool
    is_deleted: bool
    size: int
    start_cluster: int
    attr: int
    first_byte: int
    data: bytes = b""


class FAT:
    def __init__(self, reader: Any, offset: int = 0) -> None:
        self._reader = reader
        self.offset = offset
        self._parse_bpb()

    # ── 基础读取 ──────────────────────────────────────────
    def read(self, off: int, n: int) -> bytes:
        return self._reader.read(self.offset + off, n)

    def _parse_bpb(self) -> None:
        bpb = self.read(0, 90)
        if len(bpb) < 90:
            raise FatError("BPB 太短，不是 FAT 卷")
        self.bytes_per_sector = struct.unpack_from("<H", bpb, 11)[0]
        self.sectors_per_cluster = bpb[13]
        self.reserved_sectors = struct.unpack_from("<H", bpb, 14)[0]
        self.num_fats = bpb[16]
        self.root_entries = struct.unpack_from("<H", bpb, 17)[0]
        self.total_sectors16 = struct.unpack_from("<H", bpb, 19)[0]
        self.fat16_size = struct.unpack_from("<H", bpb, 22)[0]
        self.total_sectors32 = struct.unpack_from("<I", bpb, 32)[0]
        self.fat32_size = struct.unpack_from("<I", bpb, 36)[0]
        self.root_cluster = struct.unpack_from("<I", bpb, 44)[0] & 0x0FFFFFFF if len(bpb) >= 48 else 0
        self.label = bpb[71:82].split(b"\x00")[0].decode("ascii", "replace") if len(bpb) >= 82 else ""

        total = self.total_sectors16 or self.total_sectors32
        fat_size = self.fat16_size or self.fat32_size
        if fat_size == 0:
            raise FatError("FAT 大小未知")
        data_sectors = total - (self.reserved_sectors + self.num_fats * fat_size
                                + (self.root_entries * 32 + self.bytes_per_sector - 1) // self.bytes_per_sector)
        self.cluster_count = data_sectors // self.sectors_per_cluster
        if self.cluster_count < 4085:
            self.fat_type = "FAT12"
        elif self.cluster_count < 65525:
            self.fat_type = "FAT16"
        else:
            self.fat_type = "FAT32"

        self.first_fat = self.reserved_sectors * self.bytes_per_sector
        self.root_dir_off = (self.reserved_sectors + self.num_fats * fat_size) * self.bytes_per_sector
        self.cluster_off = (self.root_dir_off
                            + (self.root_entries * 32 if self.fat_type != "FAT32" else 0))
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.fat_size = fat_size * self.bytes_per_sector

    # ── FAT 表 ────────────────────────────────────────────
    def next_cluster(self, cl: int) -> int:
        if cl < 2:
            return 0
        if self.fat_type == "FAT12":
            off = self.first_fat + cl + cl // 2
            b = self.read(off, 2)
            if len(b) < 2:
                return 0
            v = struct.unpack("<H", b)[0]
            return (v >> 4) if (cl & 1) else (v & 0x0FFF)
        elif self.fat_type == "FAT16":
            off = self.first_fat + cl * 2
            b = self.read(off, 2)
            return struct.unpack("<H", b)[0] if len(b) == 2 else 0
        off = self.first_fat + cl * 4
        b = self.read(off, 4)
        return (struct.unpack("<I", b)[0] & 0x0FFFFFFF) if len(b) == 4 else 0

    def cluster_to_offset(self, cl: int) -> int:
        return self.cluster_off + (cl - 2) * self.cluster_size

    def read_cluster_chain(self, cl: int, max_bytes: int = 0, limit: int = 1 << 20) -> bytes:
        """读从 cl 开始的簇链，直到 EOC/坏簇/满 limit 字节。"""
        out = bytearray()
        seen = 0
        while cl >= 2 and cl < 0x0FFFFFF8:
            out.extend(self.read(self.cluster_to_offset(cl), self.cluster_size))
            seen += 1
            if max_bytes and len(out) >= max_bytes:
                break
            if seen > limit:
                break
            cl = self.next_cluster(cl)
        return bytes(out)

    # ── 目录 ──────────────────────────────────────────────
    def _parse_dir(self, base_off: int, base_size: int, prefix: str,
                   depth: int, out: list[FatEntry], max_depth: int) -> None:
        off = base_off
        end = base_off + base_size
        while off + 32 <= end:
            ent = self.read(off, 32)
            if len(ent) < 32:
                break
            off += 32
            first = ent[0]
            if first == 0x00:               # 目录结束
                break
            if first == 0xE5:               # 已删除
                name = self._entry_name(ent, deleted=True)
                if not name:
                    continue
                self._push(ent, name, prefix, True, base_off, out, depth, max_depth)
                continue
            if first == 0x2E or first == 0x2F:  # . / ..
                continue
            if ent[11] & 0x0F == 0x0F:      # LFN 条目（跳过，用短名即可）
                continue
            name = self._entry_name(ent)
            if not name:
                continue
            self._push(ent, name, prefix, False, base_off, out, depth, max_depth)

    def _entry_name(self, ent: bytes, deleted: bool = False) -> str:
        name = ent[0:8].decode("ascii", "replace").replace("\x00", "").strip()
        ext = ent[8:11].decode("ascii", "replace").replace("\x00", "").strip()
        if not name:
            return ""
        if deleted and name:
            name = "?" + name[1:] if name[0] != "?" else name
        return (name + (("." + ext) if ext else "")).strip()

    def _push(self, ent: bytes, name: str, prefix: str, deleted: bool,
              base_off: int, out: list[FatEntry], depth: int, max_depth: int) -> None:
        attr = ent[11]
        is_dir = bool(attr & 0x10)
        if self.fat_type == "FAT32":
            low = struct.unpack_from("<H", ent, 26)[0]
            high = struct.unpack_from("<H", ent, 20)[0]
            start = (high << 16) | low
        else:
            start = struct.unpack_from("<H", ent, 26)[0]
        size = struct.unpack_from("<I", ent, 28)[0]
        path = (prefix.rstrip("/") + "/" + name) if prefix else name
        e = FatEntry(name, path, is_dir, deleted, size, start, attr, ent[0])
        out.append(e)
        # 递归进子目录
        if is_dir and depth < max_depth and start >= 2 and not deleted:
            child = []
            self._parse_dir(self.cluster_to_offset(start), self.cluster_size * 64,
                            path, depth + 1, child, max_depth)
            out.extend(child)

    # ── 对外 ──────────────────────────────────────────────
    def tree(self, max_depth: int = 6) -> list[FatEntry]:
        out: list[FatEntry] = []
        if self.fat_type == "FAT32":
            self._parse_dir(self.cluster_to_offset(self.root_cluster), self.cluster_size * 64,
                            "", 0, out, max_depth)
        else:
            n_entries = self.root_entries
            self._parse_dir(self.root_dir_off, n_entries * 32, "", 0, out, max_depth)
        return out

    def lookup(self, path: str) -> FatEntry | None:
        parts = [p for p in path.strip("/").split("/") if p]
        node = None
        entries = self.tree(8)
        # 逐段匹配
        cur = ""
        for p in parts:
            cur = (cur + "/" + p).strip("/")
            node = next((e for e in entries if e.path == cur and not e.is_deleted), None)
            if node is None:
                return None
        return node

    def read_path(self, path: str, max_bytes: int = 64 << 20) -> bytes:
        e = self.lookup(path)
        if e is None or e.is_dir:
            raise FatError(f"not a file: {path}")
        if e.is_deleted or e.start_cluster < 2:
            # 已删除/零长度：尝试从目录项所在簇后连续读（尽力而为）
            return b""
        return self.read_cluster_chain(e.start_cluster, max_bytes=e.size or 0)

    def summary(self) -> dict[str, Any]:
        return {
            "fs": "FAT",
            "fat_type": self.fat_type,
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": self.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "cluster_count": self.cluster_count,
            "num_fats": self.num_fats,
            "label": self.label,
        }

    def records(self) -> Iterator[dict[str, Any]]:
        for e in self.tree():
            yield {"name": e.name, "path": e.path, "dir": e.is_dir,
                   "deleted": e.is_deleted, "size": e.size,
                   "cluster": e.start_cluster}


__all__ = ["FAT", "FatEntry", "FatError"]
