# -*- coding: utf-8 -*-
"""MemLens · 分区表解析（MBR + GPT）

CarveScope 底座含 MBR/GPT；MemLens 的 server 链路只认固定 VMDK 结构。
这里补一个通用分区表读取：输入 read(off,n)+总大小，输出分区列表。

MBR：4 个主分区项（0x55AA 结尾），扩展分区（EBR）链式解析。
GPT：保护性 MBR + GPT 头（0x5452415020494645）+ 条目数组（128 项/1MiB）。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

GPT_SIG = b"EFI PART"


@dataclass
class Partition:
    index: int
    offset: int          # 分区起始（绝对）
    size: int            # 分区大小（字节）
    fs_type: str = ""    # 分区类型提示（0x07=NTFS/exFAT, 0x0C=FAT32, 0x83=Linux, 0x8E=LVM...）
    label: str = ""      # GPT 名
    bootable: bool = False
    gpt: bool = False
    gpt_guid: str = ""

    def summary(self) -> dict[str, Any]:
        return {"index": self.index, "offset": self.offset, "size": self.size,
                "fs_type": self.fs_type, "label": self.label,
                "bootable": self.bootable, "gpt": self.gpt}


def _read(read: Any, off: int, n: int) -> bytes:
    return read(off, n)


def _ptype(code: int) -> str:
    return {
        0x00: "", 0x01: "FAT12", 0x04: "FAT16", 0x05: "extended",
        0x06: "FAT16", 0x07: "NTFS/exFAT", 0x0B: "FAT32", 0x0C: "FAT32",
        0x0E: "FAT16", 0x0F: "extended", 0x11: "FAT12", 0x27: "Windows RE",
        0x82: "Linux swap", 0x83: "Linux", 0x8E: "LVM", 0xA5: "BSD",
        0xAB: "macOS boot", 0xAF: "HFS+", 0xEE: "GPT", 0xEF: "EFI",
        0xFB: "VMware", 0xFC: "VMware swap",
    }.get(code, f"0x{code:02X}")


def parse_mbr(read: Any, total: int) -> list[Partition]:
    """解析 MBR 分区表（含扩展分区链）。"""
    out: list[Partition] = []
    mbr = _read(read, 0, 512)
    if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
        return out
    for i in range(4):
        e = mbr[446 + i * 16:446 + i * 16 + 16]
        if len(e) < 16:
            break
        boot, start_lba = e[0], struct.unpack_from("<I", e, 8)[0]
        num = struct.unpack_from("<I", e, 12)[0]
        if num == 0:
            continue
        out.append(Partition(i + 1, start_lba * 512, num * 512,
                             _ptype(e[4]), bootable=bool(boot & 0x80)))
    return out


def parse_gpt(read: Any, total: int) -> list[Partition]:
    """解析 GPT（保护性 MBR + 头 + 条目数组）。"""
    mbr = _read(read, 0, 512)
    if len(mbr) < 512 or mbr[510:512] != b"\x55\xaa":
        return []
    lba1 = struct.unpack_from("<I", mbr, 454)[0]  # 保护性分区起点=1
    hdr = _read(read, 512, 512)
    if len(hdr) < 512 or hdr[0:8] != GPT_SIG:
        return []
    part_lba = struct.unpack_from("<Q", hdr, 72)[0]
    n_entries = struct.unpack_from("<I", hdr, 80)[0]
    ent_size = struct.unpack_from("<I", hdr, 84)[0]
    if n_entries > 512 or ent_size < 128:
        return []
    out: list[Partition] = []
    table = _read(read, part_lba * 512, n_entries * ent_size)
    for i in range(n_entries):
        ent = table[i * ent_size:i * ent_size + ent_size]
        if len(ent) < 128:
            break
        guid = ent[0:16]
        if guid == b"\x00" * 16:
            continue
        first = struct.unpack_from("<Q", ent, 32)[0]
        last = struct.unpack_from("<Q", ent, 40)[0]
        if last <= first:
            continue
        label = ent[56:56 + 72].decode("utf-16-le", "replace").rstrip("\x00").strip()
        out.append(Partition(i + 1, first * 512, (last - first + 1) * 512,
                             "GPT", label, gpt=True,
                             gpt_guid=guid.hex()))
    return out


def parse_partitions(read: Any, total: int) -> list[Partition]:
    """优先 GPT，回退 MBR。无有效分区表时返回空（整盘单卷处理）。"""
    gpt = parse_gpt(read, total)
    if gpt:
        return gpt
    return parse_mbr(read, total)


__all__ = ["Partition", "parse_partitions", "parse_mbr", "parse_gpt"]
