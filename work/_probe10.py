# -*- coding: utf-8 -*-
"""扫 inode 64 data fork，找指向目录块的 extent（读块首 16B，快）。"""
import sys
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs, bmbt_unpack

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记❤"
x, meta = open_server_fs(IMG, PW)
info = x.inode(64)
raw = info["raw"]
print("inode 64: ver", info["ver"], "fmt", info["fmt"], "size", info["size"])
for off in range(0xB0, 0x100, 16):
    rec = raw[off:off+16]
    if len(rec) < 16: break
    e = bmbt_unpack(rec)
    if not e["startblock"] and not e["blockcount"]: continue
    try:
        head = x.read(e["startblock"] * x.bs, 16)
    except Exception as ex:
        head = b"?"; print(" 读失败", ex)
    print(f"  0x{off:x}: startblock={e['startblock']} bc={e['blockcount']} "
          f"so={e['startoff']} → 块首={head.hex(' ')}")
