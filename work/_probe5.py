# -*- coding: utf-8 -*-
"""排查 inode 版本 + data fork 偏移（v2=0x60? v3=0xB0?）。"""
import sys, struct
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs, bmbt_unpack

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记❤"
x, meta = open_server_fs(IMG, PW)
for ino in (64, 96):
    info = x.inode(ino)
    raw = info["raw"]
    print(f"inode {ino}: ver={info['ver']} fmt={info['fmt']} size={info['size']} "
          f"nextents={info['nextents']} mode=0{info['mode']:o}")
    # 试 data fork 在 0x60 / 0xB0
    for off in (0x60, 0x68, 0x70, 0xB0):
        rec = raw[off:off+16]
        if len(rec) >= 16:
            e = bmbt_unpack(rec)
            sb = e["startblock"]
            blk = x.read(sb * x.bs, 16)
            print(f"   data fork @0x{off:x}: startblock={sb} → 块首={blk.hex(' ')}")
    print()
