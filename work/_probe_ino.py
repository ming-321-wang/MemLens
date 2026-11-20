# -*- coding: utf-8 -*-
# 转储 inode 64..100 元数据，映射根目录子项名→真实 inode 号
import sys, struct
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

print("ino | mode | fmt | size | type")
for ino in range(64, 101):
    try:
        blk, slot = x.inode_loc(ino)
        raw = x.read(blk * x.bs + slot, 512)
    except Exception as e:
        print(f"{ino}: ERR {e}")
        continue
    if raw[:2] != b"\x49\x4e":
        print(f"{ino}: no IN magic")
        continue
    mode = struct.unpack_from(">H", raw, 2)[0]
    fmt = raw[5]
    size = struct.unpack_from(">Q", raw, 0x38)[0]
    typ = (mode & 0xF000)
    ts = "dir" if typ==0x4000 else ("lnk" if typ==0xA000 else ("reg" if typ==0x8000 else ("chr" if typ==0x2000 else ("blk" if typ==0x6000 else "?"))))
    # 若 symlink, 读链接目标
    tgt = ""
    if ts == "lnk" and fmt == 1:
        tgt = raw[0xB0:0xB0+size].decode("latin-1", "replace")
    print(f"{ino} | {oct(mode)} | {fmt} | {size} | {ts} | {tgt}")
