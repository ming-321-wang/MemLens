# -*- coding: utf-8 -*-
# 转储 inode 65..80 的数据 fork，找干净的目录条目布局
import sys, struct
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

for ino in range(65, 81):
    try:
        blk, slot = x.inode_loc(ino)
        raw = x.read(blk * x.bs + slot, 512)
    except Exception as e:
        print(f"ino {ino}: ERR {e}")
        continue
    mode = struct.unpack_from(">H", raw, 2)[0]
    fmt = raw[5]
    size = struct.unpack_from(">Q", raw, 0x38)[0]
    if mode == 0:
        print(f"ino {ino}: (empty) blk {blk}")
        continue
    isdir = (mode & 0xF000) == 0x4000
    islnk = (mode & 0xF000) == 0xA000
    typ = "dir" if isdir else ("lnk" if islnk else ("reg" if (mode&0xF000)==0x8000 else "?"))
    # 找 ASCII 名
    names = []
    for i in range(0xB0, 0x180, 1):
        c = raw[i]
        if 0x61 <= c <= 0x7a or 0x41 <= c <= 0x5a or 0x30 <= c <= 0x39 or c == 0x2f or c == 0x2d or c == 0x5f or c==0x2e:
            names.append(chr(c))
        else:
            if names and len(names) >= 3:
                print(f"ino {ino} {typ} fmt={fmt} size={size} blk={blk}: name={''.join(names)}")
            names = []
    if names and len(names) >= 3:
        print(f"ino {ino} {typ} fmt={fmt} size={size} blk={blk}: name={''.join(names)} (tail)")
