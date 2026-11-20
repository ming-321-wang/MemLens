# -*- coding: utf-8 -*-
# 逐字节打印 inode64 数据fork [0xB0,0x150)，尝试多种 shortform 解析
import sys, struct, binascii
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
blk, slot = x.inode_loc(64)
raw = x.read(blk * x.bs + slot, 512)

for off in range(0xB0, 0x150):
    c = raw[off]
    print(f"{off:04x} {c:02x} {chr(c) if 32<=c<127 else '.'}")
