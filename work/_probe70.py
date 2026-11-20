# -*- coding: utf-8 -*-
# 转储 ino 70 (fmt=1 目录) 完整字节，解码真实 shortform 布局
import sys, struct
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

for ino in (70, 76, 77):
    blk, slot = x.inode_loc(ino)
    raw = x.read(blk * x.bs + slot, 512)
    mode = struct.unpack_from(">H", raw, 2)[0]
    fmt = raw[5]
    size = struct.unpack_from(">Q", raw, 0x38)[0]
    nxt = struct.unpack_from(">I", raw, 0x4C)[0]
    forkoff = raw[0x52]
    print(f"=== ino {ino} mode={oct(mode)} fmt={fmt} size={size} nextents={nxt} forkoff={forkoff} ===")
    for off in range(0xB0, 0xB0 + 96, 16):
        chunk = raw[off:off+16]
        print(f"{off:04x}: {chunk.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in chunk)}")
    print()
