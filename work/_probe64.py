# -*- coding: utf-8 -*-
# 重新抓取 inode 64 原始字节，解码 shortform 目录布局
import sys, struct, binascii
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs, bmbt_unpack

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"

x, meta = open_server_fs(IMG, PW)
print("blocksize", x.bs, "rootino", x.rootino)

blk, slot = x.inode_loc(64)
raw = x.read(blk * x.bs + slot, 512)
print("inode64 blk", blk, "slot", slot)
print("magic", hex(struct.unpack_from(">H", raw, 0)[0]), "mode", oct(struct.unpack_from(">H", raw, 2)[0]))
print("ver", raw[4], "fmt", raw[5])
print("size", struct.unpack_from(">Q", raw, 0x38)[0])
print("nblocks", struct.unpack_from(">Q", raw, 0x40)[0])
print("nextents", struct.unpack_from(">I", raw, 0x4C)[0])
print("forkoff", raw[0x52], "aformat", raw[0x53])
print("ino field", struct.unpack_from(">Q", raw, 0x98)[0])
print("--- data fork 0xB0..0x130 ---")
for off in range(0xB0, 0x130, 16):
    chunk = raw[off:off+16]
    print(f"{off:04x}: {binascii.hexlify(chunk).decode()}  {''.join(chr(c) if 32<=c<127 else '.' for c in chunk)}")
print("--- ascii 0xA0..0x140 ---")
for off in range(0xA0, 0x140, 16):
    chunk = raw[off:off+16]
    print(f"{off:04x}: {''.join(chr(c) if 32<=c<127 else '.' for c in chunk)}")
