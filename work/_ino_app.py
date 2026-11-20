# -*- coding: utf-8 -*-
# 解码 /application(324624) /www(993344) 的 shortform inumber，验证是否真实
import sys, struct
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
x.find_inodes(1024 << 20)

def dump_entries(ino):
    info = x.inode(ino)
    raw = info["raw"]
    print(f"=== ino {ino} fmt={info['fmt']} size={info['size']} ===")
    # 打印数据 fork 区
    for off in range(0xB0, 0xB0+min(info["size"]+8, 200), 16):
        c = raw[off:off+16]
        print(f"  {off:04x}: {c.hex(' ')}  {''.join(chr(b) if 32<=b<127 else '.' for b in c)}")

dump_entries(324624)
print()
dump_entries(993344)
