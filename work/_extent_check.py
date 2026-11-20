# -*- coding: utf-8 -*-
# 检查已找到的 SQL 文件 fmt/extent，判断 extent 是否可信
import sys, struct, math
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs, bmbt_unpack

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
x.find_inodes(256 << 20)

for ino in (67924, 67928, 68278):
    try:
        info = x.inode(ino)
    except Exception as e:
        print(f"ino {ino}: ERR {e}")
        continue
    print(f"== ino {ino} mode={oct(info['mode'])} fmt={info['fmt']} size={info['size']} nextents={info['nextents']} ==")
    exts = x.extents(ino)
    print("  extents:", exts)
    # 手动读 extent 首块看 magic
    if exts:
        blk = exts[0]["startblock"]
        d = x.read(blk * x.bs, 64)
        print(f"  extent[0] startblock={blk} data[:32]={d[:32]!r}")
