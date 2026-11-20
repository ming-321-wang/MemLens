# -*- coding: utf-8 -*-
# 验证 ino 324625 = config.php，并读取其内容
import sys, struct, math
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
x.find_inodes(1024 << 20)

for ino in (324625, 324626, 324514):
    try:
        info = x.inode(ino)
        print(f"=== ino {ino} fmt={info['fmt']} size={info['size']} mode={oct(info['mode'])} ===")
        if info["fmt"] == 1:
            d = info["raw"][0xB0:0xB0+info["size"]]
        else:
            exts = x.extents(ino)
            nb = max(1, math.ceil(min(info["size"], 2048) / x.bs))
            d = x.read(exts[0]["startblock"] * x.bs, nb * x.bs)[:min(info["size"], 2048)]
        print("  content:", d[:400])
        print()
    except Exception as e:
        print(f"ino {ino}: ERR {e}")
