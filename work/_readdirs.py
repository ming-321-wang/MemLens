# -*- coding: utf-8 -*-
# 读取 /application(324624) /www(993344) 完整条目 + 扫描 fmt=2 目录 extent 找 etc/root/var
import sys, struct, math, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs, bmbt_unpack

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
x.find_inodes(1024 << 20)

def ascii_names(d):
    names = []
    cur = []
    for c in d:
        if 0x30 <= c <= 0x39 or 0x61 <= c <= 0x7a or 0x41 <= c <= 0x5a or c in (0x2e, 0x2d, 0x5f, 0x2f, 0x24, 0x7e, 0x2b, 0x3d, 0x40):
            cur.append(chr(c))
        else:
            if len(cur) >= 2:
                names.append("".join(cur))
            cur = []
    if len(cur) >= 2:
        names.append("".join(cur))
    return names

def dir_entries(ino):
    """读目录条目：LOCAL 内嵌 或 EXTENTS 首块"""
    try:
        info = x.inode(ino)
    except Exception as e:
        return f"ERR {e}"
    if info["fmt"] == 1:
        d = info["raw"][0xB0:0xB0+info["size"]]
        return ascii_names(d)
    exts = x.extents(ino)
    if not exts:
        return "no extents"
    nb = max(1, math.ceil(info["size"] / x.bs))
    # 最多读 8 块
    nb = min(nb, 8)
    d = x.read(exts[0]["startblock"] * x.bs, nb * x.bs)
    return ascii_names(d)

for ino in (324624, 539262, 539526, 540624, 1565459, 1609315, 759110, 958383, 993344):
    try:
        info = x.inode(ino)
        print(f"=== ino {ino} fmt={info['fmt']} size={info['size']} mode={oct(info['mode'])} ===")
        print("   entries:", dir_entries(ino))
    except Exception as e:
        print(f"ino {ino}: ERR {e}")
