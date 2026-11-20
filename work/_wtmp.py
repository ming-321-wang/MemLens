# -*- coding: utf-8 -*-
# 解析 wtmp 候选，找 BOOT_TIME 2022/2/23 12:23:49
import sys, struct, math, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs
from memlens.core.server_forensics import parse_wtmp

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
x.find_inodes(1024 << 20)

def read_data(info, maxlen=65536):
    if info["fmt"] == 1:
        return info["raw"][0xB0:0xB0+min(maxlen, info["size"])]
    if info["size"] > maxlen: return b""
    exts = x.extents(info["ino"])
    if not exts: return b""
    nb = max(1, math.ceil(info["size"] / x.bs))
    return x.read(exts[0]["startblock"] * x.bs, nb * x.bs)[:info["size"]]

cands = [26540, 26670, 68278, 68633, 68828, 69061]
for ino in cands:
    try:
        info = x.inode(ino)
        d = read_data(info)
    except Exception as e:
        print(f"ino {ino}: ERR {e}")
        continue
    try:
        boots = parse_wtmp(d)
        print(f"ino {ino} size={info['size']}: boots={boots}")
    except Exception as e:
        print(f"ino {ino} size={info['size']}: parse err {e}, head={d[:32]!r}")
