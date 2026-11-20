# -*- coding: utf-8 -*-
# 直接解析 wtmp 候选字节（utmp 384B，ut_type==2 BOOT_TIME, tv_sec@338）
import sys, struct, math, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

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

def parse_wtmp_bytes(data):
    boots = []
    for off in range(0, len(data) - 384 + 1, 384):
        rec = data[off:off+384]
        ut_type = struct.unpack_from("<h", rec, 0)[0]
        if ut_type != 2: continue
        tv_sec = struct.unpack_from("<i", rec, 338)[0]
        if 0 < tv_sec < 4_000_000_000:
            boots.append(datetime.datetime.fromtimestamp(tv_sec).strftime("%Y/%m/%d %H:%M:%S"))
    boots.sort()
    return boots

for ino in (26540, 26670, 68278, 68633, 68828, 69061):
    try:
        info = x.inode(ino)
        d = read_data(info)
    except Exception as e:
        print(f"ino {ino}: ERR {e}")
        continue
    boots = parse_wtmp_bytes(d)
    print(f"ino {ino} size={info['size']} fmt={info['fmt']}: boots={boots[:6]}")
