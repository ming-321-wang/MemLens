# -*- coding: utf-8 -*-
# 过滤真实 boot 记录（host=3.10.0-514 或 1160.119.1），找最早
import sys, struct, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
boots=[]
for blk in range(5920000, 5930000):
    dd = x.read(blk*4096, 4096)
    for rs in range(0, 4096-384, 384):
        r = dd[rs:rs+384]
        if struct.unpack_from("<h", r, 0)[0] == 2:
            host = r[76:76+256].split(b"\x00")[0]
            if b"3.10.0-514" in host or b"3.10.0-1160" in host:
                tv = struct.unpack_from("<i", r, 340)[0]
                if 0 < tv < 4_000_000_000:
                    boots.append((blk, rs, tv, host.decode("utf-8","replace")))
boots.sort(key=lambda b: b[2])
print(f"真实 boot 记录 {len(boots)} 条：", flush=True)
for blk, rs, tv, host in boots:
    print(f"  blk {blk} rs {rs}: {datetime.datetime.fromtimestamp(tv)}  host={host}", flush=True)
