# -*- coding: utf-8 -*-
# 读 blk 5928345 的 boot 记录，核实 tv_sec 偏移（332 vs 338）
import sys, struct, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
# blk 5928345 附近
d = x.read(5928345*4096, 8192)
for rs in range(0, 8192-384, 384):
    rec = d[rs:rs+384]
    ut = struct.unpack_from("<h", rec, 0)[0]
    if ut == 2:
        user = rec[44:44+32].split(b"\x00")[0].decode("utf-8","replace")
        host = rec[76:76+256].split(b"\x00")[0].decode("utf-8","replace")
        t332 = struct.unpack_from("<i", rec, 332)[0]
        t338 = struct.unpack_from("<i", rec, 338)[0]
        s332 = datetime.datetime.fromtimestamp(t332) if 0<t332<4_000_000_000 else "?"
        s338 = datetime.datetime.fromtimestamp(t338) if 0<t338<4_000_000_000 else "?"
        print(f"rec@{rs} type={ut} user={user!r} host={host!r}", flush=True)
        print(f"   tv_sec@332={t332} ({s332})   tv_sec@338={t338} ({s338})", flush=True)
