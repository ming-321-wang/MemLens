# -*- coding: utf-8 -*-
# 精确定位 96b72162（时间戳）在 boot 记录中的偏移 + 解析全部 boot 记录
import sys, struct, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
d = x.read(5928345*4096, 4096)
rec = d[0:384]
i = rec.find(bytes.fromhex("96b72162"))
print(f"96b72162 @ 记录偏移 {i}", flush=True)
# 从该偏移读 4 字节
if i >= 0:
    tv = struct.unpack_from("<i", rec, i)[0]
    print(f"  tv_sec={tv} ({datetime.datetime.fromtimestamp(tv)})", flush=True)
# 扫描 wtmp 区域（blk 5928345-5928700）所有 ut_type=2 记录，取 tv@i 和 tv@332/338
print("扫描 wtmp 区域所有 boot 记录...", flush=True)
for blk in range(5928345, 5928700):
    dd = x.read(blk*4096, 4096)
    for rs in range(0, 4096-384, 384):
        r = dd[rs:rs+384]
        if struct.unpack_from("<h", r, 0)[0] == 2:
            user = r[44:44+32].split(b"\x00")[0]
            host = r[76:76+256].split(b"\x00")[0]
            tv = None
            for o in (i if i>=0 else 338, 332, 338):
                try:
                    t = struct.unpack_from("<i", r, o)[0]
                    if 0 < t < 4_000_000_000:
                        tv = (o, t); break
                except: pass
            print(f"  blk {blk} rs {rs} user={user.decode('utf-8','replace')} host={host.decode('utf-8','replace')} tv={tv and (tv[0], datetime.datetime.fromtimestamp(tv[1]))}", flush=True)
