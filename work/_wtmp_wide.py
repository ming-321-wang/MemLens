# -*- coding: utf-8 -*-
# 宽区域扫 boot 记录，找最早（2022/2/23）
import sys, struct, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
# 扫 blk 5926000-5929000 所有 ut_type=2 记录，tv_sec@340
boots=[]
for blk in range(5926000, 5929000):
    dd = x.read(blk*4096, 4096)
    for rs in range(0, 4096-384, 384):
        r = dd[rs:rs+384]
        if struct.unpack_from("<h", r, 0)[0] == 2:
            tv = struct.unpack_from("<i", r, 340)[0]
            if 0 < tv < 4_000_000_000:
                host = r[76:76+256].split(b"\x00")[0]
                boots.append((blk, rs, tv, host.decode("utf-8","replace")))
boots.sort(key=lambda b: b[2])
print(f"共 {len(boots)} 个 boot 记录，最早 5 个：", flush=True)
for blk, rs, tv, host in boots[:5]:
    print(f"  blk {blk} rs {rs}: {datetime.datetime.fromtimestamp(tv)}  host={host}", flush=True)
print("最晚 3 个：", flush=True)
for blk, rs, tv, host in boots[-3:]:
    print(f"  blk {blk} rs {rs}: {datetime.datetime.fromtimestamp(tv)}  host={host}", flush=True)
