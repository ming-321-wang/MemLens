# -*- coding: utf-8 -*-
# 扫 wtmp 区域，tv_sec@332（标准 glibc 布局）有效记录
import sys, struct, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
found=[]
for blk in range(5928300, 5928700):
    dd = x.read(blk*4096, 4096)
    for rs in range(0, 4096-384, 384):
        r = dd[rs:rs+384]
        if struct.unpack_from("<h", r, 0)[0] == 2:
            tv = struct.unpack_from("<i", r, 332)[0]
            if 0 < tv < 4_000_000_000:
                host = r[76:76+256].split(b"\x00")[0]
                found.append((blk, rs, tv, host.decode("utf-8","replace")))
found.sort(key=lambda f: f[2])
print(f"tv@332 有效记录 {len(found)} 条：", flush=True)
for blk, rs, tv, host in found:
    print(f"  blk {blk} rs {rs}: {datetime.datetime.fromtimestamp(tv)}  host={host}", flush=True)
