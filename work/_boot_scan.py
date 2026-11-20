# -*- coding: utf-8 -*-
# 搜 boot 记录特征 "3.10.0-514.el7.x"（ut_host）→ 检查 utmp 记录
import sys, struct, time, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
END = 11827200 * x.bs
CHUNK = 32 << 20
t0=time.time(); pos=0; found=[]
while pos < END:
    n = min(CHUNK, END-pos)
    d = x.read(pos, n)
    idx = d.find(b"3.10.0-514.el7.x")
    while idx >= 0:
        # ut_host @76 → rec_start = idx-76
        rs = idx - 76
        if rs >= 0:
            ut = struct.unpack_from("<h", d, rs)[0] if rs+384 <= len(d) else -1
            tv = struct.unpack_from("<i", d, rs+338)[0] if rs+384 <= len(d) else 0
            if ut == 2:
                found.append((pos+rs, tv))
        idx = d.find(b"3.10.0-514.el7.x", idx+1)
    pos += n
    if pos % (8<<30) < CHUNK:
        print(f"  scanned {pos/1e9:.1f}GB in {time.time()-t0:.0f}s, hits={len(found)}", flush=True)
print(f"=== done {len(found)} ===", flush=True)
for off, tv in found:
    s = datetime.datetime.fromtimestamp(tv) if 0 < tv < 4_000_000_000 else "?"
    print(f"  off {off} blk {off//4096}: {s}", flush=True)
