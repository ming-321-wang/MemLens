# -*- coding: utf-8 -*-
# 找所有 "INSERT INTO `tp_order`" 位置，按块分组
import sys, re, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
END = 11827200 * x.bs
CHUNK = 32 << 20
hits = []
t0=time.time(); pos=0
while pos < END:
    n = min(CHUNK, END-pos)
    d = x.read(pos, n)
    idx = d.find(b"INSERT INTO `tp_order`")
    while idx >= 0:
        hits.append(pos+idx)
        idx = d.find(b"INSERT INTO `tp_order`", idx+1)
    pos += n
    if pos % (8<<30) < CHUNK:
        print(f"  scanned {pos/1e9:.1f}GB in {time.time()-t0:.0f}s hits={len(hits)}", flush=True)
print(f"=== done {len(hits)} hits ===", flush=True)
# 按块分组
from collections import Counter
blocks = Counter(h//4096 for h in hits)
print("不同块数:", len(blocks), flush=True)
for blk, c in sorted(blocks.items()):
    print(f"  blk {blk}: {c} hits", flush=True)
