# -*- coding: utf-8 -*-
# 综合搜索：tp_config / wtmp / kernel / trojan examples / GD
import sys, struct, re, time, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
END = 11827200 * x.bs
CHUNK = 32 << 20
patterns = [
    ("tp_config", b"INSERT INTO `tp_config`"),
    ("kernel", b"3.10.0-1160"),
    ("nat_json", b"nat-json"),
    ("examples", b"examples/trojan"),
    ("freight_100000", b"freight_free"),
]
found = {}
t0=time.time(); pos=0
while pos < END:
    n = min(CHUNK, END-pos)
    d = x.read(pos, n)
    for key, pat in patterns:
        idx = d.find(pat)
        while idx >= 0:
            abs_off = pos+idx
            found.setdefault(key, []).append((abs_off, d[max(0,idx-70):idx+130]))
            idx = d.find(pat, idx+1)
    pos += n
    if pos % (8<<30) < CHUNK:
        print(f"  scanned {pos/1e9:.1f}GB in {time.time()-t0:.0f}s", flush=True)
print(f"=== done {END/1e9:.1f}GB ===", flush=True)
for k, v in found.items():
    print(f"[{k}] {len(v)} hits", flush=True)
    for off, ctx in v[:4]:
        print(f"  off {off} blk {off//4096}: {ctx!r}", flush=True)
