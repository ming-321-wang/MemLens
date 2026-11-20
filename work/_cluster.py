# -*- coding: utf-8 -*-
# 搜索 blk 288000 聚簇区域（off 1.0-1.5GB）找所有挑战文件内容
import sys, struct, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

patterns = {
    "db_pwd": b"DB_PWD",
    "db_host": b"DB_HOST",
    "run_type": b"run_type",
    "domain": b"wyzshop",
    "title": b"[title]",
    "finger": b"[finger]",
    "icmp": b"[icmp]",
    "root_x": b"root:x:0:0:root:/root:/bin/bash",
    "remote_port": b"remote_port",
}
END = 2 << 30
CHUNK = 32 << 20
t0 = time.time()
found = {}
pos = 0
while pos < END:
    n = min(CHUNK, END - pos)
    buf = x.read(pos, n)
    for key, pat in patterns.items():
        idx = buf.find(pat)
        while idx >= 0:
            abs_off = pos + idx
            found.setdefault(key, []).append((abs_off, buf[max(0,idx-64):idx+96]))
            idx = buf.find(pat, idx+1)
    pos += n
    if pos % (256<<20) < CHUNK:
        print(f"  scanned {pos/1e9:.2f}GB in {time.time()-t0:.0f}s", flush=True)

print(f"=== done {END/1e9:.2f}GB ===", flush=True)
for k, v in found.items():
    print(f"[{k}] {len(v)} hits", flush=True)
    for off, ctx in v[:4]:
        print(f"  off {off} blk {off//4096}: {ctx!r}", flush=True)
