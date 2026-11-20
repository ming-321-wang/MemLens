# -*- coding: utf-8 -*-
# 全 XFS 扫描找挑战文件唯一串（fast numpy path）
import sys, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
DBLOCKS = meta.get("dblocks") or 11827200
END = DBLOCKS * x.bs
CHUNK = 32 << 20
patterns = [
    ("trojan", b"wyzshop1"),
    ("access_peiqi", b"peiqi.php"),
    ("access_invoke", b"invokefunction"),
    ("result_rdp", b"[RDP]"),
    ("result_icmp", b"[icmp]"),
    ("config_auth", b"AUTH_CODE"),
    ("dbpwd", b"a7b3e16ac20b10bb"),
    ("freight", b"freight_free"),
    ("passwd", b"root:x:0:0:root:/root:/bin/bash"),
]
found = {}
t0 = time.time()
pos = 0
while pos < END:
    n = min(CHUNK, END - pos)
    buf = x.read(pos, n)
    for key, pat in patterns:
        idx = buf.find(pat)
        while idx >= 0:
            abs_off = pos + idx
            found.setdefault(key, []).append((abs_off, buf[max(0,idx-48):idx+80]))
            idx = buf.find(pat, idx+1)
    pos += n
    if pos % (2<<30) < CHUNK:
        print(f"  scanned {pos/1e9:.1f}GB in {time.time()-t0:.0f}s", flush=True)

print(f"=== done {END/1e9:.1f}GB in {time.time()-t0:.0f}s ===", flush=True)
for k, v in found.items():
    print(f"[{k}] {len(v)} hits", flush=True)
    for off, ctx in v[:4]:
        print(f"  off {off} blk {off//4096}: {ctx!r}", flush=True)
