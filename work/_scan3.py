# -*- coding: utf-8 -*-
# 全 48GB 综合扫描：真实 passwd / freight_free 值 / webshell / 完整 dump.sql / wtmp
import sys, struct, re, time, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
DBLOCKS = meta.get("dblocks") or 11827200
END = DBLOCKS * x.bs
CHUNK = 32 << 20
patterns = [
    ("passwd_www", b"www:x:1000"),
    ("passwd_mysql", b"mysql:x:1001"),
    ("freight_val", b"freight_free"),
    ("webshell", b"@eval($_POST"),
    ("tp_order_full", b"INSERT INTO `tp_order`"),
    ("wtmp_boot", b"reboot"),
    ("result_ftp", b"[ftp]"),
    ("result_smb", b"[smb]"),
]
found = {}
t0 = time.time(); pos = 0
while pos < END:
    n = min(CHUNK, END - pos)
    d = x.read(pos, n)
    for key, pat in patterns:
        idx = d.find(pat)
        while idx >= 0:
            abs_off = pos + idx
            found.setdefault(key, []).append((abs_off, d[max(0,idx-70):idx+110]))
            idx = d.find(pat, idx+1)
    pos += n
    if pos % (4<<30) < CHUNK:
        print(f"  scanned {pos/1e9:.1f}GB in {time.time()-t0:.0f}s", flush=True)
print(f"=== done {END/1e9:.1f}GB in {time.time()-t0:.0f}s ===", flush=True)
for k, v in found.items():
    print(f"[{k}] {len(v)} hits", flush=True)
    for off, ctx in v[:4]:
        print(f"  off {off} blk {off//4096}: {ctx!r}", flush=True)
