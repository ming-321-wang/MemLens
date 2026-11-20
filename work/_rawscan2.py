# -*- coding: utf-8 -*-
# 针对性扫描 0-4GB 找挑战文件内容（SQL 数据在 ~1.18GB 附近）
import sys, struct, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

patterns = {
    "passwd": b"root:x:0:0",
    "config_php": b"AUTH_CODE",
    "config_json": b"remote_addr",
    "result_txt": b"[url]",
}
END = 4 << 30  # 0-4GB
CHUNK = 32 << 20
t0 = time.time()
found = {}
pos = 0
while pos < END:
    n = min(CHUNK, END - pos)
    buf = x.read(pos, n)
    for key, pat in patterns.items():
        idx = buf.find(pat)
        if idx >= 0:
            abs_off = pos + idx
            found.setdefault(key, []).append((abs_off, buf[max(0,idx-64):idx+128]))
    gi = buf.find(b"GET /")
    if gi >= 0 and b" HTTP" in buf[gi:gi+200]:
        found.setdefault("access_log", []).append((pos+gi, buf[gi:gi+180]))
    pos += n
    print(f"  scanned {pos/1e9:.2f}GB in {time.time()-t0:.0f}s", flush=True)

print(f"=== done {END/1e9:.2f}GB in {time.time()-t0:.0f}s ===", flush=True)
for k, v in found.items():
    print(f"[{k}] {len(v)} hits", flush=True)
    for off, ctx in v[:6]:
        print(f"  off {off} blk {off/4096:.0f}: {ctx!r}", flush=True)
