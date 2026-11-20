# -*- coding: utf-8 -*-
# 原始块扫描 LV 数据区，找 passwd/config.php/config.json/result.txt/access.log 内容
import sys, struct, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
print("meta lvm_offset", meta.get("lvm_offset"), "xfs base", x.base, "bs", x.bs, "dblocks", x.dblocks, flush=True)

# 从 xfs 起点扫描整个数据区（分块），找模式
patterns = {
    "passwd": b"root:x:0:0",
    "config_php": b"AUTH_CODE",
    "config_json": b"remote_addr",
    "result_txt": b"[url]",
}
total_bytes = x.dblocks * x.bs
CHUNK = 32 << 20
t0 = time.time()
found = {}
scanned = 0
pos = 0
while pos < total_bytes:
    n = min(CHUNK, total_bytes - pos)
    buf = x.read(pos, n)
    scanned += n
    for key, pat in patterns.items():
        idx = buf.find(pat)
        if idx >= 0:
            abs_off = pos + idx
            found.setdefault(key, []).append((abs_off, buf[max(0,idx-64):idx+120]))
    # 也扫访问日志
    gi = buf.find(b"GET /")
    if gi >= 0 and b" HTTP" in buf[gi:gi+200]:
        abs_off = pos + gi
        found.setdefault("access_log", []).append((abs_off, buf[gi:gi+160]))
    pos += n
    if scanned % (256 << 20) < CHUNK:
        print(f"  scanned {scanned/1e9:.2f}GB / {total_bytes/1e9:.1f}GB in {time.time()-t0:.0f}s", flush=True)

print(f"=== done scanning {scanned/1e9:.2f}GB in {time.time()-t0:.0f}s ===", flush=True)
for k, v in found.items():
    print(f"[{k}] {len(v)} hits", flush=True)
    for off, ctx in v[:5]:
        print(f"  off {off} ({off/4096:.0f} blk): {ctx!r}", flush=True)
