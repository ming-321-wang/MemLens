# -*- coding: utf-8 -*-
# 全表内容搜索：读小文件 extent 找 config.php/config.json/result.txt/passwd/access.log
import sys, struct, math, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
t0 = time.time()
n = x.find_inodes(1024 << 20)
print(f"find_inodes 1GB: {n} inodes in {time.time()-t0:.1f}s", flush=True)

hits = {"passwd": [], "config_php": [], "access_log": [], "result_txt": [], "config_json": []}
nread = 0
for idx, ino in enumerate(list(x._ino_loc.keys())):
    try:
        info = x.inode(ino)
    except Exception:
        continue
    if (info["mode"] & 0xF000) != 0x8000:
        continue
    size = info["size"]
    if size == 0 or size > 65536:
        continue
    if info["fmt"] == 1:
        d = info["raw"][0xB0:0xB0+size]
    else:
        try:
            exts = x.extents(ino)
            if not exts:
                continue
            nb = max(1, math.ceil(min(size, 2048) / x.bs))
            d = x.read(exts[0]["startblock"] * x.bs, nb * x.bs)[:min(size, 2048)]
            nread += 1
        except Exception:
            continue
    if not d: continue
    if b"root:x:0:0" in d[:256]:
        hits["passwd"].append((ino, size, d[:60]))
    if b"AUTH_CODE" in d[:2048]:
        hits["config_php"].append((ino, size, d[:80]))
    if b"[url]" in d[:256]:
        hits["result_txt"].append((ino, size, d[:80]))
    if b"remote_addr" in d[:2048]:
        hits["config_json"].append((ino, size, d[:80]))
    if (b"GET /" in d[:2048] or b"POST /" in d[:2048]) and b"HTTP" in d[:2048]:
        hits["access_log"].append((ino, size, d[:80]))
    if (idx+1) % 10000 == 0:
        print(f"  ...{idx+1} inodes ({nread} extent reads) {time.time()-t0:.0f}s", flush=True)

print(f"done, {nread} extent reads in {time.time()-t0:.0f}s", flush=True)
for k, v in hits.items():
    print(f"== {k}: {len(v)} ==", flush=True)
    for ino, size, head in v[:10]:
        print(f"  ino {ino} size {size} head={head!r}", flush=True)
