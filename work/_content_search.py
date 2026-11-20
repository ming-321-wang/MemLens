# -*- coding: utf-8 -*-
# 内容搜索：扫描 inode 表找 passwd / config.json / config.php / access.log / result.txt / dump.sql / wtmp
import sys, struct, re
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

# 先扫描 inode 定位
t0 = __import__("time").time()
n = x.find_inodes(256 << 20)
print(f"find_inodes 256MB: {n} inodes in {__import__('time').time()-t0:.1f}s")
print("total _ino_loc:", len(x._ino_loc))

def data_of(ino):
    try:
        info = x.inode(ino)
        if info["fmt"] == 1:
            return info["raw"][0xB0:0xB0+info["size"]]
        exts = x.extents(ino)
        if not exts:
            return b""
        size = info["size"]
        import math
        nb = max(1, math.ceil(size / x.bs))
        return x.read(exts[0]["startblock"] * x.bs, nb * x.bs)[:size]
    except Exception as e:
        return b""

hits = {"passwd": [], "config_json": [], "config_php": [], "access_log": [], "result_txt": [], "sql": [], "wtmp": []}
count = 0
for ino in list(x._ino_loc.keys()):
    try:
        info = x.inode(ino)
    except Exception:
        continue
    mode = info["mode"]
    typ = mode & 0xF000
    if typ != 0x8000:  # 只搜普通文件
        continue
    size = info["size"]
    if size == 0 or size > 64 << 20:
        continue
    count += 1
    d = data_of(ino)
    if not d:
        continue
    if d.startswith(b"root:x:0:0") or b"root:x:0:0:" in d[:256]:
        hits["passwd"].append((ino, size, d[:64]))
    if b"remote_addr" in d[:512] or b'"remote"' in d[:512]:
        hits["config_json"].append((ino, size, d[:64]))
    if b"AUTH_CODE" in d[:512]:
        hits["config_php"].append((ino, size, d[:64]))
    if d[:4].isdigit() and (b"GET /" in d[:512] or b"POST /" in d[:512]):
        hits["access_log"].append((ino, size, d[:64]))
    if (b"[url]" in d[:256] or b"[title]" in d[:256]) and b"[" in d[:256]:
        hits["result_txt"].append((ino, size, d[:64]))
    if b"INSERT INTO" in d[:512] or b"insert into" in d[:512]:
        hits["sql"].append((ino, size, d[:64]))
    if len(d) >= 384 and b"\x02\x00\x00\x00" in d[:16]:
        hits["wtmp"].append((ino, size, d[:64]))

print("scanned reg files:", count)
for k, v in hits.items():
    print(f"== {k}: {len(v)} hits ==")
    for ino, size, head in v[:6]:
        print(f"  ino {ino} size {size} head={head[:60]!r}")
