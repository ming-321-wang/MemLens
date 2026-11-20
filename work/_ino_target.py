# -*- coding: utf-8 -*-
# 针对性 inode 内容搜索 25000-70000（SQL/wtmp 聚簇区），找所有挑战文件
import sys, struct, math, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
x.find_inodes(1024 << 20)
print("inodes:", len(x._ino_loc), flush=True)

def read_full(info, maxlen=8192):
    try:
        if info["fmt"] == 1:
            return info["raw"][0xB0:0xB0+min(maxlen, info["size"])]
        if info["size"] > 1 << 20:
            return b""
        exts = x.extents(info["ino"])
        if not exts:
            return b""
        nb = max(1, math.ceil(min(info["size"], maxlen) / x.bs))
        return x.read(exts[0]["startblock"] * x.bs, nb * x.bs)[:min(info["size"], maxlen)]
    except Exception:
        return b""

pats = {
    "passwd": (b"root:x:0:0", b""),
    "trojan": (b"run_type", b"remote_addr"),
    "result": (b"[title]", b""),
    "rdp": (b"[RDP]", b""),
    "access": (b"POST /", b"GET /"),
    "dbpwd": (b"a7b3e16ac20b10bb", b""),
    "tpshop": (b"tpshop", b"www.tpshop"),
    "wyzshop": (b"wyzshop", b""),
    "order": (b"tp_order", b""),
    "users": (b"tp_users", b""),
    "freight": (b"freight_free", b""),
}
hits = {}
t0 = time.time()
cnt = 0
for ino in sorted(x._ino_loc.keys()):
    if not (20000 <= ino <= 72000):
        continue
    try:
        info = x.inode(ino)
    except Exception:
        continue
    if (info["mode"] & 0xF000) != 0x8000:
        continue
    if info["size"] == 0:
        continue
    cnt += 1
    d = read_full(info, 8192)
    if not d: continue
    for key, (p1, p2) in pats.items():
        if p1 in d and (p2 == b"" or p2 in d):
            hits.setdefault(key, []).append((ino, info["fmt"], info["size"], d[:100]))
    if cnt % 5000 == 0:
        print(f"  ...{cnt} files, {time.time()-t0:.0f}s", flush=True)

print(f"=== {cnt} files in {time.time()-t0:.0f}s ===", flush=True)
for k, v in hits.items():
    print(f"[{k}] {len(v)}", flush=True)
    for ino, fmt, size, head in v[:5]:
        print(f"  ino {ino} fmt={fmt} size={size}: {head!r}", flush=True)
