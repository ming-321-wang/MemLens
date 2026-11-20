# -*- coding: utf-8 -*-
# 纯目录扫描：定位 etc/www/root/application/var 等目录的 inode 号
import sys, struct, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

t0 = time.time()
n = x.find_inodes(1024 << 20)
print(f"find_inodes 1GB: {n} inodes in {time.time()-t0:.1f}s", flush=True)

def ascii_names(d):
    names = []
    cur = []
    for c in d:
        if 0x30 <= c <= 0x39 or 0x61 <= c <= 0x7a or 0x41 <= c <= 0x5a or c in (0x2e, 0x2d, 0x5f, 0x2f, 0x24, 0x7e, 0x2b, 0x3d, 0x40):
            cur.append(chr(c))
        else:
            if len(cur) >= 3:
                names.append("".join(cur))
            cur = []
    if len(cur) >= 3:
        names.append("".join(cur))
    return names

# 目标目录的关键子项
targets = {
    "passwd": "etc", "shadow": "etc", "wtmp": "var_log",
    "trojan": "root_dir", "config.php": "application", "result.txt": "application",
    "wwwlogs": "www", "dump": "any",
}
dirs = {}
for idx, ino in enumerate(list(x._ino_loc.keys())):
    try:
        info = x.inode(ino)
    except Exception:
        continue
    if (info["mode"] & 0xF000) != 0x4000:
        continue
    names = ascii_names(info["raw"][0xB0:0xB0+112])
    if not names:
        continue
    for nm in ("passwd", "shadow", "wtmp", "trojan", "config.php", "result.txt", "wwwlogs", "dump"):
        if nm in names:
            dirs.setdefault(nm, []).append((ino, info["size"], names[:16]))
    if (idx+1) % 10000 == 0:
        print(f"  ...{idx+1} inodes, {time.time()-t0:.0f}s", flush=True)

print("=== DIR RESULTS ===", flush=True)
for nm, hits in dirs.items():
    print(f"[{nm}] {len(hits)} hits", flush=True)
    for ino, size, names in hits[:8]:
        print(f"  ino {ino} size {size} names={names}", flush=True)
