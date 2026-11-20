# -*- coding: utf-8 -*-
# 对 fmt=2 目录也检查内嵌区 raw[0xB0:0xB0+112]，找 etc/root/var 的 inode
import sys, struct, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
t0 = time.time()
n = x.find_inodes(1024 << 20)
print(f"find_inodes 1GB: {n} inodes in {time.time()-t0:.1f}s", flush=True)

def ascii_names(d, minlen=2):
    names = []
    cur = []
    for c in d:
        if 0x30 <= c <= 0x39 or 0x61 <= c <= 0x7a or 0x41 <= c <= 0x5a or c in (0x2e, 0x2d, 0x5f, 0x2f, 0x24, 0x7e, 0x2b, 0x3d, 0x40):
            cur.append(chr(c))
        else:
            if len(cur) >= minlen:
                names.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        names.append("".join(cur))
    return names

# 先看根目录内嵌名（找 etc/root/var/application/www 的完整列表）
root_info = x.inode(64)
print("ROOT embedded names:", ascii_names(root_info["raw"][0xB0:0xB0+112]), flush=True)

found = {}
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
    sn = set(names)
    for key, needles in {
        "etc": ("passwd", "shadow", "group"),
        "root_dir": ("trojan", ".bashrc", ".bash_history"),
        "var_log": ("wtmp", "btmp", "lastlog"),
        "var": ("log", "spool", "cache", "www"),
    }.items():
        if any(nd in sn for nd in needles):
            found.setdefault(key, []).append((ino, info["fmt"], info["size"], names[:24]))
    if (idx+1) % 20000 == 0:
        print(f"  ...{idx+1} inodes, {time.time()-t0:.0f}s", flush=True)

for k, v in found.items():
    print(f"== {k}: {len(v)} ==", flush=True)
    for ino, fmt, size, names in v[:8]:
        print(f"  ino {ino} fmt={fmt} size={size} names={names}", flush=True)
