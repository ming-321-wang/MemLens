# -*- coding: utf-8 -*-
# 快速扫描：LOCAL 内嵌数据 + 小文件首块
import sys, struct, math, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

t0 = time.time()
n = x.find_inodes(1024 << 20)
print(f"find_inodes 1GB: {n} inodes in {time.time()-t0:.1f}s", flush=True)

def read_data(info, maxlen=1024):
    try:
        if info["fmt"] == 1:
            d = info["raw"][0xB0:0xB0+min(maxlen, info["size"])]
            return d
        if info["size"] > 128 << 10:
            return b""  # 大文件跳过
        exts = x.extents(info["ino"])
        if not exts:
            return b""
        nb = max(1, math.ceil(min(info["size"], maxlen) / x.bs))
        return x.read(exts[0]["startblock"] * x.bs, nb * x.bs)[:maxlen]
    except Exception:
        return b""

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

file_hits = {"passwd": [], "shadow": [], "config_php": [], "access_log": [], "result_txt": [], "config_json": [], "wtmp": []}
dir_hits = {"etc": [], "www": [], "root_dir": [], "application": [], "var_log": [], "var": []}
nlocal = nfmt2 = 0
for idx, ino in enumerate(list(x._ino_loc.keys())):
    try:
        info = x.inode(ino)
    except Exception:
        continue
    mode = info["mode"]; typ = mode & 0xF000
    if typ == 0x4000:
        names = ascii_names(info["raw"][0xB0:0xB0+112])
        if "passwd" in names or "shadow" in names:
            dir_hits["etc"].append((ino, info["size"], names[:10]))
        if "wwwlogs" in names:
            dir_hits["www"].append((ino, info["size"], names[:10]))
        if "trojan" in names:
            dir_hits["root_dir"].append((ino, info["size"], names[:10]))
        if "config.php" in names or "result.txt" in names:
            dir_hits["application"].append((ino, info["size"], names[:10]))
        if "wtmp" in names:
            dir_hits["var_log"].append((ino, info["size"], names[:10]))
    elif typ == 0x8000:
        if info["fmt"] == 1: nlocal += 1
        else: nfmt2 += 1
        d = read_data(info, 1024)
        if not d: continue
        if b"root:x:0:0" in d[:256]:
            file_hits["passwd"].append((ino, info["fmt"], info["size"], d[:40]))
        if b"AUTH_CODE" in d[:512]:
            file_hits["config_php"].append((ino, info["fmt"], info["size"], d[:60]))
        if (b"GET /" in d[:512] or b"POST /" in d[:512]) and b" HTTP" in d[:512]:
            file_hits["access_log"].append((ino, info["fmt"], info["size"], d[:60]))
        if b"[url]" in d[:256]:
            file_hits["result_txt"].append((ino, info["fmt"], info["size"], d[:60]))
        if b"remote_addr" in d[:512]:
            file_hits["config_json"].append((ino, info["fmt"], info["size"], d[:60]))
        if len(d) >= 384 and d[0:2] in (b"\x02\x00", b"\x01\x00"):
            file_hits["wtmp"].append((ino, info["fmt"], info["size"], d[:32]))
    if (idx+1) % 10000 == 0:
        print(f"  ...{idx+1} inodes, {time.time()-t0:.0f}s", flush=True)

print(f"LOCAL files={nlocal}, EXTENTS files={nfmt2}", flush=True)
for k, v in file_hits.items():
    if v:
        print(f"== FILE {k}: {len(v)} ==", flush=True)
        for hit in v[:8]:
            print(f"  {hit}", flush=True)
for k, v in dir_hits.items():
    if v:
        print(f"== DIR {k}: {len(v)} ==", flush=True)
        for ino, size, names in v[:5]:
            print(f"  ino {ino} size {size} names={names}", flush=True)
