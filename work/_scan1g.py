# -*- coding: utf-8 -*-
# 全面扫描 1GB 找目标文件 + 内嵌目录名
import sys, struct, math, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

t0 = time.time()
n = x.find_inodes(1024 << 20)
print(f"find_inodes 1GB: {n} inodes in {time.time()-t0:.1f}s")

def read_head(ino, info, maxlen=512):
    try:
        if info["fmt"] == 1:
            return info["raw"][0xB0:0xB0+min(maxlen, info["size"])]
        exts = x.extents(ino)
        if not exts:
            return b""
        size = info["size"]
        nb = max(1, min(math.ceil(size / x.bs), 4))  # 只读前 4 块
        return x.read(exts[0]["startblock"] * x.bs, nb * x.bs)[:maxlen]
    except Exception:
        return b""

def ascii_names(d):
    # 提取内嵌 ASCII 名字
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

# 搜索目录: 找包含 passwd/shadow 的目录 (etc), 包含 wwwlogs 的 (www), 包含 trojan 的 (root)
dir_hits = {"etc": [], "www": [], "root": [], "application": [], "var_log": [], "var": []}
# 文件搜索
file_hits = {"passwd": [], "shadow": [], "config_php": [], "access_log": [], "result_txt": [], "config_json": []}
total = 0
for ino in list(x._ino_loc.keys()):
    try:
        info = x.inode(ino)
    except Exception:
        continue
    mode = info["mode"]; typ = mode & 0xF000
    if typ == 0x4000:  # 目录
        d = info["raw"][0xB0:0xB0+112]
        names = ascii_names(d)
        joined = ",".join(names)
        if "passwd" in names or "shadow" in names:
            dir_hits["etc"].append((ino, info["size"], names[:12]))
        if "wwwlogs" in names or "wwwroot" in names:
            dir_hits["www"].append((ino, info["size"], names[:12]))
        if "trojan" in names:
            dir_hits["root"].append((ino, info["size"], names[:12]))
        if "config.php" in names or "result.txt" in names:
            dir_hits["application"].append((ino, info["size"], names[:12]))
        if "log" in names and "wtmp" in names:
            dir_hits["var_log"].append((ino, info["size"], names[:12]))
        if "www" in names or "log" in names or "tmp" in names or "run" in names:
            dir_hits["var"].append((ino, info["size"], names[:15]))
    elif typ == 0x8000:  # 文件
        total += 1
        d = read_head(ino, info)
        if not d: continue
        if b"root:x:0:0" in d[:256]:
            file_hits["passwd"].append((ino, info["size"], d[:40]))
        if b"root:" in d[:32] and b":0:" in d[:32]:
            file_hits["shadow"].append((ino, info["size"], d[:40]))
        if b"AUTH_CODE" in d[:512] or b"auth_code" in d[:512]:
            file_hits["config_php"].append((ino, info["size"], d[:60]))
        if (b"GET /" in d[:512] or b"POST /" in d[:512]) and b"." in d[:64]:
            file_hits["access_log"].append((ino, info["size"], d[:60]))
        if b"[url]" in d[:256]:
            file_hits["result_txt"].append((ino, info["size"], d[:60]))
        if b"remote_addr" in d[:512] or b"remote" in d[:256] and b"port" in d[:256]:
            file_hits["config_json"].append((ino, info["size"], d[:60]))

print(f"\nreg files checked: {total}")
for k, v in dir_hits.items():
    if v:
        print(f"== DIR {k}: {len(v)} ==")
        for ino, size, names in v[:5]:
            print(f"  ino {ino} size {size} names={names}")
for k, v in file_hits.items():
    if v:
        print(f"== FILE {k}: {len(v)} ==")
        for ino, size, head in v[:5]:
            print(f"  ino {ino} size {size} head={head!r}")
