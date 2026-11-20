# -*- coding: utf-8 -*-
# 从挑战 XFS 按内容定位提取各题文件到实体文件（供 MemLens server 子命令逐题演示）
import sys, os
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
OUT = r"D:\MemLens\work\extracted"
os.makedirs(OUT, exist_ok=True)

x, meta = open_server_fs(IMG, PW)
print("opened", flush=True)

def dump(blk, n, name, anchor=None, back=2048, fsize=None):
    """从 blk 读 n 字节；anchor 命中则从 anchor 前 back 处截起。"""
    d = x.read(blk * 4096, n)
    if anchor is not None:
        i = d.find(anchor)
        if i < 0:
            return None
        s = max(0, i - back)
        e = min(len(d), (i + fsize) if fsize else len(d))
        return d[s:e]
    return d

# 1) /etc/passwd（真实 passwd @ blk 3244079）
d = x.read(3244079 * 4096 - 4096, 16384)
i = d.find(b"root:x:0:0")
passwd = d[i:]
passwd = passwd[:passwd.rfind(b"\n")]
open(os.path.join(OUT, "passwd"), "wb").write(passwd)
print("passwd:", len(passwd), flush=True)

# 2) trojan config.json（blk 3000143）
d = x.read(3000143 * 4096, 16384)
i = d.find(b"run_type")
s = d.rfind(b"{", 0, i)
depth = 0; e = s
for j in range(s, len(d)):
    if d[j:j+1] == b"{": depth += 1
    elif d[j:j+1] == b"}":
        depth -= 1
        if depth == 0: e = j + 1; break
open(os.path.join(OUT, "config.json"), "wb").write(d[s:e])
print("config.json:", e - s, flush=True)

# 3) database.php（blk 3210550）
d = x.read(3210550 * 4096, 8192)
i = d.find(b"DB_PWD")
j = d.find(b"<?php")
if j < 0: j = 0
open(os.path.join(OUT, "database.php"), "wb").write(d[j:j + 8192])
print("database.php:", i, j, flush=True)

# 4) config.php（搜 define('AUTH_CODE'）—— 从 solve 命中块里找
found = None
for blk in (44027, 228004, 288002, 3062281):
    d = x.read(blk * 4096, 65536)
    k = d.find(b"AUTH_CODE")
    if k >= 0 and b"define" in d[max(0, k - 120):k]:
        found = (blk, d, k); break
if found:
    blk, d, k = found
    open(os.path.join(OUT, "config.php"), "wb").write(d[max(0, k - 2048):k + 4096])
    print("config.php blk", blk, "off", k, flush=True)
else:
    print("config.php 未找到 define AUTH_CODE", flush=True)

# 5) access.log（blk 3256475）
d = x.read(3256475 * 4096, 1 << 20)
open(os.path.join(OUT, "access.log"), "wb").write(d)
print("access.log:", len(d), flush=True)

# 6) dump.sql（blk 228231，取 32 MiB）
d = x.read(228231 * 4096, 32 << 20)
open(os.path.join(OUT, "dump.sql"), "wb").write(d)
print("dump.sql:", len(d), flush=True)

# 7) wtmp（blk 5928345，取 4 MiB）
d = x.read(5928345 * 4096, 4 << 20)
open(os.path.join(OUT, "wtmp"), "wb").write(d)
print("wtmp:", len(d), flush=True)

# 8) result.txt（blk 6129187）
d = x.read(6129187 * 4096 - 4096, 65536)
open(os.path.join(OUT, "result.txt"), "wb").write(d)
print("result.txt:", len(d), flush=True)

print("OUT:", OUT, flush=True)
