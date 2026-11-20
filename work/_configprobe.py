# -*- coding: utf-8 -*-
# 看 AUTH_CODE 上下文，确认 config.php 真实形态
import sys
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

for blk in (44027, 228004, 288002):
    d = x.read(blk * 4096, 16384)
    k = d.find(b"AUTH_CODE")
    print(f"=== blk {blk}  AUTH_CODE@{k} ===", flush=True)
    if k >= 0:
        print(repr(d[max(0, k - 260):k + 260]), flush=True)
        print(flush=True)

# 全盘找 define('AUTH_CODE' 形态（在已知偏移 off 180334064 附近）
d = x.read(180334064 - 8192, 32768)
k = d.find(b"AUTH_CODE")
print("=== off 180334064 附近 ===", k, flush=True)
print(repr(d[max(0, k - 300):k + 300]), flush=True)
