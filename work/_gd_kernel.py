# -*- coding: utf-8 -*-
# 搜 GD 版本 / trojan 示例 / 运行内核在已知区域
import sys, re, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
# 已知区域：内核 source (blk 44825/73512), php 相关, trojan (blk 3000143)
regions = [
    ("kernel_src", 44800, 100),   # blk 44825 kernel config
    ("kernels_dir", 73500, 100),  # blk 73512 /usr/src/kernels
    ("trojan", 2999900, 500),     # blk 3000143 trojan
    ("php_bin", 200000, 2000),    # php 相关
]
for name, blk0, cnt in regions:
    d = x.read(blk0*4096, cnt*4096)
    for pat in [b"2.1.0 compatible", b"GD Version", b"nat-json", b"client-json", b"run_type", b"1160.119.1"]:
        i = d.find(pat)
        if i >= 0:
            ctx = d[max(0,i-60):i+100]
            print(f"[{name}] {pat!r} @ blk {blk0+i//4096}: {ctx!r}", flush=True)
print("done", flush=True)
