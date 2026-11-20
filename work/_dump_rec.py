# -*- coding: utf-8 -*-
# dump blk 5928345 记录字节，找 1645593829（2022/2/23 12:23:49）
import sys, struct, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
d = x.read(5928345*4096, 4096)
# 找 1645593829 的 LE 4字节
target = struct.pack("<i", 1645593829)
idx = d.find(target)
print("目标时间戳位置:", idx, flush=True)
# dump 记录（384B）的尾部（offset 300-384）
rec = d[0:384]
print("记录 user:", rec[44:44+32].split(b'\x00')[0], flush=True)
print("记录 host:", rec[76:76+256].split(b'\x00')[0], flush=True)
print("offset 300-384 hex:", rec[300:384].hex(), flush=True)
# 也查 blk 5928346-5928360 的每个记录，找目标时间戳
for b in range(5928345, 5928361):
    dd = x.read(b*4096, 4096)
    i = dd.find(target)
    if i >= 0:
        print(f"blk {b} off {i} 找到目标时间戳", flush=True)
        print("  ctx:", dd[max(0,i-20):i+40].hex(), flush=True)
