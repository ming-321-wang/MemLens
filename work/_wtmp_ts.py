# -*- coding: utf-8 -*-
# 搜 wtmp 区域 2022-02-23 时间戳（1645575829 UTC / 1645604629 12:23:49UTC）
import sys, struct, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
# 2022-02-23 12:23:49 的候选 UTC 时间戳
cands = {
    1645575829: "04:23:49UTC",
    1645604629: "12:23:49UTC",
    1645593829: "09:23:49UTC(猜测)",
}
for blk in range(5928300, 5928700):
    dd = x.read(blk*4096, 4096)
    for ts, label in cands.items():
        b = struct.pack("<i", ts)
        i = dd.find(b)
        if i >= 0:
            print(f"blk {blk} off {i}: 找到 {ts} ({label})", flush=True)
print("done", flush=True)
