# -*- coding: utf-8 -*-
# 定位 boot 记录：全盘搜 2022-02-23 12:23:49（本地）时间戳并就地校验 utmp 记录
import sys, struct, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

want = 1645573429                       # 2022-02-23 04:23:49 UTC = 本地 12:23:49
pat = struct.pack("<i", want)
print("搜索 ts", want, "=", datetime.datetime.fromtimestamp(want), flush=True)

base_lo, base_hi = 5900000 * 4096, 5940000 * 4096
step = 512 << 20
hits = []
off = base_lo
while off < base_hi:
    n = min(step, base_hi - off)
    d = x.read(off, n)
    i = d.find(pat)
    while i >= 0:
        rec_off = off + i - 340          # 记录起点 = 时间戳位置 - 340
        r = x.read(rec_off, 384)
        if len(r) >= 384 and struct.unpack_from("<h", r, 0)[0] == 2 \
                and r[44:44 + 6] == b"reboot":
            hits.append(rec_off)
        i = d.find(pat, i + 1)
    off += n

print("命中记录数:", len(hits), flush=True)
for ro in hits[:20]:
    r = x.read(ro, 384)
    tv = struct.unpack_from("<i", r, 340)[0]
    print(f"  off {ro} blk {ro//4096} tv={tv} {datetime.datetime.fromtimestamp(tv)}", flush=True)
