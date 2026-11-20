# -*- coding: utf-8 -*-
# 列 wtmp 区域所有 boot 记录（ut_user=32 字节 "reboot"+26 零，ut_type@0==2）
import sys, struct, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

PAT = b"reboot" + b"\x00" * 26        # ut_user[32]
recs = []
base_lo, base_hi = 5900000 * 4096, 5940000 * 4096
off = base_lo
step = 512 << 20
while off < base_hi:
    n = min(step, base_hi - off)
    d = x.read(off, n)
    i = d.find(PAT)
    while i >= 0:
        rec_off = off + i - 44
        r = x.read(rec_off, 384)
        if len(r) >= 384 and struct.unpack_from("<h", r, 0)[0] == 2:
            tv = struct.unpack_from("<i", r, 340)[0]
            if 0 < tv < 4_000_000_000:
                recs.append((tv, rec_off))
        i = d.find(PAT, i + 1)
    off += n

recs.sort()
print("boot 记录数:", len(recs), flush=True)
for tv, ro in recs:
    r = x.read(ro, 384)
    host = r[76:76 + 256].split(b"\x00")[0].decode("utf-8", "replace")
    print(f"  tv={tv} {datetime.datetime.fromtimestamp(tv)}  blk={ro//4096}  host={host[:32]}", flush=True)
