# -*- coding: utf-8 -*-
# 重扫 utmp boot（ut_user @44, ut_type @0, tv_sec @338）
import sys, struct, re, time, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
END = 11827200 * x.bs
CHUNK = 32 << 20
boots = []
t0=time.time(); pos=0
while pos < END:
    n = min(CHUNK, END-pos)
    d = x.read(pos, n)
    idx = d.find(b"reboot\x00")
    while idx >= 0:
        for uoff in (44, 32):
            rec_start = idx - uoff
            if rec_start >= 0 and rec_start + 384 <= len(d):
                if struct.unpack_from("<h", d, rec_start)[0] == 2:
                    tv = struct.unpack_from("<i", d, rec_start + 338)[0]
                    if 0 < tv < 4_000_000_000:
                        boots.append((pos+rec_start, tv, uoff))
        idx = d.find(b"reboot\x00", idx+1)
    pos += n
    if pos % (8<<30) < CHUNK:
        print(f"  scanned {pos/1e9:.1f}GB in {time.time()-t0:.0f}s, boots={len(boots)}", flush=True)
print(f"=== done {len(boots)} ===", flush=True)
for off, tv, uoff in boots:
    print(f"  off {off} blk {off//4096} uoff={uoff}: {datetime.datetime.fromtimestamp(tv)}", flush=True)
