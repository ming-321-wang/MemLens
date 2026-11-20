# -*- coding: utf-8 -*-
# 全盘扫 ut_type=2 记录，tv_sec@332（标准）有效 + host 含 kernel
import sys, struct, datetime, time
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)
END = 11827200 * x.bs
CHUNK = 32 << 20
found=[]
t0=time.time(); pos=0
while pos < END:
    n = min(CHUNK, END-pos)
    d = x.read(pos, n)
    # 在块内 384 对齐找 ut_type=2
    for off in range(0, n-384, 384):
        if d[off:off+2] == b"\x02\x00":
            r = d[off:off+384]
            tv = struct.unpack_from("<i", r, 332)[0]
            if 0 < tv < 4_000_000_000:
                host = r[76:76+256].split(b"\x00")[0]
                if b"3.10" in host or b"el7" in host:
                    found.append((pos+off, tv, host.decode("utf-8","replace")))
    pos += n
    if pos % (8<<30) < CHUNK:
        print(f"  scanned {pos/1e9:.1f}GB in {time.time()-t0:.0f}s found={len(found)}", flush=True)
found.sort(key=lambda f: f[1])
print(f"=== done {len(found)} ===", flush=True)
for off, tv, host in found[:15]:
    print(f"  off {off} blk {off//4096}: {datetime.datetime.fromtimestamp(tv)} host={host}", flush=True)
