# -*- coding: utf-8 -*-
# 搜索 access.log webshell 上传 + 真实 passwd + wtmp + freight_free 值
import sys, struct, re, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs

IMG = r"E:\2025平航杯\平航杯题目"
PW = "早起王的爱恋日记\u2764"
x, meta = open_server_fs(IMG, PW)

# 1) access.log webshell：读 access.log 区域（blk 3256475 附近 ±4MB）
print("[题12] access.log webshell 搜索")
for base, span in ((13338522614 - 4<<20, 8<<20),):
    d = x.read(base, span)
    for pat in (b"file_put_contents", b"peiqi", b"@eval", b"write"):
        for m in re.finditer(re.escape(pat), d):
            s = max(0, m.start()-120); e = m.start()+160
            ctx = d[s:e]
            if b"222.2.2.2" in ctx or b"peiqi" in ctx or b"eval" in ctx or b"php" in ctx:
                print(f"  @{(base+s)}: {ctx!r}")
                break

# 2) 真实 passwd：搜 www:x:1000 / mysql:x:1001（全 XFS，可能慢——先扫描已知数据区）
print("\n[题3] 真实 passwd 搜索（www:x:1000 / mysql:x:1001）")
import time
found = {}
t0=time.time(); pos=0; CH=32<<20
while pos < 14<<30:
    d = x.read(pos, min(CH, (14<<30)-pos))
    for pat in (b"www:x:1000", b"mysql:x:1001", b"freight_free"):
        idx = d.find(pat)
        while idx >= 0:
            abs_off = pos+idx
            found.setdefault(pat.decode(), []).append((abs_off, d[max(0,idx-80):idx+120]))
            idx = d.find(pat, idx+1)
    pos += CH
    if pos % (2<<30) < CH:
        print(f"  ...{pos/1e9:.1f}GB {time.time()-t0:.0f}s", flush=True)
for k, v in found.items():
    print(f"[{k}] {len(v)} hits")
    for off, ctx in v[:3]:
        print(f"  off {off} blk {off//4096}: {ctx!r}")
