# -*- coding: utf-8 -*-
"""㉓ 根 LV 定向内容扫描：定位关键文件内容（后台跑，4 GiB）。"""
import sys, time
sys.path.insert(0, r"D:\MemLens")
sys.path.insert(0, r"D:\MemLens\work")
from _vh import open_vmdk

BS = 4096
vol, fs, ent, r, vd = open_vmdk()
P2 = 2099200 * 512
PE = 8192
LV = P2 + (2048 + 992 * PE) * 512

KEYS = [
    b"#!/", b"python", b"libxml2",
    b"trojan", b"trojan-1.16.0", b"/etc/trojan",
    b"config.json", b"REMOTE_ADDR", b"REMOTE_PORT", b"8888",
    b"AndroRAT", b"androrat", b"androRAT",
    b"ratlog", b"sfz.jpg", b"sfz",
    b"bash_history", b".bash_hist",
    b"passwd", b"shadow",
    b"neo4j", b"libcrack", b"mysqld", b"-uroot",
    b"root:", b"0:0:", b"1000:",
    b"run_type", b"local_addr", b"remote_addr", b"front_domain",
    b"bt-panel", b"panel.py", b"panel_version",
    b"qianqianwoaini", "刘晓倩".encode(), "倩倩".encode(), "起早王".encode(),
    b"310104", b"win10ue", b"bsod.html", b"fakeupdate",
]
SCAN = 4 << 30
CH = 32 << 20
prev = b""
hits = {k: [] for k in KEYS}
base = 0
t0 = time.time()
while base < SCAN:
    n = min(CH, SCAN - base)
    data = vd.read_at(LV + base - len(prev), len(prev) + n)
    lo = data.lower()
    off0 = base - len(prev)
    for k in KEYS:
        kl = k.lower()
        st = 0
        while len(hits[k]) < 6:
            i = lo.find(kl, st)
            if i < 0:
                break
            hits[k].append(off0 + i)
            st = i + max(1, len(kl))
    prev = data[-512:]
    base += n
    el = time.time() - t0
    nhit = sum(len(v) for v in hits.values())
    print(f"  {base*100//SCAN:3d}%  {base>>30} GiB  命中{nhit}  "
          f"{base/1024/1024/max(el,.001):5.1f} MB/s", flush=True)

print("\n=== 命中汇总 ===")
for k, v in hits.items():
    if v:
        print(f"  {k.decode('utf-8','replace')!r}: {len(v)} 处 {[hex(x) for x in v[:4]]}")
import json
json.dump({k.decode('utf-8','replace'): v for k, v in hits.items() if v},
          open(r"D:\MemLens\work\_lvm_hits.json", "w"))
vol.close()
