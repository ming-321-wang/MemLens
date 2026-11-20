# -*- coding: utf-8 -*-
import sys, time
sys.path.insert(0, r'D:\MemLens')
from memlens.formats.mount import ImageMount

IMG = r'E:\2025平航杯\平航杯题目'
PW = '早起王的爱恋日记\u2764'
m = ImageMount.open(IMG, PW)
exfat_v, xfs_v = m.volumes[0], m.volumes[1]

# 1) exFAT 根目录（应含 VMDK）
print('=== exFAT root ===')
t0 = time.time()
for e in exfat_v.listdir('/'):
    print('  ', e.get('name'), 'dir' if e.get('is_dir') else f"{e.get('size')}B")
print(f'  ({time.time()-t0:.1f}s)')

# 2) XFS 读 /etc/passwd
print('=== XFS read /etc/passwd ===')
t0 = time.time()
try:
    d = xfs_v.read('etc/passwd')
    print(f'  got {len(d)} bytes in {time.time()-t0:.1f}s')
    print('  ', d[:120])
except Exception as exc:
    print('  read err:', exc)

# 3) XFS 读 /var/log/wtmp 头部（前 64B）
print('=== XFS read /var/log/wtmp head ===')
try:
    d = xfs_v.read('var/log/wtmp')
    print(f'  got {len(d)} bytes; head={d[:24].hex()}')
except Exception as exc:
    print('  read err:', exc)
