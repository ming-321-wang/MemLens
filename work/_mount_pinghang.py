# -*- coding: utf-8 -*-
import sys, time
sys.path.insert(0, r'D:\MemLens')
from memlens.formats.mount import ImageMount

IMG = r'E:\2025平航杯\平航杯题目'
PW = '早起王的爱恋日记\u2764'
t0 = time.time()
m = ImageMount.open(IMG, PW)
print(f'open ok in {time.time()-t0:.1f}s')
print('kind:', m.kind, 'size:', m.size)
for v in m.volumes:
    print('--- vol', v.index, 'fs=', v.fs_type, 'kind=', v.kind, 'offset=', v.offset, 'note=', v.note)
    print('   summary:', v.summary())
print('notes:', m.notes)
