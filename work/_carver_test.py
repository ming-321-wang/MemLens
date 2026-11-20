# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, r'D:\MemLens')
from memlens.core.carver import carve_bytes, formats
d = open(r'D:\Cavescope\样本\交付-测试样本\deleted-files-01\deleted-files-01.img', 'rb').read()
hits = carve_bytes(d)
print('formats:', len(formats()))
for h in hits:
    print(f'{h.rule:10s} start={h.start} end={h.end} size={h.size} note={h.note}')
