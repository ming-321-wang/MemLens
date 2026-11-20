# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, r'D:\MemLens')
from memlens.formats.fat import FAT

data = open(r'D:\Cavescope\样本\交付-测试样本\deleted-files-01\deleted-files-01.img', 'rb').read()

class R:
    def read(self, off, n):
        return data[off:off+n]

f = FAT(R(), 0)
print('summary:', f.summary())
print('--- tree ---')
for e in f.tree():
    print(('  ' if e.is_dir else '   '), e.path, 'dir' if e.is_dir else f'size={e.size}', 'DEL' if e.is_deleted else '')
