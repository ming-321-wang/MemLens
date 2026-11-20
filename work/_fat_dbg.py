# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, r'D:\MemLens')
from memlens.formats.fat import FAT
data = open(r'D:\Cavescope\样本\交付-测试样本\deleted-files-01\deleted-files-01.img', 'rb').read()
class R:
    def read(self, off, n):
        return data[off:off+n]
f = FAT(R(), 0)
print('summary', f.summary())
for e in f.tree():
    if e.path == 'README.TXT':
        print('entry:', e.name, 'start_cluster=', e.start_cluster, 'size=', e.size)
        cl = e.start_cluster
        chain = []
        for _ in range(10):
            if cl < 2: break
            chain.append(cl)
            cl = f.next_cluster(cl)
        print('chain:', chain)
        print('data:', f.read_cluster_chain(e.start_cluster, max_bytes=e.size))
