# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, r'D:\MemLens')
from memlens.formats.mount import ImageMount

# 1) FAT16 样本
m = ImageMount.open(r'D:\Cavescope\样本\交付-测试样本\deleted-files-01\deleted-files-01.img')
print('kind:', m.kind, 'size:', m.size)
print('summary:', m.summary())
for v in m.volumes:
    print('--- volume', v.index, v.fs_type, 'kind=', v.kind, 'offset=', v.offset, 'size=', v.size)
    print('  summary:', v.summary())
    tree = v.tree()
    print('  tree entries:', len(tree))
    for t in tree[:20]:
        print('   ', t['path'], 'dir' if t['dir'] else f"{t['size']}", 'DEL' if t['deleted'] else '')
    if tree:
        p = next((t['path'] for t in tree if not t['dir'] and t['path'].endswith('.TXT')), None)
        if p:
            data = v.read(p)
            print('  read', p, '->', data[:60])
