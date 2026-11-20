# -*- coding: utf-8 -*-
"""综合冒烟：挂载/分区/浏览/读/提取/雕刻/检索/哈希/证据 全链路（FAT 样本）。"""
import sys, os, json, tempfile
sys.path.insert(0, r'D:\MemLens')
from memlens.formats.mount import ImageMount
from memlens.core.fulltext import search_region
from memlens.core.evidence import EvidenceStore
from memlens.core.hashing import hash_file

IMG = r'D:\Cavescope\样本\交付-测试样本\deleted-files-01\deleted-files-01.img'
ok = True
def chk(name, cond, detail=''):
    global ok
    print(('  ✓ ' if cond else '  ✗ ') + name + (f'  {detail}' if detail else ''))
    if not cond: ok = False

print('== ① 挂载 ==')
m = ImageMount.open(IMG)
chk('识别卷', m.volumes and m.volumes[0].fs_type.lower() == 'fat', m.volumes[0].fs_type if m.volumes else '')
v = m.volumes[0]
tree = v.tree()
chk('文件树', any(t['path'] == 'README.TXT' for t in tree), f'{len(tree)} 项')
chk('已删除标记', any(t['deleted'] and 'JPG' in t['path'] for t in tree))

print('== ② 读/提取 ==')
data = v.read('README.TXT')
chk('读文件', b'deleted-files-01' in data)
dst = os.path.join(tempfile.gettempdir(), 'ml_extract_readme.txt')
v.extract('README.TXT', dst)
chk('提取', os.path.exists(dst))

print('== ③ 雕刻 ==')
hits = v.carve()
chk('雕刻 3 JPEG', len(hits) == 3 and all(h['rule'] == 'jpeg' for h in hits), f'{len(hits)} 个')

print('== ④ 跨编码检索 ==')
rhits = search_region(v._abs_read, v.offset, v.size, 'deleted-files-01')
chk('检索命中', len(rhits) >= 1 and rhits[0]['offset'] > 0, f'{len(rhits)} 个 @{rhits[0]["offset"] if rhits else "-"}')

print('== ⑤ 哈希（SHA256 匹配 CarveScope）==')
h = hash_file(IMG)
chk('SHA256', h['sha256'] == 'dab40bc2e51cc5b31202fcbc97924924e2474be7f2d47fa7948afaa2d6661339', h['sha256'][:16])
chk('SM3 存在', 'sm3' in h)

print('== ⑥ 证据/保管链 ==')
es = EvidenceStore(os.path.join(tempfile.gettempdir(), 'ml_evidence_test.json'))
es.add(IMG, kind='raw', note='smoke')
es.add(IMG, kind='raw', note='smoke2')
okv, info = es.verify()
chk('保管链完整', okv, str(info))

print('\n== 结果 ==', 'PASS' if ok else 'FAIL')
