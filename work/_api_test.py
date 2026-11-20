# -*- coding: utf-8 -*-
import json, urllib.request, urllib.error

BASE = 'http://127.0.0.1:8766'

def post(path, payload):
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode('utf-8'),
                                 headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, r.read().decode('utf-8')

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=60) as r:
        return r.status, r.read().decode('utf-8')

# 1) open FAT sample
st, body = post('/api/mount/open', {'path': r'D:\Cavescope\样本\交付-测试样本\deleted-files-01\deleted-files-01.img', 'password': ''})
print('open:', st)
d = json.loads(body)
print('  id=', d.get('id'), 'kind=', d.get('kind'), 'vols=', len(d.get('volumes', [])))
mid = d['id']

# 2) tree
st, body = get(f'/api/mount/{mid}/tree?vol=1&limit=50')
d = json.loads(body)
print('tree:', st, 'fs=', d.get('fs'), 'n=', len(d.get('tree', [])))
for t in d['tree'][:8]:
    print('   ', t['path'], 'dir' if t['dir'] else t['size'], 'DEL' if t.get('deleted') else '')

# 3) read README.TXT
import urllib.request as ur
with ur.urlopen(f"{BASE}/api/mount/{mid}/read?vol=1&path=README.TXT", timeout=30) as r:
    data = r.read()
print('read README.TXT:', len(data), '->', data[:30])

# 4) carve
st, body = post(f'/api/mount/{mid}/carve', {'vol': 1, 'rules': ''})
d = json.loads(body)
print('carve:', st, 'count=', d.get('count'))
for h in d['hits']:
    print('   ', h['rule'], h['start'], h['size'], h['note'])

# 5) hash
st, body = post('/api/hash', {'path': r'D:\Cavescope\样本\交付-测试样本\deleted-files-01\deleted-files-01.img'})
d = json.loads(body)
print('hash:', st, 'sha256=', d.get('sha256'))
