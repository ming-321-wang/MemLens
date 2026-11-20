# -*- coding: utf-8 -*-
import json, urllib.request, urllib.error
BASE = 'http://127.0.0.1:8766'

def post(path, payload):
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode('utf-8'),
                                 headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.status, json.loads(r.read().decode('utf-8'))
def get(path):
    with urllib.request.urlopen(BASE + path, timeout=120) as r:
        return r.status, json.loads(r.read().decode('utf-8'))

# open FAT
st, d = post('/api/mount/open', {'path': r'D:\Cavescope\样本\交付-测试样本\deleted-files-01\deleted-files-01.img'})
mid = d['id']
# search
st, d = get(f'/api/mount/{mid}/search?vol=1&keyword=deleted-files-01&limit=5')
print('search:', st, 'count=', d.get('count'), '->', d['hits'][0]['offset'] if d['hits'] else None, d['hits'][0]['enc'] if d['hits'] else '')
# evidence via api
st, d = post('/api/evidence', {'path': r'D:\Cavescope\样本\交付-测试样本\deleted-files-01\deleted-files-01.img', 'note': 'api-test'})
print('evidence add:', st, 'id=', d.get('id'), 'sha256=', (d.get('hashes') or {}).get('sha256', '')[:16])
st, d = get('/api/evidence')
print('evidence list:', st, 'n=', len(d.get('records', [])))
st, d = get('/api/evidence/verify')
print('evidence verify:', st, 'ok=', d.get('ok'), d.get('info'))
