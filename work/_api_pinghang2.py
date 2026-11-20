# -*- coding: utf-8 -*-
import json, urllib.request, urllib.error

BASE = 'http://127.0.0.1:8766'

def post(path, payload):
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode('utf-8'),
                                 headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.status, json.loads(r.read().decode('utf-8'))

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=120) as r:
        return r.status, json.loads(r.read().decode('utf-8'))

st, d = post('/api/mount/open', {'path': r'E:\2025平航杯\平航杯题目', 'password': '早起王的爱恋日记\u2764'})
mid = d['id']
# exFAT 卷树（应含 VMDK / BLE / window.e01 / zip）
st, d = get(f'/api/mount/{mid}/tree?vol=1&limit=30')
print('exFAT tree:', st, 'fs=', d.get('fs'), 'n=', len(d.get('tree', [])))
for t in d['tree'][:12]:
    print('   ', t['path'], 'dir' if t['dir'] else f"{t['size']}")
# XFS 卷树（限 40 项，合成 FS 走 inode 树可能慢/不可靠——只验证不崩）
import time
t0 = time.time()
st, d = get(f'/api/mount/{mid}/tree?vol=2&limit=40')
print(f'XFS tree: {st} fs={d.get("fs")} n={len(d.get("tree", []))} in {time.time()-t0:.1f}s')
for t in d['tree'][:8]:
    print('   ', t['path'])
