# -*- coding: utf-8 -*-
import json, urllib.request, urllib.error

BASE = 'http://127.0.0.1:8766'

# 1) 前端页面含挂载面板？
html = urllib.request.urlopen(BASE + '/', timeout=20).read().decode('utf-8')
print('index has panel-mount:', 'panel-mount' in html)
print('index has mount tab:', 'data-tab="mount"' in html)
js = urllib.request.urlopen(BASE + '/static/app.js', timeout=20).read().decode('utf-8')
print('app.js has mountOpen:', 'function mountOpen' in js)
nav = urllib.request.urlopen(BASE + '/static/nav.js', timeout=20).read().decode('utf-8')
print('nav.js has 镜像挂载:', '镜像挂载' in nav)

# 2) 平航杯挂载（VeraCrypt → exFAT + XFS）
def post(path, payload):
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode('utf-8'),
                                 headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.status, json.loads(r.read().decode('utf-8'))

st, d = post('/api/mount/open', {'path': r'E:\2025平航杯\平航杯题目', 'password': '早起王的爱恋日记\u2764'})
print('\n平航杯 open:', st, 'kind=', d.get('kind'))
for v in d.get('volumes', []):
    print('   vol', v.get('index'), v.get('fs'), 'kind=', v.get('kind'), 'offset=', v.get('offset'))
print('   notes:', d.get('notes'))
