# -*- coding: utf-8 -*-
import re
t = open(r'D:\MemLens\work\extracted\dump.sql', 'rb').read().decode('utf-8', 'replace')
m = re.search(r"INSERT INTO `tp_order` VALUES (.*?);", t, re.S | re.I)
body = m.group(1)
# 取第一个元组
d = 0; i = body.index('('); start = None
cur = []
for j in range(i, len(body)):
    c = body[j]
    if c == '(':
        d += 1
        if d == 1:
            start = j + 1
        continue
    if c == ')':
        d -= 1
        if d == 0:
            cur = body[start:j]
            break
vals = re.findall(r"'(?:\\'|[^'])*'|(?:-?\d+(?:\.\d+)?)", cur)
vals = [v[1:-1] if v.startswith("'") else v for v in vals]
print("列数:", len(vals))
for k, v in enumerate(vals):
    print(f"{k:3d}: {v!r}")
