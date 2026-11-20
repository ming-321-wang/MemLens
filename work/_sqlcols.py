# -*- coding: utf-8 -*-
import re, collections
t = open(r'D:\MemLens\work\extracted\dump.sql', 'rb').read().decode('utf-8', 'replace')
tabs = collections.Counter(re.findall(r'INSERT INTO\s+`?([A-Za-z0-9_]+)`?', t, re.I))
print("INSERT tables:", tabs.most_common())
ct = collections.Counter(re.findall(r'CREATE TABLE\s*`?([A-Za-z0-9_]+)`?', t, re.I))
print("CREATE TABLE :", ct.most_common())
# 用户表列名（若有）
for name in ("tp_users", "tp_user"):
    m = re.search(r'CREATE TABLE\s*`?' + name + r'`?\s*\((.*?)\)\s*ENGINE', t, re.I | re.S)
    if m:
        cols = [c.split("(")[0].strip().strip("`") for c in m.group(1).split(",")]
        print(f"{name} cols({len(cols)}):", cols[:40])
m = re.search(r'CREATE TABLE\s*`?tp_order`?\s*\((.*?)\)\s*ENGINE', t, re.I | re.S)
if m:
    cols = [c.split("(")[0].strip().strip("`") for c in m.group(1).split(",")]
    print("tp_order cols:", cols)
    print("add_time idx:", cols.index("add_time"), "user_id idx:", cols.index("user_id"))
print("size:", len(t))
