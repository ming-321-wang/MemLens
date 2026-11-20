# -*- coding: utf-8 -*-
import re, json
t = open(r'D:\MemLens\work\extracted\dump.sql', 'rb').read().decode('utf-8', 'replace')
print("有 tp_config 表?", "tp_config" in t)
m = re.search(r"CREATE TABLE\s*`?tp_config`?\s*\((.*?)\)\s*ENGINE", t, re.I | re.S)
print("有 CREATE TABLE tp_config?", bool(m))
if m:
    print("列定义首行:", m.group(1).strip().split("\n")[0][:200])
# INSERT 样例
i = t.find("INSERT INTO `tp_config`")
print("首个 INSERT:", repr(t[i:i+260]) if i>=0 else "无")
# 找 freight_free
for mm in re.finditer(r"freight_free", t):
    print("freight_free 上下文:", repr(t[mm.start()-80:mm.start()+60]))
