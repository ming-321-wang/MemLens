# -*- coding: utf-8 -*-
import sys
from pathlib import Path
sys.path.insert(0, r"D:\MemLens")
from memlens.storage.db import DataStore

s = DataStore(r"D:\MemLens\work\memlens.db")
cs = [c for c in s.list_cases() if c["name"] == "memfrag实战2"]
if not cs:
    print("no case"); raise SystemExit
cid = cs[0]["case_id"]
print("=== Top 可读字符串（去重 + 兴趣加权后）===")
for r in s.records_of_plugin(cid, "%memfrag%", limit=40):
    if r.get("项") == "长字符串明细":
        print(f"  {r['偏移']} len={r['长度']:>5}  {r['内容'][:100]}")
print()
print("=== 全部 memfrag 记录 ===")
for r in s.records_of_plugin(cid, "%memfrag%", limit=40):
    d = {k: v for k, v in r.items() if k not in ("文件",)}
    if d.get("项") != "长字符串明细":
        print(" ", d)
s.close()
