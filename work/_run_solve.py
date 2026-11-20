# -*- coding: utf-8 -*-
# 打印 solve_server_fs 全部解析结果明细（走缓存）
import sys, json, datetime
sys.path.insert(0, r"D:\MemLens")
from memlens.formats.xfs import open_server_fs
from memlens.core import server_forensics as sf

CACHE = r"D:\MemLens\work\server_solve_hits.json"
x, meta = open_server_fs(r"E:\2025平航杯\平航杯题目", "早起王的爱恋日记\u2764")
res = sf.solve_server_fs(x, password="sbwyz1", hits_cache=CACHE, rescan=False)

for name, v in res.items():
    print("\n" + "=" * 12, name, "=" * 12, flush=True)
    if isinstance(v, dict):
        print(json.dumps({k: vv for k, vv in v.items() if k != "boots"},
                         ensure_ascii=False, indent=2, default=str), flush=True)
        for b in v.get("boots", []):
            print(f"  boot {b.get('boot_str')}  kernel={b.get('kernel')}  blk={b.get('blk')}", flush=True)
        continue
    for it in v:
        print(f"--- blk {it['blk']} off {it['off']}", flush=True)
        print(json.dumps(it["result"], ensure_ascii=False, indent=2, default=str)[:900], flush=True)
