# -*- coding: utf-8 -*-
"""端到端：走引擎真实入口跑 container.xfs 插件（scan=1GiB）。"""
import sys, time
sys.path.insert(0, r"D:\MemLens")
from memlens.engines.container import ContainerEngine

eng = ContainerEngine(workdir=r"D:\MemLens\work")
plug = next(p for p in eng.list_plugins() if p.name == "container.xfs")
image = r"E:\2025平航杯\平航杯题目"
params = {"password": "早起王的爱恋日记❤", "lv": "root", "scan": "1"}
spec = eng.build_run(plug, image, params)
t0 = time.time()
n = 0
for rec in eng.parse_records(spec, "", ""):
    n += 1
    print(f"  {n:3d}. {rec.get('项目')}: {str(rec.get('值'))[:110]}  [{rec.get('说明','')[:50]}]", flush=True)
print(f"\n共 {n} 条记录，耗时 {time.time()-t0:.1f}s")
