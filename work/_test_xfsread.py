# -*- coding: utf-8 -*-
"""测 container.xfs_read：按 inode 读文件（ino 72 = python 木马）。"""
import sys, time
sys.path.insert(0, r"D:\MemLens")
from memlens.engines.container import ContainerEngine

eng = ContainerEngine(workdir=r"D:\MemLens\work")
plug = next(p for p in eng.list_plugins() if p.name == "container.xfs_read")
image = r"E:\2025平航杯\平航杯题目"
params = {"ino": "72", "password": "早起王的爱恋日记❤", "lv": "root"}
spec = eng.build_run(plug, image, params)
t0 = time.time()
for rec in eng.parse_records(spec, "", ""):
    print(f"  {rec.get('项目')}: {str(rec.get('值'))[:80]}  [{rec.get('说明','')[:40]}]")
print(f"\n耗时 {time.time()-t0:.1f}s")
dst = r"D:\MemLens\work\extract\ino72.bin"
import os
if os.path.exists(dst):
    d = open(dst, "rb").read()
    print("已存", dst, len(d), "字节, 头:", d[:24])
