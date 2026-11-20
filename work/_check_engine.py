# -*- coding: utf-8 -*-
"""确认容器引擎加载 XFS 插件 + 跑一遍 container.xfs（真实检材）。"""
import sys
sys.path.insert(0, r"D:\MemLens")
from memlens.engines.container import ContainerEngine, ARTIFACT_PLUGINS

print("插件清单:")
for p in ARTIFACT_PLUGINS:
    print("  ", p.name, "|", p.category, "|", p.display)

eng = ContainerEngine()
ok, why = eng.available()
print("\navailable():", ok, why)
names = [p.name for p in eng.list_plugins()]
print("list_plugins:", [n for n in names if "xfs" in n or "vmdk" in n or "container" in n])
