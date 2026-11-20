# -*- coding: utf-8 -*-
import sys
from pathlib import Path
ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))
print("sys.version:", sys.version.split()[0])
try:
    from memlens.detectors.base import all_detectors, _REGISTRY
    print("注册表:", sorted(_REGISTRY))
    dets = all_detectors()
    print("all_detectors():")
    for d in dets:
        print(f"  {d.name:<24} needs={d.needs}")
except Exception as e:
    import traceback; traceback.print_exc()

print("\n--- 单独 import static_pe ---")
try:
    from memlens.detectors import static_pe
    print("OK", static_pe.__file__)
except Exception:
    import traceback; traceback.print_exc()
