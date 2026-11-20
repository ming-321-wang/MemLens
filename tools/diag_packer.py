# -*- coding: utf-8 -*-
import sys
from pathlib import Path
ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))
from memlens.engines import static

print("PACKERS_SECTION_NAME =")
for k, v in static.PACKERS_SECTION_NAME.items():
    print(f"  {k!r}: {v!r}")
print("PACKERS_CONTENT =")
for k, v in static.PACKERS_CONTENT.items():
    print(f"  {k!r}: {v!r}")

p = r"C:\Windows\System32\notepad.exe"
data = Path(p).read_bytes()
print("\nnotepad 节名:")
prof = static.profile_file(p)
for s in (prof.pe.sections if prof.pe else []):
    print(f"  {s['name']!r} ent={s['entropy']}")

print("\n内容标记实测：")
for name, marks in static.PACKERS_CONTENT.items():
    for m in marks:
        idx = data.find(m)
        if idx >= 0:
            print(f"  命中 {name}: {m!r} @ 0x{idx:x}")
            print(f"    上下文: {data[max(0,idx-40):idx+60]!r}")
