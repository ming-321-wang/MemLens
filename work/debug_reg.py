# -*- coding: utf-8 -*-
"""调试 regression_lite 里 memfrag 段为何未执行。"""
from pathlib import Path

scan = Path(r"D:\MemLens\work\attachments/scan")
print("scan exists:", scan.exists())
mfrag = None
for ex in scan.iterdir():
    if not ex.is_dir():
        continue
    for p in ex.rglob("dumped_4053_[23d1000-253e000].bin"):
        mfrag = p
        break
print("found:", mfrag)
print("exists:", mfrag.exists() if mfrag else None)

# 现在看 regression_lite 是否真跑到这段
import subprocess
r = subprocess.run(
    [r"D:\MemLens\.venv\Scripts\python.exe", "-X", "utf8",
     r"D:\MemLens\tools\regression_lite.py"],
    capture_output=True, text=True, encoding="utf-8", cwd=r"D:\MemLens",
    timeout=900,
)
out = (r.stdout or "") + (r.stderr or "")
for line in out.splitlines():
    if "memfrag" in line.lower() or "真实样本" in line:
        print("OUT:", line[:140])
