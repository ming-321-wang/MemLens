# -*- coding: utf-8 -*-
"""用 vol3 的 quick 渲染器直接看 banners 输出（不要在 jsonl 里找）。"""
import subprocess
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
PY = str(ROOT / ".venv" / "Scripts" / "python.exe")
ENTRY = str(ROOT / "memlens" / "engines" / "_vol3_entry.py")
IMG = r"E:\附件原件\solar应急响应\solarsec_202603\03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5"

for plugin in ("banners", "linux.pslist.Banners" if False else "banners"):
    argv = [PY, ENTRY, "-f", IMG, "-r", "quick", plugin]
    print(f"=== vol3 -r quick {plugin} ===")
    try:
        p = subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace",
                           timeout=180, cwd=str(ROOT))
        print("rc =", p.returncode)
        print("--- stdout ---")
        print((p.stdout or "")[:2500])
    except subprocess.TimeoutExpired:
        print("超时")
    print()

# 也试 linux.pslist（若真是 Linux 内存）
for plugin in ("linux.pslist", "linux.bash"):
    argv = [PY, ENTRY, "-f", IMG, "-r", "quick", plugin]
    print(f"=== vol3 -r quick {plugin} ===")
    try:
        p = subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace",
                           timeout=120, cwd=str(ROOT))
        print("rc =", p.returncode)
        print((p.stdout or "")[:1500])
    except subprocess.TimeoutExpired:
        print("超时")
    print()
