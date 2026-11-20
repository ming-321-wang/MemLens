# -*- coding: utf-8 -*-
"""核对主镜像的真实格式：看头字节 + 让 vol3 banners 判定（多源交叉验证）。"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
PY = str(ROOT / ".venv" / "Scripts" / "python.exe")
IMG = r"E:\附件原件\solar应急响应\solarsec_202603\03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5"

head = Path(IMG).read_bytes()[:64]
print("头 64 字节:", head.hex(" "))
print("前 16 字节 ascii:", repr(head[:16]))
print("ELF magic?", head[:4] == b"\x7fELF")

# vol3 banners（权威判定）
argv = [PY, str(ROOT / "memlens" / "engines" / "_vol3_entry.py"), "-f", IMG, "-r", "jsonl", "banners"]
print("\n=== vol3 banners ===")
try:
    p = subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace",
                       timeout=180, cwd=str(ROOT))
    print("rc =", p.returncode)
    out = (p.stdout or "").strip()
    err = (p.stderr or "").strip()
    if out:
        print("stdout 前 1200:")
        print(out[:1200])
    if err:
        print("stderr 末 600:")
        print(err[-600:])
except subprocess.TimeoutExpired:
    print("banners 超时")

# vol3 windows.info / linux.info 也要试？先看 banners。
