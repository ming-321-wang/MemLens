# -*- coding: utf-8 -*-
"""GitHub 搜索：找含真实内存镜像文件的仓库。"""
import json
from pathlib import Path

import requests

HDR = {"Accept": "application/vnd.github+json"}
OUT = Path(r"D:\MemLens\work/attachments/scan_web")
OUT.mkdir(parents=True, exist_ok=True)

queries = [
    "memory dump forensics sample",
    "volatility memory image raw",
    "memory forensics challenge image",
    "ctf memory image raw",
]

hits = []
for q in queries:
    print("=" * 70)
    print(f"# 搜索: {q}")
    print("=" * 70)
    try:
        r = requests.get("https://api.github.com/search/repositories",
                         params={"q": q, "per_page": 15, "sort": "updated"},
                         headers=HDR, timeout=30)
        if r.status_code != 200:
            print(f"  HTTP {r.status_code} {r.text[:150]}")
            continue
        items = r.json().get("items", [])
        print(f"  命中 {len(items)} 仓库")
        for it in items:
            full = it["full_name"]
            desc = (it.get("description") or "")[:80]
            print(f"    {full:<46} {it.get('size'):>7} KB  {desc}")
    except Exception as e:
        print(f"  异常 {e}")
    print()

# 直接探测几个已知可能的镜像文件名/仓库
CANDIDATES = [
    ("https://github.com/volatilityfoundation/memory-samples", "volatility 官方样本库"),
    ("https://github.com/stuxnet147/Memory-Forensics-Samples", "社区样本"),
    ("https://github.com/Abyss-W4tcher/volatility3-memory-samples", "vol3 样本"),
]
for url, desc in CANDIDATES:
    repo = "/".join(url.rstrip("/").split("/")[-2:])
    try:
        r = requests.get(f"https://api.github.com/repos/{repo}", timeout=20)
        if r.status_code == 200:
            j = r.json()
            print(f"{repo:<44} ✅ {j.get('size'):>8} KB  {desc}  {(j.get('description') or '')[:60]}")
    except Exception:
        pass
