# -*- coding: utf-8 -*-
"""探测 GitHub 上公开的内存镜像样本仓库，找可下载链接。"""
import json
from pathlib import Path

import requests

OUT = Path(r"D:\MemLens\work\attachments/scan_web")
OUT.mkdir(parents=True, exist_ok=True)

REPOS = [
    "volatilityfoundation/memory-samples",
    "Divinemonk/memory_forensics_with_volatility",
]

for repo in REPOS:
    print("=" * 70)
    print(f"# {repo}")
    print("=" * 70)
    try:
        r = requests.get(f"https://api.github.com/repos/{repo}", timeout=25)
        if r.status_code != 200:
            print(f"  repo meta → {r.status_code}")
            continue
        m = r.json()
        print(f"  描述: {m.get('description')}")
        print(f"  大小: {m.get('size')} KB   默认分支: {m.get('default_branch')}")
    except Exception as e:
        print(f"  repo meta 异常 {e}")
        continue

    br = m.get("default_branch") or "master"
    try:
        r = requests.get(
            f"https://api.github.com/repos/{repo}/git/trees/{br}?recursive=1",
            timeout=40)
        if r.status_code != 200:
            print(f"  tree → {r.status_code}")
            continue
        tree = r.json().get("tree", [])
        print(f"  条目 {len(tree)}")
        files = [t for t in tree if t.get("type") == "blob"]
        # 找镜像与压缩包
        interesting = [t for t in files
                       if t["path"].lower().endswith(
                           (".raw", ".mem", ".vmem", ".dmp", ".zip", ".gz",
                            ".7z", ".img", ".bin", ".core", ".lime"))
                       or "image" in t["path"].lower()]
        print(f"  可能是镜像/压缩包的条目 {len(interesting)}")
        for t in interesting[:40]:
            sz = t.get("size", 0)
            print(f"    {sz:>12,}  {t['path']}")
    except Exception as e:
        print(f"  tree 异常 {e}")
    print()
