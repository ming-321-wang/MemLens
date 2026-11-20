# -*- coding: utf-8 -*-
"""列出候选仓库的文件树，找实际镜像文件。"""
import requests

REPOS = [
    ("BashiruDamoah/MEMORY-FORENSICS-INVESTIGATION-OF-AN-AGENT-TESLA-MALWARE-INFECTION-USING-VOLATILITY-3", "Agent Tesla"),
    ("dfrws/dfrws2009-challenge", "DFRWS 2009"),
    ("the404packet/darkcomet", "DarkComet 1.95GB"),
    ("Gurleen-Brar/ComputerForensics-CTFs", "CTF writeups"),
]

for repo, tag in REPOS:
    print("=" * 72)
    print(f"# {repo}   [{tag}]")
    print("=" * 72)
    try:
        m = requests.get(f"https://api.github.com/repos/{repo}", timeout=25).json()
        br = m.get("default_branch") or "master"
        size = m.get("size", 0)
        print(f"  体积 {size:,} KB  分支 {br}  {(m.get('description') or '')[:70]}")
        r = requests.get(
            f"https://api.github.com/repos/{repo}/git/trees/{br}?recursive=1",
            timeout=45)
        if r.status_code != 200:
            print(f"  tree HTTP {r.status_code}")
            continue
        tree = r.json().get("tree", [])
        blobs = [t for t in tree if t.get("type") == "blob"]
        print(f"  文件 {len(blobs)} 个")
        # 大文件 Top 15（镜像通常是大文件）
        big = sorted(blobs, key=lambda t: -t.get("size", 0))[:15]
        print("  --- 体积 Top 15 ---")
        for t in big:
            print(f"    {t.get('size',0):>13,}  {t['path']}")
        # 镜像后缀
        imgs = [t for t in blobs if t["path"].lower().endswith(
            (".raw", ".mem", ".vmem", ".dmp", ".img", ".core", ".lime", ".bin",
             ".zip", ".7z", ".gz", ".001"))]
        if imgs:
            print("  --- 镜像/压缩包 ---")
            for t in imgs[:20]:
                print(f"    {t.get('size',0):>13,}  {t['path']}")
    except Exception as e:
        print(f"  异常 {e}")
    print()
