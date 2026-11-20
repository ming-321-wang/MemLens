# -*- coding: utf-8 -*-
"""用 codeload 下载整仓库 tarball（raw 域名被重置时的替代）。"""
import tarfile
from pathlib import Path

import requests

OUT = Path(r"D:\MemLens\work/attachments/web_samples")
OUT.mkdir(parents=True, exist_ok=True)

REPOS = [
    ("BashiruDamoah",
     "MEMORY-FORENSICS-INVESTIGATION-OF-AN-AGENT-TESLA-MALWARE-INFECTION-USING-VOLATILITY-3",
     "main", "agent_tesla"),
    ("dfrws", "dfrws2009-challenge", "main", "dfrws2009"),
]

for owner, repo, br, tag in REPOS:
    dest = OUT / f"{tag}.tar.gz"
    print("=" * 70)
    print(f"# {owner}/{repo}")
    print("=" * 70)
    url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{br}"
    print(f"    {url}")
    try:
        r = requests.get(url, timeout=600, stream=True)
        print(f"    HTTP {r.status_code}")
        if r.status_code != 200:
            print("    失败")
            continue
        with open(dest, "wb") as fp:
            got = 0
            for chunk in r.iter_content(1 << 20):
                fp.write(chunk)
                got += len(chunk)
        print(f"    已存 {dest} ({got:,} B)")
        ex = OUT / tag
        ex.mkdir(exist_ok=True)
        with tarfile.open(dest, "r:gz") as t:
            members = t.getmembers()
            print(f"    解压 {len(members)} 项")
            t.extractall(ex, filter="data")
        # 列出内容
        for p in sorted(ex.rglob("*")):
            if p.is_file() and p.stat().st_size > 1000:
                print(f"      {p.stat().st_size:>12,}  {p.relative_to(ex)}")
    except Exception as e:
        print(f"    异常 {type(e).__name__}: {e}")
    print()
