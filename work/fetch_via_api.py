# -*- coding: utf-8 -*-
"""用 GitHub Contents/Blob API 下载文件（raw/codeload 域名被断时的替代路径）。"""
import base64
import bz2
import io
import json
import zipfile
from pathlib import Path

import requests

OUT = Path(r"D:\MemLens\work/attachments/web_samples")
OUT.mkdir(parents=True, exist_ok=True)
API = "https://api.github.com"


def tree_blobs(owner, repo, br):
    r = requests.get(f"{API}/repos/{owner}/{repo}/git/trees/{br}?recursive=1",
                     timeout=60)
    if r.status_code != 200:
        print(f"  tree HTTP {r.status_code}: {r.text[:120]}")
        return {}
    return {t["path"]: (t.get("sha"), t.get("size", 0))
            for t in r.json().get("tree", []) if t.get("type") == "blob"}


def fetch_blob(owner, repo, sha, size):
    r = requests.get(f"{API}/repos/{owner}/{repo}/git/blobs/{sha}", timeout=300)
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}"
    j = r.json()
    if j.get("truncated"):
        return None, f"内容被截断（size={size}）"
    try:
        return base64.b64decode(j["content"]), None
    except Exception as e:
        return None, f"base64 解码失败 {e}"


JOBS = [
    ("BashiruDamoah",
     "MEMORY-FORENSICS-INVESTIGATION-OF-AN-AGENT-TESLA-MALWARE-INFECTION-USING-VOLATILITY-3",
     "main", "agent_tesla",
     ["Agent Tesla.zip", "ioc/iocs.txt", "string/memory_strings.txt",
      "commands/volatility_commands.txt", "README.md"]),
    ("dfrws", "dfrws2009-challenge", "main", "dfrws2009",
     ["materials/nssal-thumb-fs.dd.bz2", "materials/README.md"]),
]

for owner, repo, br, tag, want in JOBS:
    print("=" * 74)
    print(f"# {owner}/{repo}")
    print("=" * 74)
    blobs = tree_blobs(owner, repo, br)
    if not blobs:
        continue
    print(f"  仓库共 {len(blobs)} 文件")
    dest_dir = OUT / tag
    dest_dir.mkdir(parents=True, exist_ok=True)
    for w in want:
        if w not in blobs:
            # 尝试忽略大小写/路径差异
            cand = [p for p in blobs if p.lower() == w.lower()]
            if not cand:
                print(f"  ✗ 未找到 {w}")
                continue
            w = cand[0]
        sha, size = blobs[w]
        dest = dest_dir / Path(w).name
        print(f"  ↓ {w}  ({size:,} B)")
        data, err = fetch_blob(owner, repo, sha, size)
        if err:
            print(f"    失败: {err}")
            continue
        dest.write_bytes(data)
        print(f"    已存 {dest}  ({len(data):,} B)")

        # bz2 自动解
        if dest.suffix == ".bz2":
            try:
                raw = bz2.decompress(data)
                out2 = dest.with_suffix("")
                out2.write_bytes(raw)
                print(f"    解压 → {out2.name}  ({len(raw):,} B)")
                print(f"    头 16B: {raw[:16].hex(' ')}")
            except Exception as e:
                print(f"    解压失败: {e}")
        if dest.suffix == ".zip":
            ex = dest_dir / (dest.stem + "_extracted")
            ex.mkdir(exist_ok=True)
            try:
                with zipfile.ZipFile(dest) as z:
                    for n in z.namelist():
                        print(f"      {z.getinfo(n).file_size:>10,}  {n}")
                    z.extractall(ex)
            except Exception as e:
                print(f"     解压失败: {e}")
    print()
