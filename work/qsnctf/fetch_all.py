# -*- coding: utf-8 -*-
"""下载所有内存/取证/应急相关题的 zip 附件，解压后统计内容（找内存镜像）。"""
import json
import re
import zipfile
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
WORK = Path(r"D:\MemLens\work\qsnctf")
DL = Path(r"D:\MemLens\work\attachments/scan")
DL.mkdir(parents=True, exist_ok=True)

items = json.loads((WORK / "all_challenges.json").read_text(encoding="utf-8"))

KW = ("内存", "memory", "dump", "镜像", "volatil", "memproc", "取证", "应急",
      "勒索", "webshell", "入侵", "木马", "后门", "安全事件", "样本", "恶意")


def is_irish(it):
    text = f"{it.get('question','')} {it.get('description','')}".lower()
    tags = " ".join(t["name"] for t in (it.get("tag") or []))
    return any(k.lower() in text or k.lower() in tags.lower() for k in KW)


cands = [it for it in items if is_irish(it) and (it.get("file_list") or [])]
print(f"相关且有附件的题：{len(cands)}")

s = requests.Session()
s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0"})

found_images = []
downloaded = 0
for it in cands:
    qid = it["id"]
    for f in (it.get("file_list") or []):
        name = f.get("file_name") or ""
        url = f.get("file_url")
        if not url:
            continue
        dest = DL / f"{qid}_{name}"
        if dest.exists():
            continue
        try:
            r = s.get(url, timeout=180, stream=True)
            if r.status_code != 200:
                print(f"  [{qid}] {name} → HTTP {r.status_code}")
                continue
            with open(dest, "wb") as fp:
                for chunk in r.iter_content(1 << 20):
                    fp.write(chunk)
            downloaded += 1
            if downloaded % 20 == 0:
                print(f"  ...已下载 {downloaded}")
        except Exception as e:
            print(f"  [{qid}] {name} 异常 {e}")

print(f"下载完成 {downloaded} 个文件")

# 解压并统计
MEM_SUFFIX = (".raw", ".mem", ".vmem", ".vmsn", ".sav", ".vmss", ".dmp", ".dump",
              ".dd", ".lime", ".core", ".hiber")
print("\n=== 解压 zip 并查找镜像 ===")
for z in sorted(DL.rglob("*.zip")):
    ex = z.with_suffix("")
    ex.mkdir(exist_ok=True)
    try:
        with zipfile.ZipFile(z) as zf:
            zf.extractall(ex)
    except Exception as e:
        print(f"  {z.name} 解压失败: {str(e)[:60]}")
        continue
    for p in ex.rglob("*"):
        if p.is_file():
            if p.suffix.lower() in MEM_SUFFIX:
                found_images.append((z.name, p.name, p.stat().st_size))
                print(f"  ★ 镜像: {z.name} → {p.name} ({p.stat().st_size:,} B)")

print(f"\n共找到 {len(found_images)} 个内存镜像")
for zn, pn, sz in found_images:
    print(f"  {sz:>14,}  {zn} :: {pn}")

# 也统计解压出的所有文件类型
from collections import Counter
c = Counter()
for ex in DL.iterdir():
    if ex.is_dir():
        for p in ex.rglob("*"):
            if p.is_file():
                c[p.suffix.lower() or "(无后缀)"] += 1
print("\n=== 解压后文件类型分布 ===")
for suf, n in c.most_common(40):
    print(f"  {suf:<24} {n}")

(WORK / "found_images.json").write_text(json.dumps(found_images, ensure_ascii=False, indent=1))
