# -*- coding: utf-8 -*-
"""下载题目附件到工作区。"""
import json
import zipfile
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
WORK = Path(r"D:\MemLens\work\qsnctf")
TOKEN = (WORK / "token.txt").read_text().strip()
DL = Path(r"D:\MemLens\work\attachments")
DL.mkdir(parents=True, exist_ok=True)

s = requests.Session()
s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0",
                  "Authorization": "Bearer " + TOKEN})
s.get(BASE + "/", timeout=30)

items = json.loads((WORK / "with_files.json").read_text(encoding="utf-8"))

# 下载目标：512(可疑DLL) + 1028(流量包)；554/613 是说明 PDF，价值低
WANT = [512, 1028]

for it in items:
    if it["id"] not in WANT:
        continue
    for f in it.get("file_list") or []:
        name = f.get("file_name")
        url = f.get("file_url")
        print(f"=== [{it['id']}] {it['question']} → {name}")
        print(f"    {url}")
        try:
            r = s.get(url, timeout=300, stream=True)
            if r.status_code != 200:
                print(f"    下载失败 HTTP {r.status_code}")
                continue
            dest = DL / f"{it['id']}_{name}"
            with open(dest, "wb") as fp:
                for chunk in r.iter_content(1 << 20):
                    fp.write(chunk)
            print(f"    已存 {dest}  ({dest.stat().st_size:,} bytes)")

            if dest.suffix.lower() == ".zip":
                ex = DL / f"{it['id']}_{dest.stem}"
                ex.mkdir(exist_ok=True)
                try:
                    with zipfile.ZipFile(dest) as z:
                        names = z.namelist()
                        print(f"    解压 {len(names)} 项 → {ex}")
                        z.extractall(ex)
                        for n in names[:40]:
                            zi = z.getinfo(n)
                            print(f"       {zi.file_size:>12,}  {n}")
                        if len(names) > 40:
                            print(f"       … 其余 {len(names)-40} 项")
                except zipfile.BadZipFile as e:
                    print(f"    解压失败(可能加密): {e}")
                except Exception as e:
                    print(f"    解压异常: {e}")
        except Exception as e:
            print(f"    下载异常: {e}")
        print()

print("下载目录:", DL)
