# -*- coding: utf-8 -*-
"""列出题目：标题/描述/附件，筛出有附件的。"""
import json
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
WORK = Path(r"D:\MemLens\work\qsnctf")
TOKEN = (WORK / "token.txt").read_text().strip()
RACE_ID = 5
CAT = "27"

items = json.loads((WORK / f"challenges_cat{CAT}.json").read_text(encoding="utf-8"))

s = requests.Session()
s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0",
                  "Authorization": "Bearer " + TOKEN})
s.get(BASE + "/", timeout=30)

print(f"category={CAT} 共 {len(items)} 题\n")

with_files = []
for it in items:
    fl = it.get("file_list") or []
    q = it.get("question")
    desc = (it.get("description") or "").replace("\n", " ⏎ ")
    tag = ",".join(t.get("name", "") for t in (it.get("tag") or []))
    mark = "★" if fl else " "
    print(f"{mark} [{it['id']:>4}] {q:<28} 难度={it.get('difficulty')} "
          f"附件={len(fl)} 提交数={it.get('answer_count')} 标签={tag}")
    if fl:
        with_files.append(it)
        print(f"        desc: {desc[:220]}")
        for f in fl:
            print(f"        file: {json.dumps(f, ensure_ascii=False)[:300]}")

print(f"\n===== 带附件的题：{len(with_files)} 道 =====")
(WORK / "with_files.json").write_text(json.dumps(with_files, ensure_ascii=False, indent=1))
for it in with_files:
    print(f"  [{it['id']}] {it['question']}  files={len(it['file_list'])}")
