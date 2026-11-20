# -*- coding: utf-8 -*-
"""拉取靶场题目列表（category 可指定），存 JSON。"""
import json
import sys
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
WORK = Path(r"D:\MemLens\work\qsnctf")
TOKEN = (WORK / "token.txt").read_text().strip()
RACE_ID = 5
CATEGORY = sys.argv[1] if len(sys.argv) > 1 else "27"

s = requests.Session()
s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0",
                  "Authorization": "Bearer " + TOKEN})
s.get(BASE + "/", timeout=30)

all_items = []
page = 1
while page <= 20:
    url = (f"{BASE}/api/api/races/{RACE_ID}/ctf/challenge"
           f"?page={page}&page_size=50&category={CATEGORY}")
    r = s.get(url, timeout=40)
    if r.status_code != 200:
        print(f"page {page} → HTTP {r.status_code}: {r.text[:200]}")
        break
    j = r.json()
    items = j.get("results") or j.get("data") or []
    if isinstance(items, dict):
        items = items.get("results", [])
    print(f"page {page} → {len(items)} 条（总键: {list(j.keys())}）")
    if not items:
        break
    all_items.extend(items)
    if len(items) < 50:
        break
    page += 1

print(f"\n共 {len(all_items)} 题")
(WORK / f"challenges_cat{CATEGORY}.json").write_text(
    json.dumps(all_items, ensure_ascii=False, indent=1))

for it in all_items:
    cid = it.get("id")
    title = it.get("title") or it.get("name")
    score = it.get("score")
    solved = it.get("solved") or it.get("is_solved")
    attach = it.get("attachment") or it.get("attachments")
    print(f"  [{cid}] {title}  分值={score} solved={solved} 附件={str(attach)[:120]}")
