# -*- coding: utf-8 -*-
"""检查 token 有效性 + 枚举靶场全部分类与题目总数。"""
import json
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
WORK = Path(r"D:\MemLens\work\qsnctf")
TOKEN = (WORK / "token.txt").read_text().strip()

s = requests.Session()
s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0",
                  "Authorization": "Bearer " + TOKEN})
s.get(BASE + "/", timeout=30)

# 1. token 还有效吗
p = s.get(BASE + "/api/profile", timeout=30)
print(f"profile → {p.status_code}")
if p.status_code != 200:
    print("token 已过期，需要重新登录")
    raise SystemExit(1)
j = p.json()
print(f"  用户: {j.get('username')}")

# 2. 分类/标签
for path, desc in (("/api/api/challenge_tags", "题目标签"),
                   ("/api/api/tags", "标签")):
    try:
        r = s.get(BASE + path, timeout=30)
        print(f"{desc} {path} → {r.status_code}")
        if r.status_code == 200:
            try:
                d = r.json()
                print("  ", json.dumps(d, ensure_ascii=False)[:1500])
            except Exception:
                print("  ", r.text[:600])
    except Exception as e:
        print(f"{desc} 异常 {e}")

# 3. 靶场题目不带分类参数：拿总数
for cat in ["", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12",
            "20", "25", "26", "27", "28", "30", "50", "100"]:
    url = (f"{BASE}/api/api/races/5/ctf/challenge"
           f"?page=1&page_size=1&category={cat}")
    try:
        r = s.get(url, timeout=25)
        if r.status_code != 200:
            continue
        d = r.json()
        cnt = d.get("count", 0)
        if cnt:
            print(f"category={cat or '(空/全部)':<8} count={cnt}")
    except Exception:
        pass

# 4. 全部题目（不带分类）分页拉齐
all_items = []
page = 1
while page <= 40:
    url = f"{BASE}/api/api/races/5/ctf/challenge?page={page}&page_size=100"
    r = s.get(url, timeout=40)
    if r.status_code != 200:
        print(f"page {page} → {r.status_code}")
        break
    d = r.json()
    items = d.get("results") or []
    print(f"page {page}: {len(items)} / count={d.get('count')}")
    if not items:
        break
    all_items.extend(items)
    if len(all_items) >= (d.get("count") or 0):
        break
    page += 1

(WORK / "all_challenges.json").write_text(json.dumps(all_items, ensure_ascii=False, indent=1))
print(f"\n共拉取 {len(all_items)} 题 → all_challenges.json")
