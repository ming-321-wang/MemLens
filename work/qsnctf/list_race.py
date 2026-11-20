# -*- coding: utf-8 -*-
"""登录后拉取靶场列表 + 指定分类的题目。"""
import json
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
WORK = Path(r"D:\MemLens\work\qsnctf")
TOKEN = (WORK / "token.txt").read_text().strip()

s = requests.Session()
s.headers.update({
    "Referer": BASE + "/",
    "User-Agent": "Mozilla/5.0",
    "Authorization": "Bearer " + TOKEN,
})
s.get(BASE + "/", timeout=30)


def api(path, desc):
    try:
        r = s.get(BASE + path, timeout=40)
        print(f"=== {desc}\n    GET {path} → {r.status_code} len={len(r.content)}")
        if r.status_code != 200:
            print("   ", r.text[:300])
            return None
        try:
            return r.json()
        except Exception:
            print("   (非 JSON)", r.text[:200])
            return None
    except Exception as e:
        print(f"=== {desc} 异常 {e}")
        return None


print("--- /api/profile ---")
p = s.get(BASE + "/api/profile", timeout=30)
print(f"    HTTP {p.status_code} {p.text[:300]}")

pr = api("/api/api/practice_race", "靶场列表")
if pr:
    out = WORK / "practice_race.json"
    out.write_text(json.dumps(pr, ensure_ascii=False, indent=1))
    print(f"    已存 {out}")
    # 打印结构概览
    if isinstance(pr, dict):
        print("    keys:", list(pr.keys())[:20])
        for k, v in pr.items():
            if isinstance(v, list):
                print(f"    {k}: list[{len(v)}]")
                if v:
                    print(f"      首元素 keys: {list(v[0].keys()) if isinstance(v[0], dict) else type(v[0])}")
                    print(f"      首元素: {json.dumps(v[0], ensure_ascii=False)[:500]}")
            else:
                print(f"    {k}: {str(v)[:100]}")
    elif isinstance(pr, list):
        print(f"    list[{len(pr)}] 首元素: {json.dumps(pr[0], ensure_ascii=False)[:500]}")
