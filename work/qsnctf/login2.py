# -*- coding: utf-8 -*-
"""用指定 codeId + 验证码登录 qsnctf。"""
import sys
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
WORK = Path(r"D:\MemLens\work\qsnctf")
USER = "冥"
PASS = "wzh211955"

cap = sys.argv[1] if len(sys.argv) > 1 else "tBaF"
cid = sys.argv[2] if len(sys.argv) > 2 else (WORK / "code_now.txt").read_text().strip()

print(f"codeId={cid[:8]}…  captcha={cap}")

s = requests.Session()
s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0"})
s.get(BASE + "/", timeout=30)

r = s.post(f"{BASE}/api/login",
           json={"username": USER, "password": PASS, "captcha": cap, "code": cid},
           timeout=40)
print(f"HTTP {r.status_code}")
print(r.text[:800])

if r.status_code == 200:
    try:
        j = r.json()
    except Exception:
        j = {}
    if j.get("access"):
        (WORK / "token.txt").write_text(j["access"])
        if j.get("refresh"):
            (WORK / "refresh.txt").write_text(j["refresh"])
        (WORK / "used_code.txt").write_text(cid)
        (WORK / "cookie.txt").write_text("; ".join(f"{c.name}={c.value}" for c in s.cookies))
        print("\n*** 登录成功 ***")
        print(f"token 长度={len(j['access'])}")
        print(f"用户字段: {[k for k in j.keys() if k != 'access'][:12]}")
