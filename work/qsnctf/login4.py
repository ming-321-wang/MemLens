# -*- coding: utf-8 -*-
"""用指定的 codeId + 验证码登录。"""
import sys
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
W = Path(r"D:\MemLens/work/qsnctf")
USER, PASS = "冥", "wzh211955"

CAP = sys.argv[1] if len(sys.argv) > 1 else "DCru"
cid = sys.argv[2] if len(sys.argv) > 2 else (W / "code_now.txt").read_text().strip()
print(f"codeId={cid[:8]}…  captcha={CAP}")

s = requests.Session()
s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0"})
s.get(BASE + "/", timeout=30)

r = s.post(BASE + "/api/login",
           json={"username": USER, "password": PASS, "captcha": CAP, "code": cid},
           timeout=40)
print(f"HTTP {r.status_code}")
print(r.text[:400])

if r.status_code == 200:
    try:
        j = r.json()
    except Exception:
        j = {}
    if j.get("access"):
        (W / "token.txt").write_text(j["access"])
        (W / "refresh.txt").write_text(j.get("refresh", ""))
        (W / "used_code.txt").write_text(cid)
        (W / "cookie.txt").write_text("; ".join(f"{c.name}={c.value}" for c in s.cookies))
        print("\n*** 登录成功，token/refresh/cookie 已保存 ***")
        print(f"token 长度={len(j['access'])}")
        # 顺手验证 profile
        p = s.get(BASE + "/api/profile", timeout=30)
        if p.status_code == 200:
            d = p.json()
            print(f"已验证身份: {d.get('username')}")
    else:
        print("响应里没有 access 字段")
