# -*- coding: utf-8 -*-
"""qsnctf 登录：payload = {username, password, captcha, code(codeId)}"""
import json
import time
import uuid
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
WORK = Path(r"D:\MemLens\work\qsnctf")
USER = "冥"
PASS = "wzh211955"
CAPTCHA = "UmyB"

s = requests.Session()
s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0"})
try:
    s.get(BASE + "/", timeout=30)
except Exception as e:
    print("home:", e)

ids = sorted((WORK).glob("code?.txt"), key=lambda p: p.name)
code_ids = [p.read_text().strip() for p in ids]
print(f"待试 codeId: {len(code_ids)}")

login_ok = None
for cid in code_ids:
    body = {"username": USER, "password": PASS, "captcha": CAPTCHA, "code": cid}
    try:
        r = s.post(BASE + "/api/login", json=body, timeout=40)
        print(f"--- code={cid[:8]}… → HTTP {r.status_code}")
        txt = r.text[:600]
        print("   ", txt.replace("\n", " ")[:500])
        if r.status_code == 200:
            try:
                j = r.json()
            except Exception:
                j = None
            if isinstance(j, dict) and j.get("access"):
                (WORK / "token.txt").write_text(j["access"])
                if j.get("refresh"):
                    (WORK / "refresh.txt").write_text(j["refresh"])
                (WORK / "used_code.txt").write_text(cid)
                login_ok = (cid, j)
                print("   *** 登录成功，token 已保存 ***")
                break
    except Exception as e:
        print(f"--- code={cid[:8]}… → 异常 {e}")
    time.sleep(0.4)

if not login_ok:
    print("\n全部失败。可能原因：①该验证码不属于这 5 个 codeId；②codeId 已过期。")
    print("→ 我重新生成一张新验证码请你看图读数。")
