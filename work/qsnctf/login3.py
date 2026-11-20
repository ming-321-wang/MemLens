# -*- coding: utf-8 -*-
"""用手上所有 codeId 试 dVdh 登录。"""
import time
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
W = Path(r"D:\MemLens/work/qsnctf")
USER, PASS, CAP = "冥", "wzh211955", "dVdh"

ids = []
for f in sorted(W.glob("code*.txt")):
    ids.append((f.name, f.read_text().strip()))
# 确保 code_now 在里面
if not any("now" in n for n, _ in ids):
    p = W / "code_now.txt"
    if p.exists():
        ids.append(("code_now", p.read_text().strip()))
print(f"codeId 数量: {len(ids)}  验证码: {CAP}")

for name, cid in ids:
    s = requests.Session()
    s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0"})
    try:
        s.get(BASE + "/", timeout=25)
    except Exception:
        pass
    try:
        r = s.post(BASE + "/api/login",
                   json={"username": USER, "password": PASS, "captcha": CAP, "code": cid},
                   timeout=40)
        short = r.text[:200].replace("\n", " ")
        print(f"  {name:<12} {cid[:8]}… → {r.status_code}  {short}")
        if r.status_code == 200:
            try:
                j = r.json()
            except Exception:
                j = {}
            if j.get("access"):
                (W / "token.txt").write_text(j["access"])
                (W / "refresh.txt").write_text(j.get("refresh", ""))
                (W / "used_code.txt").write_text(cid)
                print("\n*** 登录成功，token 已保存 ***")
                break
    except Exception as e:
        print(f"  {name:<12} 异常 {e}")
    time.sleep(0.3)
else:
    print("\n全部失败。原因通常是：dVdh 来自你浏览器页面的图，而我拿不到那张图的 codeId。")
    print("→ 我重新生成一张，你读我给的图。")
