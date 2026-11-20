# -*- coding: utf-8 -*-
"""生成一张验证码，保存图片 + codeId，等待用户读图。"""
import uuid
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
W = Path(r"D:\MemLens/work/qsnctf")
W.mkdir(parents=True, exist_ok=True)

s = requests.Session()
s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0"})
s.get(BASE + "/", timeout=30)

code_id = str(uuid.uuid4())
png = W / "captcha_now.png"
r = s.get(f"{BASE}/api/captcha/{code_id}", timeout=30)
if r.status_code != 200 or len(r.content) < 500:
    print(f"获取失败 HTTP {r.status_code} len={len(r.content)}")
    raise SystemExit(1)
png.write_bytes(r.content)
(W / "code_now.txt").write_text(code_id)
print(f"codeId = {code_id}")
print(f"图片 = {png} ({len(r.content)} bytes)")
