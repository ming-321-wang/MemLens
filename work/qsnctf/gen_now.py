# -*- coding: utf-8 -*-
"""生成一张全新验证码并在对话里展示，用户读数后立即登录。"""
import uuid
from pathlib import Path

import requests

BASE = "https://www.qsnctf.com"
WORK = Path(r"D:\MemLens\work\qsnctf")
WORK.mkdir(parents=True, exist_ok=True)

s = requests.Session()
s.headers.update({"Referer": BASE + "/", "User-Agent": "Mozilla/5.0"})
s.get(BASE + "/", timeout=30)

code_id = str(uuid.uuid4())
png = WORK / "captcha_now.png"
r = s.get(f"{BASE}/api/captcha/{code_id}", timeout=30)
if r.status_code != 200 or len(r.content) < 500:
    print(f"获取验证码失败: HTTP {r.status_code} len={len(r.content)}")
    raise SystemExit(1)

png.write_bytes(r.content)
(WORK / "code_now.txt").write_text(code_id)
print(f"codeId = {code_id}")
print(f"图片   = {png}  ({len(r.content)} bytes)")
print("请在对话里查看上方图片，把 4 个字符发我（注意大小写）")
