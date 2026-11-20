# -*- coding: utf-8 -*-
"""用裸 settings 对象 PUT，并恢复 ropeForm。"""
import requests

BASE = "http://127.0.0.1:43129"
WID = "up-muudbz0e-jnryv5"

s = requests.Session()
s.headers.update({"User-Agent": "MemLens-installer/1.0"})

payload = s.get(f"{BASE}/wallpaper-engine/settings", timeout=15).json()
settings = dict(payload.get("settings", {}))
settings["id"] = WID
settings["ropeForm"] = "whale"          # 恢复被我空 body PUT 改掉的值

print(f"发送字段数 {len(settings)}，id={settings['id']!r}")

# 方式 A：裸对象
r = s.put(f"{BASE}/wallpaper-engine/settings", json=settings, timeout=60)
print(f"A 裸对象 PUT → {r.status_code}  {r.text[:200]}")
after = s.get(f"{BASE}/wallpaper-engine/settings", timeout=15).json().get("settings", {})
print(f"   → id={after.get('id')!r}  ropeForm={after.get('ropeForm')!r}")
if after.get("id") == WID:
    print("\n*** 成功（方式 A）***")
    raise SystemExit(0)

# 方式 B：包一层 settings
body = {"settings": settings}
r = s.put(f"{BASE}/wallpaper-engine/settings", json=body, timeout=60)
print(f"B 包装 PUT → {r.status_code}  {r.text[:200]}")
after = s.get(f"{BASE}/wallpaper-engine/settings", timeout=15).json().get("settings", {})
print(f"   → id={after.get('id')!r}  ropeForm={after.get('ropeForm')!r}")
if after.get("id") == WID:
    print("\n*** 成功（方式 B）***")
    raise SystemExit(0)

print("\n两种方式都没写入 id —— 需要换思路")
