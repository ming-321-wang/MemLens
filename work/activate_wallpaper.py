# -*- coding: utf-8 -*-
"""把上传的壁纸设为当前壁纸（PUT /wallpaper-engine/settings，只改 id）。"""
import json
from pathlib import Path

import requests

BASE = "http://127.0.0.1:43129"
WID = "up-muudbz0e-jnryv5"          # 上传成功后返回的 id

s = requests.Session()
s.headers.update({"User-Agent": "MemLens-installer/1.0"})

# 1. 读当前完整 settings（确保其它字段不被覆盖丢）
r = s.get(f"{BASE}/wallpaper-engine/settings", timeout=15)
payload = r.json()
settings = payload.get("settings", {})
print(f"读到的 settings 字段数: {len(settings)}")
print(f"  当前 id = {settings.get('id')!r}")

# 2. 只改 id
settings["id"] = WID
body = payload if isinstance(payload, dict) and "settings" in payload else {"settings": settings}
if "settings" in body:
    body["settings"] = settings
else:
    body = {"settings": settings}

# 3. PUT 回去
r = s.put(f"{BASE}/wallpaper-engine/settings", json=body, timeout=60)
print(f"\nPUT → HTTP {r.status_code}")
try:
    resp = r.json()
except Exception:
    resp = {}
new = resp.get("settings", settings)
print(f"  返回 id = {new.get('id')!r}")
print(f"  返回字段数: {len(new)}")

# 4. 验证（独立再读一次）
inv = s.get(f"{BASE}/wallpaper-engine/inventory", timeout=15).json()
st = s.get(f"{BASE}/wallpaper-engine/settings", timeout=15).json()
sid = st.get("settings", {}).get("id")
ws = inv.get("wallpapers") or []
print("\n=== 最终验证 ===")
print(f"  inventory.total = {inv.get('total')}")
for w in ws:
    mark = "  ← 当前选中" if w.get("id") == sid else ""
    print(f"    [{w['id']}] {w.get('title')}  type={w.get('type')}{mark}")
print(f"  settings.id = {sid!r}")
print(f"  settings.typeFilter = {st.get('settings', {}).get('typeFilter')!r}")
print(f"  settings.objectFit  = {st.get('settings', {}).get('objectFit')!r}")
print(f"  settings.backgroundBrightness = {st.get('settings', {}).get('backgroundBrightness')!r}")
# 关键设置项是否完好（对比空 PUT 之前的默认值）
for k, expect in (("scrim", 0.25), ("blur", 16), ("accent", "#4f8cff"),
                  ("glassWindow", True), ("ropeForm", "whale")):
    got = st.get("settings", {}).get(k)
    flag = "OK" if got == expect else "!!"
    print(f"  {flag} {k} = {got!r}（期望 {expect!r}）")

ok = (inv.get("total") or 0) >= 1 and sid == WID
print("\n*** 壁纸已安装并设为当前 ***" if ok else "\n*** 仍未生效 ***")
