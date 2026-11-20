# -*- coding: utf-8 -*-
"""
通过 DSH 壁纸引擎的 HTTP 路由安装一张壁纸：
  1) POST /wallpaper-engine/upload?title=…   （raw body + image/png）→ 得到 up-… id
  2) GET  /wallpaper-engine/settings          （读当前设置，只改 id）
  3) POST /wallpaper-engine/settings          （写回）
  4) GET  /wallpaper-engine/inventory         （验证 total=1 且 id 生效）
"""
import json
from pathlib import Path

import requests

BASE = "http://127.0.0.1:43129"
for _c in (Path(r"C:\Users\WZH\Desktop\MemLens_wallpaper_4K.png"),
           Path(r"D:\DSH\工作区\MemLens_wallpaper_4K.png"),
           Path(r"D:\MemLens\work\MemLens_wallpaper_4K.png")):
    if _c.exists():
        IMG = _c
        break
else:
    raise SystemExit("找不到壁纸图片")
TITLE = "MemLens 4K 深色取证风"

s = requests.Session()
s.headers.update({"User-Agent": "MemLens-installer/1.0"})

# ---- 0. 当前状态 ----
r = s.get(f"{BASE}/wallpaper-engine/inventory", timeout=15)
inv = r.json()
print("安装前 inventory:")
print(f"  installDir={inv.get('installDir')}  uploadDir={inv.get('uploadDir')}")
print(f"  total={inv.get('total')}  wallpapers={len(inv.get('wallpapers') or [])}")

st = s.get(f"{BASE}/wallpaper-engine/settings", timeout=15).json()
cur = st.get("settings", {})
print(f"  当前 settings.id = {cur.get('id')!r}")

# ---- 1. 上传 ----
data = IMG.read_bytes()
print(f"\n上传 {IMG.name}（{len(data):,} bytes）…")
r = s.post(f"{BASE}/wallpaper-engine/upload",
           params={"title": TITLE},
           data=data,
           headers={"Content-Type": "image/png"},
           timeout=180)
print(f"  HTTP {r.status_code}")
print(f"  {r.text[:600]}")
if r.status_code not in (200, 201):
    raise SystemExit("上传失败")

try:
    up = r.json()
except Exception:
    up = {}
wid = up.get("id") or up.get("uploadId") or up.get("wallpaper", {}).get("id")
if not wid:
    # 回退：从 inventory 里找刚上传的
    inv = s.get(f"{BASE}/wallpaper-engine/inventory", timeout=15).json()
    ws = inv.get("wallpapers") or []
    wid = ws[-1].get("id") if ws else None
print(f"  → 得到壁纸 id: {wid}")

# ---- 2/3. 写入 settings（只改 id）----
st = s.get(f"{BASE}/wallpaper-engine/settings", timeout=15).json()
settings = st.get("settings", {})
settings["id"] = wid
r = s.post(f"{BASE}/wallpaper-engine/settings",
           json=settings if "settings" in st else {"settings": settings},
           timeout=60)
print(f"\n写入 settings → HTTP {r.status_code}")
print(f"  {r.text[:400]}")

# ---- 4. 验证 ----
inv2 = s.get(f"{BASE}/wallpaper-engine/inventory", timeout=15).json()
st2 = s.get(f"{BASE}/wallpaper-engine/settings", timeout=15).json()
print("\n=== 安装后 ===")
print(f"  total={inv2.get('total')}")
for w in (inv2.get("wallpapers") or []):
    print(f"    [{w.get('id')}] {w.get('title') or w.get('name')}  "
          f"type={w.get('type')} size={w.get('size') or w.get('bytes')}")
print(f"  settings.id = {st2.get('settings', {}).get('id')!r}")
print(f"  typeFilter  = {st2.get('settings', {}).get('typeFilter')!r}")
ok = (inv2.get("total") or 0) >= 1 and st2.get("settings", {}).get("id") == wid
print("\n*** 安装成功 ***" if ok else "\n*** 未完全生效，需检查 ***")
