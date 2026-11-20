# -*- coding: utf-8 -*-
"""最终验证壁纸安装状态。"""
import requests

BASE = "http://127.0.0.1:43129"
WID = "up-muudbz0e-jnryv5"
s = requests.Session()

inv = s.get(f"{BASE}/wallpaper-engine/inventory", timeout=15).json()
st = s.get(f"{BASE}/wallpaper-engine/settings", timeout=15).json()
settings = st.get("settings", {})
sid = settings.get("id")

print("=" * 62)
print("壁纸引擎最终状态")
print("=" * 62)
print(f"  上传目录        : {inv.get('uploadDir')}")
print(f"  Wallpaper Engine: {inv.get('installDir') or '（未安装）'}")
print(f"  壁纸总数        : {inv.get('total')}")
print(f"  当前选中 id     : {sid!r}")
print()
for w in (inv.get("wallpapers") or []):
    cur = "   ← 当前显示中" if w["id"] == sid else ""
    print(f"  [{w['id']}] {w.get('title')}  type={w.get('type')}{cur}")
    print(f"      media  : {w.get('media')}")
    print(f"      preview: {w.get('preview')}")
print()
print("  显示相关设置：")
for k in ("objectFit", "typeFilter", "backgroundBrightness", "wallpaperBlur",
          "wallpaperOpacity", "scrim", "blur"):
    print(f"    {k:<22} = {settings.get(k)!r}")
print()
print("  其它关键设置（确认未被破坏）：")
for k, expect in (("accent", "#4f8cff"), ("ropeForm", "whale"), ("glassWindow", True),
                  ("scrim", 0.25), ("blur", 16), ("switchTransition", "cut")):
    got = settings.get(k)
    print(f"    {'OK' if got == expect else '!!'} {k:<20} = {got!r}")

ok = sid == WID and (inv.get("total") or 0) >= 1
print()
print("*** 壁纸安装完成，已设为当前 ***" if ok else "*** 异常 ***")

# 顺手确认媒体可访问
r = s.get(BASE + "/wallpaper-engine/media/RDpcRFNIXHVwLW11dWRiejBlLWpucnl2NS5wbmc",
          timeout=20)
print(f"\n媒体路由 GET → {r.status_code}  {len(r.content):,} bytes  "
      f"Content-Type={r.headers.get('Content-Type')}")
