# -*- coding: utf-8 -*-
"""确认 UPLOAD_EXT 白名单 + 当前壁纸的设置字段名。"""
import re
from pathlib import Path

G = Path(r"C:\Users\WZH\AppData\Roaming\dsh-desktop\harness\profiles\web"
         r"\node_modules\dsh-plugin-wallpaper-engine")

# 1) UPLOAD_EXT / 契约表
for name in ("lib/routes/upload.js", "lib/index.js", "lib/settings-schema.js",
             "lib/types", "lib/pkg-read.js"):
    p = G / name
    if not p.exists():
        continue
    txt = p.read_text(encoding="utf-8", errors="replace")
    print("=" * 78)
    print(f"# {name}")
    print("=" * 78)
    hits = 0
    for i, ln in enumerate(txt.splitlines(), 1):
        if re.search(r"UPLOAD_EXT|accepts?Mime|MIME_|image/|\.png\b|\.jpe?g\b|\.webp\b|\.mp4\b|\.gif\b", ln):
            print(f"  {i:>5}: {ln.strip()[:150]}")
            hits += 1
            if hits >= 18:
                break
    print()

# 2) 当前壁纸字段
print("=" * 78)
print("# 当前壁纸的选择字段（active / current / selected）")
print("=" * 78)
for name in ("lib/settings-schema.js", "lib/index.js", "lib/routes/scene-serve.js"):
    p = G / name
    if not p.exists():
        continue
    txt = p.read_text(encoding="utf-8", errors="replace")
    print(f"--- {name}")
    n = 0
    for i, ln in enumerate(txt.splitlines(), 1):
        if re.search(r"(activeWallpaper|currentWallpaper|selectedWallpaper|wallpaperId|activeId|"
                     r"currentId|active_scene|activeScene|playlistId|active_playlist)\b", ln):
            print(f"  {i:>5}: {ln.strip()[:150]}")
            n += 1
            if n >= 14:
                break
    print()
