# -*- coding: utf-8 -*-
"""读 wallpaper-engine 插件的 upload/settings 路由，确定正确的壁纸安装方式。"""
from pathlib import Path

G = Path(r"C:\Users\WZH\AppData\Roaming\dsh-desktop\harness\profiles\web"
         r"\node_modules\dsh-plugin-wallpaper-engine")

for name in ("lib/routes/upload.js", "lib/index.js"):
    p = G / name
    print("=" * 78)
    print(f"# {name}")
    print("=" * 78)
    if not p.exists():
        print("  不存在")
        continue
    txt = p.read_text(encoding="utf-8", errors="replace")
    lines = txt.splitlines()
    # 找路由注册与关键逻辑
    import re
    keys = ("route(", "router.", "app.", "post(", "get(", "put(", "delete(",
            "upload", "remove", "multer", "multipart", "formData", "busboy",
            "maxFileSize", "accept", "mime", "extension", ".png", ".jpg",
            "json()", "sendFile", "writeFile", "mkdir", "uploadDir")
    shown = 0
    for i, ln in enumerate(lines, 1):
        if any(k in ln for k in keys) and shown < 45:
            print(f"  {i:>5}: {ln.strip()[:155]}")
            shown += 1
    print()
