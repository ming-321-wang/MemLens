# -*- coding: utf-8 -*-
"""确认 settings-schema 是否包含 'id'，并找出"当前壁纸"真正的保存位置。"""
import re
from pathlib import Path

G = Path(r"C:\Users\WZH\AppData\Roaming\dsh-desktop\harness\profiles\web"
         r"\node_modules\dsh-plugin-wallpaper-engine")

txt = (G / "lib/settings-schema.js").read_text(encoding="utf-8", errors="replace")
print("=" * 78)
print("# settings-schema.js 中的字段声明")
print("=" * 78)
# 找形如  name: { kind: ... } 的字段声明
for i, ln in enumerate(txt.splitlines(), 1):
    if re.match(r"\s{2,4}[a-zA-Z_][a-zA-Z0-9_]*:\s*\{\s*kind:", ln):
        print(f"  {i:>5}: {ln.strip()[:120]}")
print()
print("=== 是否出现 'id' 作为设置键 ===")
for i, ln in enumerate(txt.splitlines(), 1):
    if re.search(r"^\s{2,4}id\s*:", ln) or re.search(r"\bid\s*:\s*\{\s*kind", ln):
        print(f"  {i:>5}: {ln.strip()[:120]}")
print()
print("=== 'active' / 'current' / 'selected' 相关 ===")
for i, ln in enumerate(txt.splitlines(), 1):
    if re.search(r"(?i)(active|current|selected)\w*\s*[:=]", ln):
        print(f"  {i:>5}: {ln.strip()[:130]}")

# host 端 index.js 里 id 的处理
print()
print("=" * 78)
print("# host index.js 里 settings.id 的处理")
print("=" * 78)
idx = (G / "lib/index.js").read_text(encoding="utf-8", errors="replace")
for i, ln in enumerate(idx.splitlines(), 1):
    if re.search(r"settings\.id\b|\.id\s*=|id:\s*''|normalizeSettings|SETTINGS_KEYS|allowlist|ALLOWED", ln):
        print(f"  {i:>5}: {ln.strip()[:140]}")
