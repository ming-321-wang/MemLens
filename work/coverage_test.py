# -*- coding: utf-8 -*-
"""
覆盖度验证：用真实 Agent Tesla 内存字符串清单测 MemLens 的 strings 维度。
看能提取出几条真实 IOC、漏掉哪些 —— 漏的就是工具缺陷。
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, r"D:\MemLens")
from memlens.engines.static import extract_interesting_strings

SRC = Path(r"D:\MemLens/work/attachments/web_samples/agent_tesla/memory_strings.txt")
raw = SRC.read_text(encoding="utf-8", errors="replace")

# 把清单里的"标本字符串"抽出来（跳过说明行）
标本 = []
for line in raw.splitlines():
    s = line.strip()
    if not s or s.startswith(("=", "-", "#", "Sample", "Tool", "Note")):
        continue
    if re.fullmatch(r"[A-Z /\-]+", s):      # 纯大写的分类标题
        continue
    标本.append(s)
print(f"清单中的标本字符串 {len(标本)} 条\n")

blob = "\n".join(标本).encode("latin1", "replace")
found = extract_interesting_strings(blob, limit_per_group=50)

got = set()
for g, items in found.items():
    for it in items:
        got.add(it.strip())

print("=" * 78)
print("MemLens 实际提取到的（按类别）")
print("=" * 78)
for g, items in found.items():
    print(f"  [{g}] {len(items)} 条")
    for it in items[:12]:
        print(f"      {it[:95]}")

print()
print("=" * 78)
print("漏掉的真实 IOC（工具缺陷）")
print("=" * 78)
missed = [s for s in 标本 if s not in got]
print(f"漏 {len(missed)} / {len(标本)} 条")
for s in missed:
    print(f"  ✗ {s[:100]}")

# 分类归因：漏的这些属于什么类型
print()
print("=" * 78)
print("漏报类型归因")
print("=" * 78)
BUCKETS = {
    "SMTP/邮件外泄凭据": r"(?i)smtp|mail|@smtp|smtpPassword|smtpPort|smtpSender",
    "PyInstaller 打包痕迹": r"(?i)_MEI|python31|pyinstaller|PYZ|\.pyz",
    "C2 / gate.php 外联": r"(?i)gate\.php|proxy/|jino-net|%APPDATA%",
    "键盘记录器 ID": r"(?i)keylog|tibia",
    "IP 地址（裸IP非URL）": r"^\d{1,3}(\.\d{1,3}){3}$",
    "注册表持久化": r"(?i)CurrentVersion\\Run|HKCU|Software\\",
}
for name, pat in BUCKETS.items():
    hits = [s for s in missed if re.search(pat, s)]
    if hits:
        print(f"  [{name}] 漏 {len(hits)} 条")
        for h in hits[:6]:
            print(f"      {h[:95]}")
