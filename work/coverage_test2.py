# -*- coding: utf-8 -*-
"""重测覆盖度（修正测试脚本：过滤文档元数据行）。"""
import re
import sys
from pathlib import Path

sys.path.insert(0, r"D:\MemLens")
from memlens.engines.static import extract_interesting_strings

SRC = Path(r"D:\MemLens/work/attachments/web_samples/agent_tesla/memory_strings.txt")
raw = SRC.read_text(encoding="utf-8", errors="replace")

# 说明行/命令行这类"文档元数据"不算标本（工具本来就不该提它们）
META = re.compile(r"(?i)^(note|then|strings\s+-n|sample|tool)\b")

标本 = []
for line in raw.splitlines():
    s = line.strip()
    if not s or s.startswith(("=", "-", "#")):
        continue
    if META.match(s):
        continue
    if re.fullmatch(r"[A-Z /\-]+", s):      # 纯大写分类标题
        continue
    标本.append(s)
print(f"标本字符串 {len(标本)} 条")

blob = "\n".join(标本).encode("latin1", "replace")
found = extract_interesting_strings(blob, limit_per_group=50)
got = {it.strip() for items in found.values() for it in items}

print(f"MemLens 提取 {len(got)} 条 / {len(标本)}  = {len(got)/len(标本):.0%}")
print()
for g, items in sorted(found.items()):
    print(f"  [{g}] {len(items)}")

missed = [s for s in 标本 if s not in got]
print(f"\n漏报 {len(missed)} 条：")
for s in missed:
    print(f"  ✗ {s[:100]}")
