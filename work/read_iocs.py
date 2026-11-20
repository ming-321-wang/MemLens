# -*- coding: utf-8 -*-
"""读真实 IoC 清单 + 内存字符串清单，并测试 MemLens 对加密 zip 的处理。"""
from pathlib import Path

D = Path(r"D:\MemLens/work/attachments/web_samples/agent_tesla")
for f in sorted(D.glob("*.txt")):
    print("=" * 74)
    print(f"# {f.name}")
    print("=" * 74)
    try:
        print(f.read_text(encoding="utf-8", errors="replace")[:2200])
    except Exception as e:
        print("读取失败:", e)
    print()
