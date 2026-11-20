# -*- coding: utf-8 -*-
"""路由清点：查重复路由 + 打印浏览器/vmscan/verdict 相关路由。"""
import pathlib
import re
from collections import Counter

t = pathlib.Path(r"D:\MemLens\memlens\web\app.py").read_text(encoding="utf-8")
routes = re.findall(r'@app\.(get|post|delete)\("([^"]+)"', t)
c = Counter(p for _, p in routes)
dups = [p for p, n in c.items() if n > 1]
print("路由总数:", len(routes))
print("重复路由:", dups if dups else "无")
print("--- 浏览器/VM/结论相关 ---")
for m, p in routes:
    if any(k in p for k in ("browser", "vmscan", "verdict")):
        print("   %-6s %s" % (m.upper(), p))

# 自动启动检查：有没有在 import/启动路径里自动调 browser_history
print("--- 自动启动风险检查 ---")
hits = []
for i, line in enumerate(t.splitlines(), 1):
    if "browser_history" in line and not line.strip().startswith(("#", '"""', "*")):
        # 只关心出现在函数定义/路由之外的可执行调用
        if "def " in line or "@app." in line or "import" in line:
            continue
        hits.append((i, line.strip()))
print("app.py 中非定义处的 browser_history 引用:", hits if hits else "无")
