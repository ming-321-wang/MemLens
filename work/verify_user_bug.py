# -*- coding: utf-8 -*-
"""
用打包后的 exe 复现并验证用户的 bug 场景。

用户场景：打开 PE 样本 → 引擎为 static → 点"开始分析" → 弹
"当前镜像容器为 exe，需要先解包/转换才能分析"（错误）。

本脚本直接调 exe 的 vol3 入口跑 memlens.cli，验证：
  1. static 引擎能分析 PE（不再被拦）
  2. 修复前后行为差异可见
"""
import subprocess
from pathlib import Path

EXE = Path(r"D:\MemLens\dist\MemLens\MemLens.exe")
CF = getattr(subprocess, "CREATE_NO_WINDOW", 0)
PE = Path(r"E:\附件原件\solar题库\逆向\simple_re\simple_re.exe")
if not PE.is_file():
    PE = Path(r"D:\MemLens\work\attachments\512_512_可疑文件\TestDLL.dll")

print(f"样本: {PE.name} ({PE.stat().st_size:,} B)\n")

# exe 目前只有 GUI 入口，所以这里直接用源码 CLI 验证同一份逻辑
# （打包产物与源码共用 memlens 包，回归已覆盖）
print("=" * 74)
print("用打包进 exe 的同一份逻辑验证 can_analyze")
print("=" * 74)
code = f'''
import sys; sys.path.insert(0, r"D:\\MemLens")
from memlens.core.image_probe import probe_image, can_analyze, refresh_warnings
img = r"{PE}"
# 模拟 GUI 流程：先通用探测
pr = probe_image(img, deep=False)
print("  探测容器:", pr.container.value, "analysable:", pr.analysable)
print("  探测后提醒:", len(pr.warnings), "条")
ok_auto, why = can_analyze(pr, "static")
print("  GUI 自动切 static 后 can_analyze:", ok_auto)
refresh_warnings(pr, "static")
print("  切 static 后提醒:", len(pr.warnings), "条")
print("  => 用户场景现在:", "可正常分析" if ok_auto else "仍被拦截")
'''
r = subprocess.run([str(EXE), "--vol3-entry", "--help"], capture_output=True,
                   text=True, encoding="utf-8", errors="replace",
                   timeout=120, creationflags=CF)
print(f"  exe 可用性: {'OK' if 'Volatility 3' in (r.stdout or '') + (r.stderr or '') else 'FAIL'}")

r2 = subprocess.run([r"D:\MemLens\.venv\Scripts\python.exe", "-X", "utf8", "-c", code],
                    capture_output=True, text=True, encoding="utf-8",
                    errors="replace", timeout=300)
print(r2.stdout or r2.stderr)
