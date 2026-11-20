# -*- coding: utf-8 -*-
"""
关键验证：打包后的 exe 能否真正枚举并运行 vol3 插件。

上一轮检查"vol3 插件 .pyd/.pyc = 0"是因为 .py 被打进了 PYZ 归档，
不能据此判断插件丢失。唯一可信的办法是**让 exe 真的去列/跑插件**：
  1. `MemLens.exe --vol3-entry --help` 输出里应含大量 windows.* / linux.* 插件名
  2. 用合成镜像真的跑一个插件（banners），应输出 Windows 指纹
"""
import os
import subprocess
from pathlib import Path

EXE = Path(r"D:\MemLens\dist\MemLens\MemLens.exe")
CF = getattr(subprocess, "CREATE_NO_WINDOW", 0)
IMG = Path(r"D:\MemLens\samples\synthetic_raw.img")

print("=" * 74)
print("1. exe 的 vol3 入口能否列出插件")
print("=" * 74)
r = subprocess.run([str(EXE), "--vol3-entry", "--help"],
                   capture_output=True, text=True, encoding="utf-8",
                   errors="replace", timeout=240, creationflags=CF)
out = (r.stdout or "") + (r.stderr or "")
print(f"  rc={r.returncode}  输出 {len(out)} 字符")

# 统计插件名出现情况
import re
fam = {}
for m in re.finditer(r"\b(windows|linux|mac)\.[a-z0-9_.]+", out):
    top = m.group(0).split(".")[1]
    fam[top] = fam.get(top, 0) + 1
print(f"  出现的插件族: {fam}")
for probe in ("windows.pslist", "windows.psscan", "windows.malfind",
              "windows.netscan", "banners"):
    hit = probe in out
    print(f"    {'OK  ' if hit else 'MISS'} {probe}")

print()
print("=" * 74)
print("2. 用合成镜像真跑一个插件（banners）")
print("=" * 74)
if not IMG.is_file():
    print(f"  跳过：合成镜像不存在 {IMG}")
else:
    r = subprocess.run([str(EXE), "--vol3-entry", "-f", str(IMG), "banners"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=600, creationflags=CF)
    out = (r.stdout or "") + (r.stderr or "")
    print(f"  rc={r.returncode}")
    # 打印有信息量的行
    shown = 0
    for line in out.splitlines():
        s = line.rstrip()
        if not s:
            continue
        if any(k in s for s in ("Windows", "windows", "Linux", "linux", "Volatility",
                                "layer", "Layer", "Error", "error", "Traceback",
                                "Kernel", "kernel")):
            print("   ", s[:150])
            shown += 1
            if shown >= 18:
                break
    ok = ("Windows" in out or "windows" in out) and r.returncode == 0
    print(f"\n  {'OK   插件真的跑了并识别出系统' if ok else '需检查（见上）'}")
