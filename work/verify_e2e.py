# -*- coding: utf-8 -*-
"""端到端实测：打包后的 exe 用合成 Windows 镜像真跑 vol3 插件。"""
import subprocess
from pathlib import Path

EXE = Path(r"D:\MemLens\dist\MemLens\MemLens.exe")
CF = getattr(subprocess, "CREATE_NO_WINDOW", 0)
IMG = Path(r"D:\MemLens\samples\synthetic_windows.raw")

print(f"镜像: {IMG.name} ({IMG.stat().st_size:,} B)\n")

for plugin in ("banners", "windows.info", "windows.pslist"):
    print("=" * 74)
    print(f"# {plugin}")
    print("=" * 74)
    r = subprocess.run([str(EXE), "--vol3-entry", "-f", str(IMG), plugin],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=600, creationflags=CF)
    out = ((r.stdout or "") + (r.stderr or "")).strip()
    print(f"  rc={r.returncode}  输出 {len(out)} 字符")
    for line in out.splitlines()[:14]:
        print("   ", line[:150])
    print()
