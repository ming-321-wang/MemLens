# -*- coding: utf-8 -*-
"""确认典型误判：Dockerfile→memfrag、APK→memfrag、pcapng 截断、zip 无内容清单。"""
import sys
from pathlib import Path

ROOT = Path(r"D:\MemLens")
sys.path.insert(0, str(ROOT))
from memlens.core.image_probe import (ContainerFormat, probe_image,
                                      _looks_like_memory_fragment)

CASES = [
    ("Dockerfile.debian", r"D:\MemLens\work\attachments\scan"),
    ("ParlooChecker.apk", None),
    ("capture_20260628_105013.pca", None),
    ("弱帕鲁.jpg", None),
    ("TopSecret.pdf", None),
    ("._flag.enc", None),
    ("LICENSE", None),
]

scan = ROOT / "work" / "attachments" / "scan"
targets = {}
for ex in scan.iterdir():
    if not ex.is_dir():
        continue
    for p in ex.rglob("*"):
        if p.is_file() and p.name in [c[0] for c in CASES]:
            targets.setdefault(p.name, p)

for name in [c[0] for c in CASES]:
    p = targets.get(name)
    if not p:
        continue
    with open(p, "rb") as f:
        head = f.read(64)
    pr = probe_image(str(p), deep=False)
    frag = _looks_like_memory_fragment(str(p), None)
    print(f"{name:<34} size={p.stat().st_size:>9,}  容器={pr.container.value}")
    print(f"   头16B: {head[:16].hex(' ')}")
    print(f"   ASCII: {head[:24]!r}")
    print(f"   命中 memfrag 判据: {frag}")
    for w in pr.warnings:
        print(f"   ! {w[:100]}")
    print()

# zip/apk 内容是否有清单
print("=== zip 类文件是否给出内容清单 ===")
import zipfile
for nm in ("附件.zip", "app.jar", "ParlooChecker.apk"):
    p = targets.get(nm)
    if not p:
        continue
    try:
        with zipfile.ZipFile(p) as z:
            names = z.namelist()
            print(f"{nm}: {len(names)} 项，前 8: {names[:8]}")
            # 内嵌可执行
            for zi in z.infolist():
                if zi.filename.lower().endswith((".exe", ".dll", ".sys", ".elf", ".so")):
                    print(f"    ★ 内嵌可执行: {zi.filename} ({zi.file_size:,})")
    except Exception as e:
        print(f"{nm}: 非标准 zip ({str(e)[:60]})")
