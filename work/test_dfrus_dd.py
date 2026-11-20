# -*- coding: utf-8 -*-
"""DFRWS 2009 磁盘镜像：验证 MemLens 对磁盘镜像的识别（磁盘 vs 内存镜像区分）。"""
import sys
from pathlib import Path

sys.path.insert(0, r"D:\MemLens")
from memlens.core.image_probe import ContainerFormat, probe_image, describe

P = Path(r"D:\MemLens/work/attachments/web_samples/dfrws2009/nssal-thumb-fs.dd")
if not P.exists():
    print("镜像不存在，先下载")
    raise SystemExit(1)

print(f"文件: {P.name}  {P.stat().st_size:,} B")
print(f"头 64B: {open(P,'rb').read(64).hex(' ')}")
print()

pr = probe_image(str(P), deep=False, for_engine="vol3")
print(f"容器: {pr.container.value}  (置信度 {pr.container_confidence})")
print(f"系统: {pr.os_type.value}  ({pr.os_confidence})")
print(f"内存镜像? {pr.container.is_memory_image}")
print(f"可直接分析? {pr.analysable}")
print()
print("证据:")
for e in pr.evidence:
    print(f"  [{e.source}] {e.detail[:130]}")
print()
print("提醒:")
for w in pr.warnings:
    print(f"  ! {w[:150]}")
print()
print(describe(pr).splitlines()[3])

# 关键判断：这是磁盘镜像（MBR 分区表），不是内存镜像
head = open(P, "rb").read(512)
print()
print("=== 分区表判据 ===")
print(f"  MBR 签名 0x55AA: {head[510:512].hex()}")
for i in range(4):
    e = head[446 + i * 16: 446 + (i + 1) * 16]
    if any(e):
        boot, sh, ss, se, typ, eh, es, ee = e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7]
        lba = int.from_bytes(e[8:12], "little")
        cnt = int.from_bytes(e[12:16], "little")
        print(f"  分区{i+1}: type=0x{typ:02x} LBA={lba} 扇区数={cnt} "
              f"({cnt*512/1024/1024:.1f} MiB)")
