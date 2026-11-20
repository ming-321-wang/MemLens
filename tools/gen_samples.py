# -*- coding: utf-8 -*-
"""
生成用于自测的**合成样本**（不含任何真实数据，纯粹用来验证探测逻辑）。

为什么需要它：在没有真实内存镜像的情况下，也必须能验证
「容器识别 / 系统指纹 / 对齐与稀疏判定」这条链路是否正确。
"""
from __future__ import annotations

import os
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "samples"
OUT.mkdir(parents=True, exist_ok=True)

WIN_PROCS = [b"System\x00", b"smss.exe", b"csrss.exe", b"wininit.exe", b"services.exe",
             b"lsass.exe", b"winlogon.exe", b"svchost.exe", b"explorer.exe"]
WIN_STRS = [b"\\SystemRoot\\System32\\ntdll.dll", b"\\Device\\HarddiskVolume2\\Windows",
            b"Windows NT 10.0", b"Microsoft Windows"]
LINUX_STRS = [b"Linux version 5.15.0-91-generic", b"swapper/0", b"kthreadd",
              b"/sbin/init", b"systemd\x00", b"/lib/systemd/systemd"]


def _pad_to(buf: bytearray, size: int) -> bytearray:
    if len(buf) < size:
        buf += bytes(size - len(buf))
    return buf


def make_windows_raw(path: Path, size_mb: int = 8) -> None:
    """伪 Windows 裸内存镜像：4KiB 对齐、含进程名与系统路径特征、含空洞。"""
    size = size_mb << 20
    buf = bytearray(size)
    import random
    random.seed(42)
    # 制造一些"非零数据页"
    for _ in range(size // 8192):
        off = random.randrange(0, size - 4096) & ~0xFFF
        buf[off:off + 4096] = bytes(random.getrandbits(8) for _ in range(4096))
    # 埋入特征串
    pos = 0x1000
    for s in WIN_PROCS + WIN_STRS:
        buf[pos:pos + len(s)] = s
        pos += 0x800 + len(s)
    path.write_bytes(bytes(buf))


def make_lime(path: Path) -> None:
    """伪 LiME 分段镜像：头部 b'EMiL' + version/start/end/reserved。"""
    body = bytearray(2 << 20)
    for s in LINUX_STRS:
        body[0x1000:0x1000 + len(s)] = s
    header = b"EMiL" + struct.pack("<IIQQ", 1, 0, len(body), 0)
    path.write_bytes(header + bytes(body))


def make_windmp(path: Path) -> None:
    """伪 Windows 崩溃转储（PAGEDU64）。"""
    buf = bytearray(1 << 20)
    buf[0:4] = b"PAGE"
    buf[4:8] = b"DU64"
    for i, s in enumerate(WIN_PROCS):
        off = 0x2000 + i * 0x100
        buf[off:off + len(s)] = s
    path.write_bytes(bytes(buf))


def make_minidump(path: Path) -> None:
    buf = bytearray(64 << 10)
    buf[0:4] = b"MDMP"
    for i, s in enumerate(WIN_PROCS):
        off = 0x1000 + i * 0x40
        buf[off:off + len(s)] = s
    path.write_bytes(bytes(buf))


def make_linux_raw(path: Path) -> None:
    size = 4 << 20
    buf = bytearray(size)
    pos = 0x2000
    for s in LINUX_STRS:
        buf[pos:pos + len(s)] = s
        pos += 0x1000 + len(s)
    path.write_bytes(bytes(buf))


def make_unknown(path: Path) -> None:
    """既非镜像也无系统指纹（模拟"这是别的东西"）。"""
    path.write_bytes(os.urandom(123456))  # 故意不对齐 4KiB


def main() -> None:
    make_windows_raw(OUT / "synthetic_windows.raw", 8)
    make_lime(OUT / "synthetic_lime.lime")
    make_windmp(OUT / "synthetic_crash.dmp")
    make_minidump(OUT / "synthetic_mini.dmp")
    make_linux_raw(OUT / "synthetic_linux.raw")
    make_unknown(OUT / "synthetic_unknown.bin")
    for p in sorted(OUT.iterdir()):
        print(f"{p.stat().st_size:>12,}  {p.name}")


if __name__ == "__main__":
    main()
