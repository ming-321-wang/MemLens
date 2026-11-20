"""
C 盘占用分析：顶层目录体积 + 最大的文件（只读，不删任何东西）。

用法：python disk_usage_c.py [盘符]
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path


def dir_size(p: Path, limit: int = 4_000_000) -> int:
    total = 0
    files = 0
    stack = [p]
    while stack:
        cur = stack.pop()
        try:
            entries = list(os.scandir(cur))
        except (OSError, PermissionError):
            continue
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    stack.append(Path(e.path))
                elif e.is_file(follow_symlinks=False):
                    total += e.stat(follow_symlinks=False).st_size
                    files += 1
                    if files >= limit:
                        return total
            except OSError:
                continue
    return total


def human(n: float) -> str:
    v = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or u == "TB":
            return f"{v:,.2f} {u}"
        v /= 1024
    return f"{v:.2f} TB"


def main() -> int:
    drive = (sys.argv[1] if len(sys.argv) > 1 else "C:").rstrip("\\")
    root = Path(drive + "\\")
    out = Path(__file__).with_name(f"disk_usage_{drive.rstrip(':')}.txt")
    lines: list[str] = []

    def say(s: str = "") -> None:
        print(s, flush=True)
        lines.append(s)

    try:
        du = shutil.disk_usage(str(root))
        say(f"=== {drive} 磁盘 ===")
        say(f"总计 {human(du.total)}   已用 {human(du.used)}   空闲 {human(du.free)}")
        say("")
    except OSError as exc:
        say(f"读取磁盘信息失败：{exc}")

    say("=== 顶层占用 ===")
    rows: list[tuple[float, str]] = []
    try:
        entries = list(os.scandir(root))
    except OSError as exc:
        say(f"无法枚举 {root}：{exc}")
        entries = []
    for e in entries:
        try:
            if e.is_file(follow_symlinks=False):
                rows.append((e.stat(follow_symlinks=False).st_size / 1073741824, e.name))
            elif e.is_dir(follow_symlinks=False):
                rows.append((dir_size(Path(e.path)) / 1073741824, e.path))
        except OSError:
            continue
    rows.sort(reverse=True)
    for gb, name in rows:
        say(f"  {gb:9.2f} GB  {name}")

    say("\n=== C:\\Users\\WZH 二级占用 ===")
    up = root / "Users" / "WZH"
    if up.is_dir():
        rows2: list[tuple[float, str]] = []
        try:
            for e in os.scandir(up):
                try:
                    if e.is_dir(follow_symlinks=False):
                        rows2.append((dir_size(Path(e.path)) / 1073741824, e.path))
                    else:
                        rows2.append((e.stat(follow_symlinks=False).st_size / 1073741824,
                                       e.path))
                except OSError:
                    continue
        except OSError:
            pass
        rows2.sort(reverse=True)
        for gb, name in rows2[:20]:
            say(f"  {gb:9.2f} GB  {name}")

    say("\n=== 全盘最大的 40 个文件（>200 MB）===")
    big: list[tuple[int, str]] = []
    stack = [root]
    t0 = time.time()
    while stack:
        cur = stack.pop()
        try:
            entries = list(os.scandir(cur))
        except (OSError, PermissionError):
            continue
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    if e.name.lower() in ("$recycle.bin", "system volume information"):
                        continue
                    stack.append(Path(e.path))
                elif e.is_file(follow_symlinks=False):
                    st = e.stat(follow_symlinks=False)
                    if st.st_size > 200 * 1024 * 1024:
                        big.append((st.st_size, e.path))
            except OSError:
                continue
    big.sort(reverse=True)
    for sz, p in big[:40]:
        say(f"  {human(sz):>12}  {p}")
    say(f"\n（扫描耗时 {time.time() - t0:.0f} s）")

    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n完整报告 → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
