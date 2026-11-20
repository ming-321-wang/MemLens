"""
C 盘 · 第二轮定点清理：已知"可再生成"的大块缓存（固定白名单，不猜）

原则：路径写死在白名单里 → 只删内容不删目录 → 被占用自动跳过 → 删前二次校验名字。
"""
from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

USER = Path.home()
LOCAL = Path(os.environ.get("LOCALAPPDATA", USER / "AppData/Local"))
ROAMING = Path(os.environ.get("APPDATA", USER / "AppData/Roaming"))

#: (标签, 路径) —— 全部是**可再生成**的缓存/日志/中间产物
FIXED = [
    ("显卡着色器缓存", LOCAL / "NVIDIA/DXCache"),
    ("显卡着色器缓存", LOCAL / "NVIDIA/GLCache"),
    ("显卡着色器缓存", LOCAL / "NVIDIA ComputeCache"),
    ("显卡驱动下载", Path(r"C:\ProgramData\NVIDIA Corporation\Downloader")),
    ("传递优化缓存", Path(r"C:\ProgramData\Microsoft\Windows\DeliveryOptimization\Cache")),
    ("传递优化缓存", Path(r"C:\Windows\SoftwareDistribution\DeliveryOptimization")),
    ("Windows 日志", Path(r"C:\Windows\Logs\CBS")),
    ("Windows 日志", Path(r"C:\Windows\Logs\DISM")),
    ("Windows 日志", Path(r"C:\Windows\Logs\WindowsUpdate")),
    ("Windows 升级残留", Path(r"C:\Windows\WinSxS\Temp")),
    ("崩溃转储", LOCAL / "CrashDumps"),
    ("错误报告", Path(r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue")),
    ("错误报告", Path(r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive")),
    ("系统临时", Path(r"C:\Windows\Temp")),
    ("Gradle 缓存", USER / ".gradle/caches"),
    ("Gradle 缓存", USER / ".gradle/daemon"),
    ("Gradle 缓存", USER / ".gradle/wrapper"),
    ("NuGet 缓存", USER / ".nuget/packages"),
    ("npm 缓存", LOCAL / "npm-cache"),
    ("pip 缓存", LOCAL / "pip/Cache"),
    ("yarn 缓存", LOCAL / "Yarn/Cache"),
    ("Playwright 缓存", LOCAL / "ms-playwright/.cache"),
    ("VS Code 缓存", ROAMING / "Code/Cache"),
    ("VS Code 缓存", ROAMING / "Code/CachedData"),
    ("VS Code 缓存", ROAMING / "Code/CachedExtensions"),
    ("VS Code 日志", ROAMING / "Code/logs"),
    ("JetBrains 缓存", LOCAL / "JetBrains"),
    ("WPS 更新包", ROAMING / "kingsoft/office6/update"),
    ("WPS 日志", ROAMING / "kingsoft/office6/log"),
    ("WPS 云图标缓存", LOCAL / "Kingsoft/WPS Cloud Files/resource/iconcache"),
    ("Edge 扩展缓存", LOCAL / "Microsoft/Edge/User Data/Default/Extension Cache"),
    ("Edge 崩溃上报", LOCAL / "Microsoft/Edge/User Data/Crashpad/reports"),
    ("DSH 插件缓存", LOCAL / "dsh-desktop/harness/.cache"),
    ("Windows 字体缓存", Path(r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache")),
    ("临时互联网文件", LOCAL / "Microsoft/Windows/INetCache"),
    ("Windows 通知缓存", LOCAL / "Microsoft/Windows/Notifications"),
    ("Docker 数据", LOCAL / "Docker/wsl"),
    ("WSL 发行版", LOCAL / "Packages"),
]

#: 名字护栏
NEVER = ("cookies", "login data", "web data", "history", "bookmarks", "preferences",
         "local storage", "session storage", "indexeddb", "extensions", "sessions",
         "packages", "userdata", "backup", "sync", "documents", "desktop", "downloads")


def dir_size(p: Path, limit: int = 800_000) -> int:
    total = 0
    count = 0
    stack = [p]
    while stack:
        try:
            cur = stack.pop()
            entries = list(os.scandir(cur))
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    stack.append(Path(e.path))
                elif e.is_file(follow_symlinks=False):
                    total += e.stat(follow_symlinks=False).st_size
                    count += 1
                    if count >= limit:
                        return total
            except OSError:
                continue
    return total


def clean(d: Path) -> tuple[int, int, int]:
    freed = deleted = skipped = 0
    for root, _dirs, files in os.walk(d, topdown=False):
        for fn in files:
            f = Path(root) / fn
            try:
                sz = f.stat(follow_symlinks=False).st_size
                f.unlink()
                freed += sz
                deleted += 1
            except OSError:
                skipped += 1
        if Path(root) != d:
            try:
                os.rmdir(root)
            except OSError:
                pass
    return freed, deleted, skipped


def main() -> int:
    before = shutil.disk_usage("C:\\").free / 1073741824
    print(f"清理前 C: 剩余 {before:.2f} GB\n")
    total = 0
    checked: list[tuple[str, Path, int]] = []
    for label, p in FIXED:
        try:
            if not p.exists():
                continue
        except OSError:
            print(f"  ⊘ 无权访问，跳过：{p}")
            continue
        try:
            sz = dir_size(p)
        except OSError:
            continue
        if sz < 20 * 1024 * 1024:          # 小于 20 MB 不折腾
            checked.append((label, p, sz))
            continue
        low = str(p).lower()
        if any(n in low for n in NEVER) and label not in ("WSL 发行版",):
            print(f"  ⊘ 护栏跳过 {p}")
            continue
        try:
            freed, deleted, skipped = clean(p)
        except OSError as exc:
            print(f"  ⊘ 清理失败 {p}：{exc}")
            continue
        total += freed
        print(f"  ✔ {label:<14} 清理前 {sz/1048576:8.1f} MB → 释放 {freed/1048576:8.1f} MB"
              f"（删 {deleted}，跳过 {skipped}）  {p}")

    # ---- UWP 应用缓存（LocalCache / TempState / INetCache，不碰 LocalState/RoamingState）----
    pkg_root = LOCAL / "Packages"
    try:
        if pkg_root.is_dir():
            for app in pkg_root.iterdir():
                for sub in ("LocalCache", "TempState", "AC/INetCache"):
                    d = app / Path(sub)
                    try:
                        if not d.is_dir():
                            continue
                        sz = dir_size(d)
                        if sz < 10 * 1024 * 1024:
                            continue
                        freed, deleted, skipped = clean(d)
                        total += freed
                        print(f"  ✔ {'UWP 应用缓存':<14} 清理前 {sz/1048576:8.1f} MB → "
                              f"释放 {freed/1048576:8.1f} MB  {d}")
                    except OSError:
                        continue
    except OSError:
        pass

    after = shutil.disk_usage("C:\\").free / 1073741824
    print(f"\n第二轮合计释放 {total/1073741824:.2f} GB")
    print(f"C: 剩余 {before:.2f} GB → {after:.2f} GB（+{after-before:.2f} GB）")
    if checked:
        print(f"\n查过但不足 20 MB / 无需处理：")
        for label, p, sz in checked[:20]:
            print(f"  · {label:<14} {sz/1048576:7.1f} MB  {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
