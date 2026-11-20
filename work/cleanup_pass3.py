"""
C 盘第三轮：只删"下载好的安装包 / 旧版本 / 纯缓存"（可再下载，不影响使用）。

执行内容：
  A. 各软件自动更新器目录里的安装包（13 个 *-updater）
  B. C:\\DrvPath 的驱动安装包（.exe/.7z/.zip）
  C. 百度网盘安装包 BaiduNetdisk.zip
  D. Edge 侧边栏 AI 模型 quant.ort（335 MB，会自动重下）
  E. 剪映旧版本 8.6.0（当前在用 8.9.0）
  F. %TEMP% 里 2 天前的文件
不动：pagefile.sys / WinSxS / Windows\\Installer / ProgramData\\Package Cache /
      WPS(kingsoft) / Tencent / Documents / Desktop / 任何用户数据目录。
"""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

LOCAL = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
ROAMING = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))

freed = 0
deleted = 0
skipped = 0
log: list[str] = []


def rm(p: Path) -> int:
    """删文件/目录，返回释放字节；失败返回 0。"""
    global freed, deleted, skipped
    try:
        if p.is_dir(follow_symlinks=False):
            sz = 0
            for r, _d, fs in os.walk(p, topdown=False):
                for n in fs:
                    try:
                        sz += os.path.getsize(os.path.join(r, n))
                        os.unlink(os.path.join(r, n))
                        deleted += 1
                    except OSError:
                        skipped += 1
                if Path(r) != p:
                    try:
                        os.rmdir(r)
                    except OSError:
                        pass
            try:
                os.rmdir(p)
            except OSError:
                pass
            freed += sz
            return sz
        sz = p.stat(follow_symlinks=False).st_size
        p.unlink()
        freed += sz
        deleted += 1
        return sz
    except OSError:
        skipped += 1
        return 0


def main() -> int:
    before = shutil.disk_usage("C:\\").free
    print(f"清理前 C: 空闲 {before/1073741824:.2f} GB\n")

    # A. updater 安装包
    for d in sorted(LOCAL.glob("*updater*")) + sorted(LOCAL.glob("QuarkUpdater")):
        if not d.is_dir():
            continue
        got = 0
        for f in d.iterdir():
            if f.is_file() and f.suffix.lower() in (".exe", ".zip", ".7z", ".msi"):
                got += rm(f)
        if got:
            print(f"  ✔ 更新器安装包 释放 {got/1048576:8.1f} MB  {d.name}")

    # B. DrvPath
    drv = Path(r"C:\DrvPath")
    if drv.is_dir():
        got = 0
        for f in list(drv.iterdir()):
            if f.is_file() and f.suffix.lower() in (".exe", ".7z", ".zip", ".msi"):
                got += rm(f)
        if got:
            print(f"  ✔ 驱动安装包   释放 {got/1048576:8.1f} MB  C:\\DrvPath")

    # C. 百度网盘安装包
    for p in (ROAMING / "baidu/BaiduNetdisk.zip", ROAMING / "baidu/BaiduNetdisk.exe"):
        if p.is_file():
            got = rm(p)
            if got:
                print(f"  ✔ 百度网盘安装包 释放 {got/1048576:8.1f} MB  {p.name}")

    # D. Edge 侧边栏 AI 模型
    for p in LOCAL.glob("Microsoft/Edge.jiu/User Data/ProvenanceData/**/*.ort"):
        got = rm(p)
        if got:
            print(f"  ✔ Edge 侧边栏 AI 模型 释放 {got/1048576:8.1f} MB  {p.name}")

    # E. 剪映旧版本（保留 8.9.0）
    jy = LOCAL / "JianyingPro/Apps"
    if jy.is_dir():
        vers = [v for v in jy.iterdir() if v.is_dir()]
        if len(vers) > 1:
            newest = max(vers, key=lambda v: v.stat().st_mtime)
            for v in vers:
                if v == newest:
                    continue
                got = rm(v)
                if got:
                    print(f"  ✔ 剪映旧版本 {v.name} 释放 {got/1043741824:.2f} GB"
                          f"（保留 {newest.name}）")

    # F. Temp 里 2 天前的
    tmp = Path(os.environ.get("TEMP", LOCAL / "Temp"))
    cutoff = time.time() - 2 * 86400
    got = 0
    for root, _d, fs in os.walk(tmp, topdown=False):
        for n in fs:
            f = Path(root) / n
            try:
                if f.stat(follow_symlinks=False).st_mtime > cutoff:
                    continue
            except OSError:
                continue
            got += rm(f)
    if got:
        print(f"  ✔ 系统临时(>2天) 释放 {got/1048576:8.1f} MB")

    after = shutil.disk_usage("C:\\").free
    print(f"\n合计释放 {freed/1073741824:.2f} GB（删 {deleted} 项，跳过 {skipped} 项）")
    print(f"C: 空闲 {before/1073741824:.2f} GB → {after/1073741824:.2f} GB"
          f"（+{(after-before)/1073741824:.2f} GB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
