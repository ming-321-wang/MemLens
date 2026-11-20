"""
C 盘缓存清理 · 执行器（只删缓存内容，不动配置/用户数据/环境变量）

安全护栏（删除前二次校验）：
  1. 目标路径的**最后一段**必须命中缓存类名，否则跳过；
  2. 最后一段若落在"绝不能删"名单（Cookies/Login Data/History/…）→ 跳过；
  3. 只删**目录里的内容**，保留目录本身（应用期望目录存在）；
  4. 被占用的文件（浏览器/WPS 正在运行）自动跳过；
  5. 系统临时目录（%TEMP%）只删**2 天前**的条目，避免打断正在进行的安装/编辑。
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

PLAN = Path(__file__).with_name("cleanup_plan.json")

#: 最后一段必须像缓存（大小写不敏感）
CACHE_LIKE = (
    "cache", "cache2", "caches", "code cache", "gpucache", "shadercache",
    "grshadercache", "dawncache", "dawngraphitecache", "dawnwebgpucache",
    "cachestorage", "scriptcache", "component_crx_cache", "crashpad",
    "cachedata", "logs", "log", "iconcache", "clscache", "temp", "tmp",
    "thumbcache", "onlinetemplates", "startupcache", "workbuddy-update",
    "download", "reportarchive", "reportqueue",
)
#: 绝对不碰
NEVER = (
    "cookies", "login data", "web data", "history", "bookmarks", "preferences",
    "local storage", "session storage", "indexeddb", "extensions", "sessions",
    "backup", "sync", "user data", "profile", "default", "documents",
    "desktop", "downloads", "wps cloud files", "autorecovery", "templates",
    "personal", "accounts", "customization", "dictionary", "databases",
)


def ok_target(path: Path) -> tuple[bool, str]:
    name = path.name.lower()
    if name in NEVER or any(name.startswith(n + " ") for n in NEVER):
        return False, "命中禁删名单"
    if not any(name == c or c in name for c in CACHE_LIKE):
        return False, "名字不像缓存"
    return True, ""


def rm_file(p: Path) -> tuple[int, bool]:
    try:
        sz = p.stat().st_size
    except OSError:
        sz = 0
    try:
        p.unlink()
        return sz, True
    except (OSError, PermissionError):
        return 0, False


def clean_dir(d: Path, min_age_days: float = 0.0) -> tuple[int, int, int]:
    """返回(释放字节, 删除数, 跳过数)。只删内容，保留目录。"""
    freed = deleted = skipped = 0
    cutoff = time.time() - min_age_days * 86400 if min_age_days > 0 else 0.0
    for root, dirs, files in os.walk(d, topdown=False):
        for fn in files:
            f = Path(root) / fn
            if cutoff:
                try:
                    if f.stat().st_mtime > cutoff:
                        skipped += 1
                        continue
                except OSError:
                    skipped += 1
                    continue
            sz, done = rm_file(f)
            if done:
                freed += sz
                deleted += 1
            else:
                skipped += 1
        # 清空子目录（保留最外层目录骨架）
        if Path(root) != d:
            try:
                os.rmdir(root)
            except OSError:
                pass
    return freed, deleted, skipped


def main() -> int:
    if not PLAN.is_file():
        print("找不到清理计划，先跑 cleanup_scan.py")
        return 1
    plan = json.loads(PLAN.read_text(encoding="utf-8"))

    def free_gb() -> float:
        import shutil as sh
        return sh.disk_usage("C:\\").free / 1073741824

    before = free_gb()
    print(f"清理前 C: 剩余 {before:.2f} GB\n")
    total_freed = 0
    total_del = 0
    total_skip = 0
    blocked: list[str] = []
    for item in plan:
        p = Path(item["path"])
        if not p.exists():
            continue
        good, why = ok_target(p)
        if not good:
            blocked.append(f"{p}  ({why})")
            continue
        # 系统临时根目录：只删 2 天前的
        age = 2.0 if p.name.lower() == "temp" and str(p).lower().endswith("appdata\\local\\temp") else 0.0
        if p.is_file():
            sz, done = rm_file(p)
            if done:
                total_freed += sz
                total_del += 1
            else:
                total_skip += 1
            continue
        try:
            freed, deleted, skipped = clean_dir(p, age)
        except OSError as exc:
            blocked.append(f"{p}  (读取失败 {exc})")
            continue
        total_freed += freed
        total_del += deleted
        total_skip += skipped
        print(f"  ✔ {item['label']:<8} {freed/1048576:8.1f} MB  删除 {deleted:>6}  跳过 {skipped:>5}  {p}")

    after = free_gb()
    print(f"\n合计释放 {total_freed/1073741824:.2f} GB，删除 {total_del} 个文件，"
          f"跳过（被占用/保护）{total_skip} 个")
    print(f"C: 剩余 {before:.2f} GB → {after:.2f} GB（+{(after-before):.2f} GB）")
    if blocked:
        print(f"\n因护栏跳过 {len(blocked)} 项：")
        for b in blocked[:15]:
            print("  · " + b)
    return 0


if __name__ == "__main__":
    sys.exit(main())
