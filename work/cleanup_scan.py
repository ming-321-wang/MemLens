"""
C 盘缓存清理 · 扫描与分类（只读，不删任何东西）

分类原则：
  SAFE  = 可再生成的缓存 / 日志 / 临时文件（删了不影响系统与使用）
  KEEP  = 用户数据 / 配置 / 凭据 / 会话（绝不能碰）

用法：python cleanup_scan.py
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

USER = Path.home()
LOCAL = Path(os.environ.get("LOCALAPPDATA", USER / "AppData/Local"))
ROAMING = Path(os.environ.get("APPDATA", USER / "AppData/Roaming"))

# ---- 安全可删：Edge / Chromium 系缓存（白名单目录名，绝不整目录删 User Data）----
EDGE_CACHE_NAMES = (
    "Cache", "Code Cache", "GPUCache", "ShaderCache", "GrShaderCache",
    "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "Cache_Data",
    "component_crx_cache", "extensions_crx_cache", "Network Predictor",
    "Network Persistent State",  # 仅目录形式存在时另判
)

# ---- 目录名里带这些词、且**不是**用户数据的 → 视为缓存（白名单）----
CACHE_DIR_NAMES = (
    "cache", "caches", "cache2", "code cache", "gpucache", "shadercache",
    "crashpad", "crash dumps", "crashdumps", "temp", "tmp", "log", "logs",
    "dump", "dumps", "thumbcache", "inetcache", "webcache", "gpu cache",
    "cef_cache", "cef_cache_data", "installer", "setup", "update", "updates",
    "downloads_temp", "crash_reporter", "diagnostics", "blob_storage",
)

# ---- 明确禁止触碰的目录名（哪怕名字里含 cache/log）----
FORBIDDEN = (
    "cookies", "login data", "web data", "history", "bookmarks", "preferences",
    "local storage", "session storage", "indexeddb", "extensions",
    "sessions", "sessions_*", "profile*", "user data", "default",
    "documents", "desktop", "downloads", "pictures", "videos", "music",
    "wps cloud", "backup", "roaming", "sync", "wpsdoc", "autorecovery",
    "personal", "template", "templates", "customization", "accounts",
)


def dir_size(p: Path, limit: int = 400_000) -> tuple[int, int]:
    """(字节, 文件数)；带文件数上限，避免超大目录卡死。"""
    total = 0
    count = 0
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
                    try:
                        total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
                    count += 1
                    if count >= limit:
                        return total, count
            except OSError:
                continue
    return total, count


def classify(name: str) -> str:
    low = name.lower()
    for bad in FORBIDDEN:
        if low == bad or low.startswith(bad):
            return "KEEP"
    return "SAFE"


def walk_roots(roots: list[tuple[str, Path]], depth: int = 4) -> list[dict]:
    """在给定根下找深度 <= depth 的、名字像缓存的目录。"""
    out: list[dict] = []
    seen: set[str] = set()
    for label, root in roots:
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        stack = [(root, 0)]
        while stack:
            cur, d = stack.pop()
            if d >= depth:
                continue
            try:
                entries = list(os.scandir(cur))
            except OSError:
                continue
            for e in entries:
                try:
                    if not e.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                sub = Path(e.path)
                key = str(sub).lower()
                if key in seen:
                    continue
                seen.add(key)
                nm = e.name
                if classify(nm) == "SAFE" and any(
                        nm.lower() == c or c in nm.lower() for c in CACHE_DIR_NAMES):
                    sz, cnt = dir_size(sub)
                    if sz > 0:
                        out.append({"label": label, "path": str(sub), "mb": sz / 1048576,
                                    "files": cnt})
                    continue                      # 缓存目录里不再下钻
                if d + 1 < depth:
                    stack.append((sub, d + 1))
    return out


def main() -> int:
    targets: list[dict] = []

    # ① Edge / Chromium 用户数据下的缓存
    edge_roots = []
    for base in (LOCAL / "Microsoft/Edge/User Data", ROAMING / "Microsoft/Edge/User Data"):
        if base.is_dir():
            edge_roots.append(("Edge", base))
    targets += walk_roots(edge_roots, depth=3)

    # ② WPS / 金山
    wps_roots = []
    for p in (ROAMING / "kingsoft", LOCAL / "Kingsoft", LOCAL / "kingsoft",
              ROAMING / "kingsoft/office6", LOCAL / "Temp"):
        if p.is_dir():
            wps_roots.append(("WPS", p))
    targets += walk_roots(wps_roots, depth=4)

    # ③ 其它浏览器
    other_roots = []
    for p in (LOCAL / "Google/Chrome/User Data", LOCAL / "Mozilla/Firefox/Profiles",
              LOCAL / "Microsoft/Edge/Application"):
        if p.is_dir():
            other_roots.append(("其他浏览器", p))
    targets += walk_roots(other_roots, depth=3)

    # ④ 明确的系统/应用临时与日志目录（白名单，不猜）
    fixed = [
        ("系统临时", Path(os.environ.get("TEMP", LOCAL / "Temp"))),
        ("系统临时", Path(r"C:\Windows\Temp")),
        ("崩溃转储", LOCAL / "CrashDumps"),
        ("错误报告", Path(r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive")),
        ("错误报告", Path(r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue")),
        ("更新缓存", Path(r"C:\Windows\SoftwareDistribution\Download")),
        ("pip 缓存", LOCAL / "pip/Cache"),
        ("npm 缓存", LOCAL / "npm-cache"),
        ("缩略图", LOCAL / "Microsoft/Windows/Explorer"),
    ]
    for label, p in fixed:
        if p.is_dir():
            if label == "缩略图":
                for f in p.glob("thumbcache_*.db"):
                    try:
                        sz = f.stat().st_size
                        if sz > 0:
                            targets.append({"label": label, "path": str(f),
                                            "mb": sz / 1048576, "files": 1})
                    except OSError:
                        pass
                continue
            sz, cnt = dir_size(p)
            if sz > 0:
                targets.append({"label": label, "path": str(p), "mb": sz / 1048576,
                                "files": cnt})

    targets.sort(key=lambda x: -x["mb"])
    total = sum(t["mb"] for t in targets)
    print(f"候选缓存目录 {len(targets)} 个，合计 {total/1024:.2f} GB\n")
    by_label: dict[str, float] = {}
    for t in targets:
        by_label[t["label"]] = by_label.get(t["label"], 0) + t["mb"]
    print("== 按类合计 ==")
    for k, v in sorted(by_label.items(), key=lambda kv: -kv[1]):
        print(f"  {k:<10} {v/1024:8.2f} GB")
    print("\n== 明细（前 60）==")
    for t in targets[:60]:
        print(f"  [{t['label']}] {t['mb']/1024:7.2f} GB  {t['files']:>7} 文件  {t['path']}")
    out = Path(__file__).with_name("cleanup_plan.json")
    out.write_text(json.dumps(targets, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n完整清单 → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
