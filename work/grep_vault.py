"""
从 MemProcFS 收获目录里快速搜 vault/密码/flag 线索（纯标准库，快）。

用法：python grep_vault.py <harvest_dir> [关键字正则]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

DEFAULT_PAT = r"(?i)(flag\{|ctf\{|password|passwd|vault|secret|credential|personalvault|bitlocker)"

TEXT_EXT = (".txt", ".csv", ".json", ".log")


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else r"D:\MemLens\work\mp")
    pat = re.compile((argv[2] if len(argv) > 2 else DEFAULT_PAT).encode())
    hits: list[tuple[str, str, str]] = []
    scanned = 0
    total_bytes = 0
    for p in sorted(root.rglob("*")):
        try:
            if not p.is_file() or p.suffix.lower() not in TEXT_EXT:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        scanned += 1
        total_bytes += len(data)
        for m in pat.finditer(data):
            s = max(0, m.start() - 110)
            e = min(len(data), m.end() + 180)
            ctx = data[s:e].decode("utf-8", "replace").replace("\r", " ").replace("\n", " ")
            hits.append((p.relative_to(root).as_posix(), m.group(0).decode("utf-8", "replace"), ctx))
            if len(hits) >= 500:
                break
        if len(hits) >= 500:
            break
    print(f"扫描 {scanned} 个文本文件（{total_bytes/1048576:.1f} MB），命中 {len(hits)} 处")
    seen: set[str] = set()
    shown = 0
    for name, kw, ctx in hits:
        key = ctx[:120]
        if key in seen:
            continue
        seen.add(key)
        shown += 1
        print(f"\n[{name}] 命中 {kw!r}\n  {ctx[:300]}")
        if shown >= 40:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
