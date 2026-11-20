# -*- coding: utf-8 -*-
"""第一轮取证：读 USD.c 源码 + 在 dumped region 与大 ELF 中搜 flag 模式。

铁律：**只读原件，所有产物写工作区**。
"""
import re
from pathlib import Path

BASE = Path(r"E:\附件原件\solar应急响应\solarsec_202603")
OUT = Path(r"D:\DSH\工作区\MemLens\work\solarsec")
OUT.mkdir(parents=True, exist_ok=True)

# ---------- 1. USD.c 源码 ----------
src = (BASE / "USD.c")
if src.exists():
    text = src.read_text(encoding="utf-8", errors="replace")
    (OUT / "USD.c.copy.txt").write_text(text, encoding="utf-8")
    print("=" * 70)
    print("USD.c 源码（%d 字节）:" % len(text))
    print(text[:3000])
    print("…" if len(text) > 3000 else "")

# ---------- 2. flag.solarsec.locked ----------
lk = BASE / "flag.solarsec.locked"
if lk.exists():
    data = lk.read_bytes()
    print("=" * 70)
    print(f"flag.solarsec.locked（{len(data)} 字节）")
    print("hex :", data[:64].hex(" "))
    print("repr:", repr(data[:120]))
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    print("可打印:", printable[:200])
    (OUT / "flag_locked.bin").write_bytes(data)

# ---------- 3. 在 dumped region 里搜 flag ----------
PATTERNS = [
    rb"flag\{[^}]{1,120}\}",
    rb"FLAG\{[^}]{1,120}\}",
    rb"solarsec\{[^}]{1,120}\}",
    rb"SOLARSEC\{[^}]{1,120}\}",
    rb"flag\[[^\]]{1,120}\]",
    rb"flag[:=][ -~]{4,120}",
    rb"[A-Za-z0-9_]*flag[A-Za-z0-9_]*",
]
print("=" * 70)
print("扫描 dumped_4053_*.bin 中的 flag 模式：")
for p in sorted(BASE.glob("dumped_4053_*.bin")):
    blob = p.read_bytes()
    hits = []
    for pat in PATTERNS[:4]:
        for m in re.finditer(pat, blob):
            try:
                s = m.group().decode("ascii")
            except UnicodeDecodeError:
                continue
            if len(s) >= 6 and s not in hits:
                hits.append(s)
    print(f"  {p.name}  ({len(blob):,} 字节)  → {len(hits)} 命中")
    for h in hits[:12]:
        print(f"      {h!r}")

# ---------- 4. 大 ELF 与 USD 里的 flag ----------
print("=" * 70)
for name in ("USD", "03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5"):
    p = BASE / name
    if not p.exists():
        continue
    blob = p.read_bytes()
    hits = []
    for pat in PATTERNS[:4]:
        for m in re.finditer(pat, blob):
            try:
                s = m.group().decode("ascii")
            except UnicodeDecodeError:
                continue
            if len(s) >= 6 and s not in hits:
                hits.append(s)
    print(f"  {name}  ({len(blob):,} 字节)  → {len(hits)} 命中")
    for h in hits[:12]:
        print(f"      {h!r}")
