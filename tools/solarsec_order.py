# -*- coding: utf-8 -*-
"""① 算 G 的真实阶   ② 在 dumped 内存里搜 CryptoPP::Integer 二进制编码的公钥/私钥"""
import struct
from pathlib import Path

P = 0xe2e20e64347abef0fef83d1a5901
A = 0x592a5290d72d5d58c73266dc96b2
B = 0x630e734697aa226547d498f14e5b
G = (0x881fb0676400f362aac2b6ae22e6, 0x5ceeaeea8ed10a70ee90737c9efb)
N = 0xe2e20e64347abea8720594c31783


def inv(x, m): return pow(x, -1, m)


def add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def mul(k, pt):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r


print("=== 试 G 的真实阶（N 的因子组合） ===")
for f in (2, 23, 347, 23 * 347, N // 23, N // 347, N // (23 * 347), N):
    try:
        r = mul(f, G)
        print(f"  {f:<28} *G = {'O (是阶!)' if r is None else '非 O'}")
    except Exception as e:
        print(f"  {f} 出错 {e}")

print("\n=== 曲线点数（粗略上界：p+1+2√p）===")
import math
print(f"  p+1 ≈ {P+1}")
print(f"  Hasse 区间 ≈ [{P+1-2*int(math.isqrt(P))}, {P+1+2*int(math.isqrt(P))}]")

# ---- CryptoPP::Integer 编码：32-bit 小端 word 数组 ----
def cp_int_enc(v: int) -> bytes:
    """CryptoPP Integer 存为 32 位小端 word 数组（无前导零 word）。"""
    words = []
    while v:
        words.append(v & 0xFFFFFFFF)
        v >>= 32
    return b"".join(struct.pack("<I", w) for w in words)


BASE = Path(r"E:\附件原件\solar应急响应\solarsec_202603")
FS = (P.bit_length() + 7) // 8

print("\n=== 在 dumped 内存里搜二进制编码的候选值 ===")
targets = {}
# 密文里的 R（临时公钥）
R = (0x379f281c551556125a391fda096b, 0x79f6223b4cbc4d91b72a79be1f31)
for nm, val in (("R.x", R[0]), ("R.y", R[1]), ("Gx", G[0]), ("Gy", G[1]),
                ("N", N), ("p", P), ("a", A), ("b", B)):
    for fmt, enc in (("LE32words", cp_int_enc(val)),
                     ("BE-fixed14", val.to_bytes(FS, "big")),
                     ("LE-fixed14", val.to_bytes(FS, "little")),
                     ("BE-nopad", val.to_bytes((val.bit_length() + 7) // 8, "big")),
                     ("LE-nopad", val.to_bytes((val.bit_length() + 7) // 8, "little"))):
        targets[f"{nm}/{fmt}"] = enc

for p in sorted(BASE.glob("dumped_4053_*.bin")):
    blob = p.read_bytes()
    hits = [(k, v) for k, v in targets.items() if v in blob]
    print(f"  {p.name} ({len(blob):,} B) → {len(hits)} 个命中")
    for k, v in hits:
        print(f"      ✔ {k}")

# 也搜整个大 ELF（命令行可能以字面量形式存在）
big = (BASE / "03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5").read_bytes()
hits = [(k, v) for k, v in targets.items() if v in big]
print(f"  15MB ELF → {len(hits)} 个命中")
for k, v in hits:
    print(f"      ✔ {k}")

# ---- 明文 flag 的线索：flag.solarsec 原文不在，但也许内存里有 ----
print("\n=== 在 dumped 内存里找疑似 flag 明文 ===")
import re
for p in sorted(BASE.glob("dumped_4053_*.bin")):
    blob = p.read_bytes()
    for pat in (rb"[ -~]{8,120}", ):
        for m in re.finditer(pat, blob):
            s = m.group().decode("latin1")
            if re.search(r"(?i)(flag|solar|key|\{.*\}|LOCKED)", s) and len(s) < 130:
                print(f"  [{p.name[16:30]}] {s!r}")
