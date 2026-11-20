# -*- coding: utf-8 -*-
"""① 从 dumped_4053_* 内存里找命令行参数（公钥 Q 的坐标 0x...）
   ② 用标准库手算椭圆曲线，验证 G/Q/N，估计 ECDLP 难度。"""
import re
from pathlib import Path

BASE = Path(r"E:\附件原件\solar应急响应\solarsec_202603")

A = 0xe2e20e64347abef0fef83d1a5901
B = 0xe2e20e64347abea8720594c31783
P = 0x592a5290d72d5d58c73266dc96b2
GX = 0x630e734697aa226547d498f14e5b
GY = 0x881fb0676400f362aac2b6ae22e6
N = 0x5ceeaeea8ed10a70ee90737c9efb

print("=== 曲线参数 ===")
for name, v in (("a", A), ("b", B), ("p", P), ("Gx", GX), ("Gy", GY), ("N", N)):
    print(f"  {name} = 0x{v:x}  ({v.bit_length()} bit)")

# ---- 验证 G 在曲线上 ----
def on_curve(x, y, p, a, b):
    return (y * y - x * x * x - a * x - b) % p == 0

print(f"\nG 在曲线上: {on_curve(GX, GY, P, A, B)}")

# ---- 从 dumped 内存里找 0x 形式的命令行参数 ----
print("\n=== 在 dumped_4053_*.bin 里搜 14 位十六进制（候选公钥坐标）===")
pat = re.compile(rb"0x[0-9a-fA-F]{10,60}\b")
found = {}
for p in sorted(BASE.glob("dumped_4053_*.bin")):
    blob = p.read_bytes()
    for m in pat.finditer(blob):
        s = m.group().decode()
        if s.lower() not in found:
            found[s.lower()] = p.name
print(f"共 {len(found)} 个不同的 0x… 串（前 30）")
for s, f in list(found.items())[:30]:
    v = int(s, 16)
    print(f"  {s:<44} ({v.bit_length():>3}bit)  ← {f}")
    if 0 < v < P and on_curve(v, 0, P, A, B) if False else False:
        pass

# ---- 主 ELF 里是否也藏了公钥 ----
print("\n=== 在 15MB ELF 里搜候选公钥坐标 ===")
big = BASE / "03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5"
blob = big.read_bytes()
cands = {}
for m in pat.finditer(blob):
    s = m.group().decode()
    v = int(s, 16)
    if 56 <= v.bit_length() <= 60 and v < P:
        cands[s.lower()] = cands.get(s.lower(), 0) + 1
print(f"56-60bit 的 0x… 串共 {len(cands)} 个：")
for s, c in list(cands.items())[:20]:
    print(f"  {s}  ×{c}")

# ---- flag.solarsec.locked 的结构 ----
print("\n=== flag.solarsec.locked 结构 ===")
data = (BASE / "flag.solarsec.locked").read_bytes()
print(f"  总长 {len(data)}")
print(f"  头 6B = {data[:6]!r}")
import struct
plen = struct.unpack_from("<Q", data, 6)[0]
print(f"  明文长度(小端 u64 @6) = {plen}")
ct = data[14:]
print(f"  密文长度 = {len(ct)}")
print(f"  密文首 32B = {ct[:32].hex(' ')}")
print(f"  密文末 32B = {ct[-32:].hex(' ')}")
print(f"  明文 {plen} 字节 vs 密文 {len(ct)} 字节 → 膨胀 {len(ct) - plen}")
