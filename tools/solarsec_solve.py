# -*- coding: utf-8 -*-
"""完整 EC 实现 + 攻击准备：
   1. 确认参数与阶
   2. 分解 N（Pohlig-Hellman 可行性）
   3. 解析 ECIES 密文结构（R || masked || MAC）
   4. 找 Q（命令行参数）——从 dumped 内存 + ELF .rodata/+ 也许题目说明
"""
import struct
from pathlib import Path

P = 0xe2e20e64347abef0fef83d1a5901
A = 0x592a5290d72d5d58c73266dc96b2
B = 0x630e734697aa226547d498f14e5b
GX = 0x881fb0676400f362aac2b6ae22e6
GY = 0x5ceeaeea8ed10a70ee90737c9efb
N = 0xe2e20e64347abea8720594c31783
FS = (P.bit_length() + 7) // 8
print(f"域元素字节数 FS={FS}")


def inv(x, m):
    return pow(x, -1, m)


def add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if x1 == x2 and y1 == y2:
        lam = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


def on_curve(x, y):
    return (y * y - x * x * x - A * x - B) % P == 0


print(f"G 在曲线上: {on_curve(GX, GY)}")
print(f"2G = {mul(2, (GX, GY))[0]:x} …")

# ---- 阶验证 ----
print("\n=== 阶验证 ===")
ord_g = None
# 用 N 试算：若 N*G == O 则 N 是阶的倍数
NG = mul(N, (GX, GY))
print(f"N*G == O : {NG is None}")
# 试 N 的小因子组合
x = N
facs = {}
d = 2
tmp = x
while d < 100000 and tmp > 1:
    while tmp % d == 0:
        facs[d] = facs.get(d, 0) + 1
        tmp //= d
    d += 1
print(f"N 的小因子分解（试除到 1e5）: {facs}")
print(f"N 的剩余部分 = {tmp}  ({tmp.bit_length()} bit)")

# ---- 密文结构 ----
BASE = Path(r"E:\附件原件\solar应急响应\solarsec_202603")
data = (BASE / "flag.solarsec.locked").read_bytes()
plen = struct.unpack_from("<Q", data, 6)[0]
ct = data[14:]
print(f"\n=== ECIES 密文 ===  明文 {plen} B，密文 {len(ct)} B")
print(f"tag = {ct[0]:#04x}（未压缩点应为 0x04）")
R = (int.from_bytes(ct[1:1 + FS], "big"), int.from_bytes(ct[1 + FS:1 + 2 * FS], "big"))
print(f"临时公钥 R = (0x{R[0]:x}, 0x{R[1]:x})")
print(f"R 在曲线上: {on_curve(*R)}")
print(f"R == G ? {R == (GX, GY)}")
body = ct[1 + 2 * FS:]
MAC = 20
masked, mac = body[:plen], body[plen:]
print(f"掩码密文 {len(masked)} B（应等于明文 {plen}）")
print(f"MAC(HMAC-SHA1) {len(mac)} B: {mac.hex()}")
print(f"掩码密文前 48B: {masked[:48].hex(' ')}")

# ---- 找 Q：命令行参数 ----
print("\n=== 找公钥 Q（argv1/argv2，形如 0x…） ===")
import re
pat = re.compile(rb"(0x[0-9a-fA-F]{20,60})")
for p in sorted(BASE.glob("dumped_4053_*.bin")):
    blob = p.read_bytes()
    for m in pat.finditer(blob):
        try:
            v = int(m.group(1).decode(), 16)
        except ValueError:
            continue
        if v < P and on_curve(v, 0) is False and v.bit_length() >= 100:
            print(f"  {p.name}: {m.group(1).decode()}")

# 也从整个 ELF 找以 "0x" 开头且 < P 的串（.rodata）
big = (BASE / "03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5").read_bytes()
seen = set()
for m in pat.finditer(big):
    s = m.group(1).decode()
    v = int(s, 16)
    if P > v > (1 << 80) and s.lower() not in seen:
        seen.add(s.lower())
print(f"ELF 中 81~111 bit 的 0x… 串 {len(seen)} 个（前 15）：")
for s in list(seen)[:15]:
    print(f"   {s}")
