# -*- coding: utf-8 -*-
"""修正参数映射后重验；并尝试从内存/命令行找真正的 Q。"""
import struct
from pathlib import Path

# IDA: ECP(&ec, &v10, &v12, &v13) → ECP(p, a, b)
P = 0x592a5290d72d5d58c73266dc96b2   # v12 模数
A = 0xe2e20e64347abef0fef83d1a5901   # v10  a
B = 0x630e734697aa226547d498f14e5b   # v13  b
GX = 0x881fb0676400f362aac2b6ae22e6   # v14
GY = 0x5ceeaeea8ed10a70ee90737c9efb   # v15
N = 0xe2e20e64347abea8720594c31783    # v11 = n（ECP 的 order）

for k, v in (("p", P), ("a", A), ("b", B), ("Gx", GX), ("Gy", GY), ("N", N)):
    print(f"  {k:<3} = 0x{v:x}  ({v.bit_length()} bit)")

def on_curve(x, y):
    return (y * y - x * x * x - A * x - B) % P == 0

print(f"\nG 在曲线上: {on_curve(GX, GY)}")
print(f"G ≠ O:      {(GX, GY) != (0, 0)}")

# 密文结构
BASE = Path(r"E:\附件原件\solar应急响应\solarsec_202603")
data = (BASE / "flag.solarsec.locked").read_bytes()
plen = struct.unpack_from("<Q", data, 6)[0]
ct = data[14:]
GELEM = 1 + len(P.to_bytes(8, "big")) * 2     # 未压缩点: 0x04 || X || Y
MAC = 20
print(f"\n明文 {plen} B / 密文 {len(ct)} B")
print(f"若 密文 = EC点({GELEM}B) + 掩码密文 + HMAC-SHA1({MAC}B) → 掩码密文应为 "
      f"{plen - 0}，总 {(plen + GELEM + MAC)} B")
print(f"实测密文 {len(ct)} B，差 {len(ct) - (plen + GELEM + MAC)} B")
print(f"密文首字节 0x{ct[0]:02x}（ECIES 未压缩点应为 0x04）")
print(f"密文头 {GELEM} B: {ct[:GELEM].hex(' ')}")
print(f"密文尾 {MAC} B （疑似 MAC）: {ct[-MAC:].hex(' ')}")
print(f"中间段长度 {len(ct) - GELEM - MAC} B")

# 尝试解析 EC 点（k*G，k 未知，但点本身给出去了 —— 这正好是 ECIES 的临时公钥）
def field_size(p):
    return (p.bit_length() + 7) // 8
FS = field_size(P)
print(f"\n域元素字节数 = {FS}")
pt = ct[1:1 + 2 * FS]
X = int.from_bytes(ct[1:1 + FS], "big")
Y = int.from_bytes(ct[1 + FS:1 + 2 * FS], "big")
print(f"解析到的临时公钥点: X=0x{X:x}  Y=0x{Y:x}")
print(f"该点在曲线上: {on_curve(X, Y)}")
print(f"该点 == G ? {(X, Y) == (GX, GY)}")

masked = ct[1 + 2 * FS:-MAC]
mac = ct[-MAC:]
print(f"掩码后的密文长度 = {len(masked)}  （明文应为 {plen}）")
print(f"掩码密文前 32B: {masked[:32].hex(' ')}")
print(f"MAC: {mac.hex(' ')}")
