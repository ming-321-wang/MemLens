# -*- coding: utf-8 -*-
"""检查 p 与 N 的关系（前 56 bit 完全相同，强烈暗示 N = p ± k, k 很小 → 曲线异常/超奇异）。"""
P = 0xe2e20e64347abef0fef83d1a5901
A = 0x592a5290d72d5d58c73266dc96b2
B = 0x630e734697aa226547d498f14e5b
G = (0x881fb0676400f362aac2b6ae22e6, 0x5ceeaeea8ed10a70ee90737c9efb)
N = 0xe2e20e64347abea8720594c31783

print(f"p = 0x{P:x}")
print(f"N = 0x{N:x}")
print(f"p - N = {P - N}  (0x{P-N:x})")
print(f"N - p = {N - P}")

# 共同前缀长度
pb = bin(P)[2:]; nb = bin(N)[2:]
common = 0
for x, y in zip(pb, nb):
    if x != y: break
    common += 1
print(f"二进制共同前缀 bit 数: {common}")

# 曲线阶（真实 order）用 Sage 不可用 → 用 Hasse 上界 + 检查 N 是否是阶
print("\n=== 若 N = p - k，检查曲线是否 anomalous (#E = p) ===")
for k in range(-200, 201):
    cand = P - k
    if cand == N:
        print(f"  N = p - ({k}) → {'anomalous!' if k==0 else f'N = p{k:+d}'}")

# 检查 #E(Fp) 是否等于 p（anomalous curve）→ 用 Schoof 不可行，用 baby-step 检验 |#E - p - 1| 小
print("\n=== 用 Hasse 检验：若 |#E - (p+1)| < 2*sqrt(p) 恒成立，无法直接判定；"
      "\n     改测 #E == p + 1 - t，尝试小 t ===")

# 直接检验：如果 #E = p，则对任意点 X，有 p*X = O
def inv(x, m): return pow(x, -1, m)
def add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    lam = ((3*x1*x1 + A) * inv(2*y1, P)) if (x1 == x2 and y1 == y2) else ((y2 - y1) * inv(x2 - x1, P))
    x3 = (lam*lam - x1 - x2) % P
    return (x3, (lam*(x1-x3) - y1) % P)
def mul(k, pt):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r

for name, k in (("p", P), ("p+1", P+1), ("p-1", P-1), ("N", N)):
    print(f"  {name} * G = {'O' if mul(k, G) is None else '非 O'}")

# 如果曲线阶 = p（anomalous），则 p*G == O 且可用 Smart 攻击：
#   d = z / x  mod p，其中 (z,y) = d*Q, z = y^2 - x^3 - a*x  ... 需要构造映射
print("\n=== 若 anomalous，Smart 攻击可用，需要 Q。当前 Q 未知，故：检查是否存在小 t 使 #E = p+1-t ===")
# 用小范围暴力估算 t：无法直接算 #E，但可检测 (p+1-t)*G == O 对小 t
found = []
for t in range(-300, 301):
    if mul(P + 1 - t, G) is None:
        found.append(t)
print(f"  使 (p+1-t)*G == O 的小 t: {found[:20]}")
if found:
    print(f"  → 曲线阶很可能是 p+1-{found[0]}（t={found[0]}），"
          f"N(=p{N-P:+d}) {'是阶本身' if (P+1-found[0]) == N else '不等于阶，需重新设 order'}")
