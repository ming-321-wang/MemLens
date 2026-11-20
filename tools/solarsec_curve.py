# -*- coding: utf-8 -*-
"""枚举可能的参数映射，找出"G 在曲线上"的唯一组合。"""
V = {
    "v10": 0xe2e20e64347abef0fef83d1a5901,
    "n":   0xe2e20e64347abea8720594c31783,
    "v12": 0x592a5290d72d5d58c73266dc96b2,
    "v13": 0x630e734697aa226547d498f14e5b,
    "v14": 0x881fb0676400f362aac2b6ae22e6,
    "v15": 0x5ceeaeea8ed10a70ee90737c9efb,
}

def on_curve(x, y, p, a, b):
    return (y * y - x * x * x - a * x - b) % p == 0

# 6 个常量中：一个 p、一个 a、一个 b；G=(两个)、N 或 a 之一
names = list(V)
print("=== 穷举 p/a/b 组合，找出 G=(v14,v15) 在曲线上的 ===")
hits = []
for pn in names:
    for an in names:
        for bn in names:
            if len({pn, an, bn}) != 3:
                continue
            p, a, b = V[pn], V[an], V[bn]
            # G 可能是 (v14,v15) 或 (v12,v13)
            for gname, (gx, gy) in (("(v14,v15)", (V["v14"], V["v15"])),
                                    ("(v12,v13)", (V["v12"], V["v13"]))):
                if gx < p and gy < p and on_curve(gx, gy, p, a, b):
                    hits.append((pn, an, bn, gname))
                    print(f"  ✔ p={pn} a={an} b={bn}  G={gname}")

if not hits:
    print("  没有组合命中 —— 说明我对常量取值或 G 的取法有误")

# 另一种可能：ECP(modulus, a, b) 中 modulus 也可由 Initialize 的 n 之外推导；
# 先按最常见映射（CryptoPP 5.6.5 ecp.h: ECP(modulus, a, b)）列出来
print("\n=== 若 G=(v14,v15)，单独试 p=v10（最常见映射） ===")
p, a, b = V["v10"], V["v12"], V["v13"]
print(f"  p=0x{p:x} a=0x{a:x} b=0x{b:x}")
print(f"  G 在曲线上: {on_curve(V['v14'], V['v15'], p, a, b)}")
# 试 G=(v12,v13)
print(f"  若 G=(v12,v13): 在曲线上: {on_curve(V['v12'], V['v13'], p, a, b)}")

print("\n=== 试所有 G 候选 × 所有 p 候选（a,b 用剩下的大数） ===")
cands = []
for gx_name, gy_name in (("v14", "v15"), ("v12", "v13"), ("v13", "v14"), ("v15", "n")):
    for pn in names:
        for an in names:
            for bn in names:
                if len({pn, an, bn}) != 3 or gx_name in (pn, an, bn) or gy_name in (pn, an, bn):
                    continue
                p, a, b = V[pn], V[an], V[bn]
                gx, gy = V[gx_name], V[gy_name]
                if gx < p and gy < p and on_curve(gx, gy, p, a, b):
                    cands.append((pn, an, bn, gx_name, gy_name))
print(f"全部命中 {len(cands)} 个组合：")
for c in cands[:12]:
    print(f"  p={c[0]} a={c[1]} b={c[2]}  G=({c[3]},{c[4]})")
