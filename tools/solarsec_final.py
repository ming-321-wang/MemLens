# -*- coding: utf-8 -*-
"""按 IDA 得到的精确算法实现：
   keyLen = plaintextLen + 16
   masked = plain(0..plaintextLen) XOR key(0..plaintextLen)
   MAC     = HMAC-SHA1(key = key[plaintextLen : plaintextLen+16], ciphertext)
   key     = P1363_KDF2<SHA1>(z)   // z = ECDH 结果（x 坐标，14 字节）
对 plaintextLen 的多个候选值逐个验 MAC —— MAC 是可靠判据。
"""
import hashlib
import hmac as hmaclib
import struct
from pathlib import Path

P = 0xe2e20e64347abef0fef83d1a5901
A = 0x592a5290d72d5d58c73266dc96b2
B = 0x630e734697aa226547d498f14e5b
G = (0x881fb0676400f362aac2b6ae22e6, 0x5ceeaeea8ed10a70ee90737c9efb)
FS = (P.bit_length() + 7) // 8   # 14


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


BASE = Path(r"E:\附件原件\solar应急响应\solarsec_202603")
data = (BASE / "flag.solarsec.locked").read_bytes()
declared = struct.unpack_from("<Q", data, 6)[0]
ct = data[14:]
body = ct[1 + 2 * FS:]
R = (int.from_bytes(ct[1:1 + FS], "big"), int.from_bytes(ct[1 + FS:1 + 2 * FS], "big"))
print(f"声明明文长度 = {declared}，body = {len(body)} B")


def kdf2(secret: bytes, out_len: int) -> bytes:
    """P1363_MGF1KDF2_Common：SHA1(secret || counter_be32)，counter 从 1 递增。"""
    out = b""
    c = 1
    while len(out) < out_len:
        out += hashlib.sha1(secret + struct.pack(">I", c)).digest()
        c += 1
    return out[:out_len]


def attempt(plen: int, z_point):
    """对给定明文长度与共享点 z 尝试解密，返回 (mac_ok, plaintext)。"""
    if z_point is None:
        return False, b""
    masked = body[:plen]
    mac = body[plen:plen + 20]
    if len(masked) != plen or len(mac) != 20:
        return False, b""
    key = kdf2(z_point[0].to_bytes(FS, "big"), plen + 16)
    pt = bytes(a ^ b for a, b in zip(masked, key[:plen]))
    mk = key[plen:plen + 16]
    calc = hmaclib.new(mk, masked, hashlib.sha1).digest()
    return hmaclib.compare_digest(calc, mac), pt


print("\n=== ① 先确定明文长度：用 plen 遍历，只看 MAC 是否可能对齐 ===")
# 只有当 d 正确时 MAC 才会通过，所以这一步先确认"body 长度 - plen == 20" 的候选
for plen in range(declared - 12, len(body) - 19):
    if len(body) - plen == 20:
        print(f"  plen={plen} → MAC 长度 20 ✔")

print("\n=== ② 搜索私钥 d（Q=d·G），z = d·R，对所有 plen 候试验 MAC ===")
cands = [p for p in range(len(body) - 20, 0, -1) if len(body) - p == 20]
if not cands:
    cands = [declared, 224, 218]
hit = None
for plen in cands:
    for d in range(1, 40001):
        z = mul(d, R)
        ok, pt = attempt(plen, z)
        if ok:
            hit = (d, plen, pt)
            print(f"  ✔✔ d={d}  plen={plen}  MAC 校验通过！")
            print(f"     明文: {pt!r}")
            break
        # 也试 z = d·Q? 没有 Q。试 z = k·R（不假设 Q=dG）
    if hit:
        break

if not hit:
    print("  未命中（d ≤ 40000）。改用 z = k·R for k in 1..5000：")
    for plen in cands:
        for k in range(1, 5001):
            z = mul(k, R)
            ok, pt = attempt(plen, z)
            if ok:
                hit = (k, plen, pt)
                print(f"  ✔ k={k} plen={plen}: {pt!r}")
                break
        if hit:
            break

if not hit:
    # 兜底：对所有 plen 候选 × d=1..2000，看可打印率
    print("\n=== ③ 可打印率兜底 ===")
    best = []
    for plen in cands:
        for d in range(1, 2001):
            z = mul(d, R)
            ok, pt = attempt(plen, z)
            if not pt:
                continue
            score = sum(1 for b in pt[:60] if 32 <= b < 127) / max(1, min(60, len(pt)))
            best.append((score, d, plen, pt[:60]))
    best.sort(reverse=True)
    for s, d, plen, pt in best[:5]:
        print(f"  score={s:.0%} d={d} plen={plen}: {pt!r}")
