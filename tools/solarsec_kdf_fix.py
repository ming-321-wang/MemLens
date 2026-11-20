# -*- coding: utf-8 -*-
"""修正 KDF：CryptoPP P1363_KDF2 的计数器是 1 字节（counterSize=1）。"""
import hashlib
import hmac as hmaclib
import struct
from pathlib import Path

P = 0xe2e20e64347abef0fef83d1a5901
A = 0x592a5290d72d5d58c73266dc96b2
B = 0x630e734697aa226547d498f14e5b
G = (0x881fb0676400f362aac2b6ae22e6, 0x5ceeaeea8ed10a70ee90737c9efb)
FS = (P.bit_length() + 7) // 8


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
R = (int.from_bytes(ct[1:1 + FS], "big"), int.from_bytes(ct[1 + FS:1 + 2 * FS], "big"))
body = ct[1 + 2 * FS:]
print(f"声明 plen={declared}  body={len(body)}")


def kdf2_1b(secret: bytes, out_len: int) -> bytes:
    """P1363_KDF2 with counterSize=1：SHA1(secret || counter_1byte)。"""
    out = b""
    c = 1
    while len(out) < out_len:
        out += hashlib.sha1(secret + bytes([c & 0xFF])).digest()
        c += 1
    return out[:out_len]


def attempt(plen: int, z_point, kdf=kdf2_1b, mac_len=20):
    if z_point is None:
        return False, b""
    masked = body[:plen]
    mac = body[plen:plen + mac_len]
    if len(mac) != mac_len:
        return False, b""
    key = kdf(z_point[0].to_bytes(FS, "big"), plen + 16)
    pt = bytes(a ^ b for a, b in zip(masked, key[:plen]))
    calc = hmaclib.new(key[plen:plen + 16], masked, hashlib.sha1).digest()
    return hmaclib.compare_digest(calc, mac), pt


print("\n=== ① 修正计数器后重搜 d（plen=224 与 declared 都试）===")
hit = None
for plen in sorted({declared, 224, len(body) - 20}):
    for d in range(1, 60001):
        ok, pt = attempt(plen, mul(d, R))
        if ok:
            hit = (d, plen, pt); break
    if hit: break
if hit:
    print(f"  ✔✔ d={hit[0]} plen={hit[1]}")
    print(f"     明文: {hit[2]!r}")
else:
    print("  仍未命中")

if not hit:
    print("\n=== ② 试 z = k·R (k=1..8000) ===")
    for plen in sorted({declared, 224, len(body) - 20}):
        for k in range(1, 8001):
            ok, pt = attempt(plen, mul(k, R))
            if ok:
                hit = (k, plen, pt); break
        if hit: break
    print("  命中！" if hit else "  未命中")

if not hit:
    print("\n=== ③ 试 z = 点本身（d=1, Q=G 情形已含），以及 z.x 的其它编码 ===")
    variants = {
        "z.x BE(14)": lambda z: z[0].to_bytes(FS, "big"),
        "z.x BE(1)": lambda z: z[0].to_bytes(1, "big"),
        "z.x LE(14)": lambda z: z[0].to_bytes(FS, "little"),
        "z 点 0x04||x||y": lambda z: bytes([4]) + z[0].to_bytes(FS, "big") + z[1].to_bytes(FS, "big"),
        "z.x||z.y BE": lambda z: z[0].to_bytes(FS, "big") + z[1].to_bytes(FS, "big"),
    }
    for name, enc in variants.items():
        def attempt2(plen, z_point, enc=enc):
            if z_point is None: return False, b""
            masked = body[:plen]; mac = body[plen:plen+20]
            if len(mac) != 20: return False, b""
            key = kdf2_1b(enc(z_point), plen + 16)
            pt = bytes(a ^ b for a, b in zip(masked, key[:plen]))
            calc = hmaclib.new(key[plen:plen+16], masked, hashlib.sha1).digest()
            return hmaclib.compare_digest(calc, mac), pt
        for plen in sorted({declared, 224}):
            for k in list(range(1, 3001)) + [0]:
                z = mul(k, R) if k else R
                ok, pt = attempt2(plen, z)
                if ok:
                    print(f"  ✔ 编码={name} k={k} plen={plen}")
                    print(f"     {pt!r}")
                    hit = ("x",); break
            if hit: break
        if hit: break

print("\n结果:", "已解出" if hit else "未解出")
