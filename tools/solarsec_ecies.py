# -*- coding: utf-8 -*-
"""ECIES 解密 + 对私钥 d 做小范围搜索（HMAC-SHA1 作为可靠判据）。"""
import hashlib
import hmac as hmaclib
import struct
from pathlib import Path

P = 0xe2e20e64347abef0fef83d1a5901
A = 0x592a5290d72d5d58c73266dc96b2
B = 0x630e734697aa226547d498f14e5b
G = (0x881fb0676400f362aac2b6ae22e6, 0x5ceeaeea8ed10a70ee90737c9efb)
N = 0xe2e20e64347abea8720594c31783
FS = (P.bit_length() + 7) // 8


def inv(x, m): return pow(x, -1, m)


def add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0: return None
    lam = ((3 * x1 * x1 + A) * inv(2 * y1, P)) if (x1 == x2 and y1 == y2) \
        else ((y2 - y1) * inv(x2 - x1, P))
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
plen = struct.unpack_from("<Q", data, 6)[0]
ct = data[14:]
R = (int.from_bytes(ct[1:1 + FS], "big"), int.from_bytes(ct[1 + FS:1 + 2 * FS], "big"))
body = ct[1 + 2 * FS:]
print(f"明文长度 {plen}，body {len(body)} B，差 {len(body) - plen}")

# MAC 长度：CryptoPP ECIES 默认 HMAC<SHA1> → 20 B
MAC_LEN = 20
for mac_len in (20, 26, 24, 32):
    masked = body[:len(body) - mac_len]
    mac = body[len(body) - mac_len:]
    print(f"  若 MAC={mac_len}B → 掩码密文 {len(masked)} B" + ("  ← 与明文等长 ✔" if len(masked) == plen else ""))

masked = body[:len(body) - MAC_LEN]
mac = body[len(body) - MAC_LEN:]
print(f"\n采用 MAC_LEN={MAC_LEN}")
print(f"掩码密文 {len(masked)} B / MAC {len(mac)} B")


# ---- CryptoPP P1363_KDF2<SHA1>：z 的编码 → SHA1(x||counter '') 逐块 ----
def cp_kdf2(shared_x: bytes, key_len: int) -> bytes:
    """P1363_KDF2<SHA1>：SHA1(z || counter_be32) 串联，counter 从 1 开始。"""
    out = b""
    counter = 1
    while len(out) < key_len:
        out += hashlib.sha1(shared_x + struct.pack(">I", counter)).digest()
        counter += 1
    return out[:key_len]


def try_decrypt(z_point):
    """给定共享点 z，试解。返回 (ok, plaintext, mac_ok)"""
    if z_point is None:
        return False, b"", False
    zx = z_point[0].to_bytes(FS, "big")
    mask = cp_kdf2(zx, len(masked))
    pt = bytes(a ^ b for a, b in zip(masked, mask))
    # CryptoPP DL_EncryptionAlgorithm_Xor<HMAC<SHA1>>: mac = HMAC(zx, ciphertext)
    calc = hmaclib.new(zx, masked, hashlib.sha1).digest()
    mac_ok = hmaclib.compare_digest(calc[:len(mac)], mac)
    return True, pt, mac_ok


print("\n=== 搜索私钥 d（Q = d·G），用 MAC 校验 ===")
found = []
for d in range(1, 20001):
    Q = mul(d, G)
    z = mul(d, R)          # 收方共享密钥 = d·R
    ok, pt, mac_ok = try_decrypt(z)
    if mac_ok:
        found.append((d, pt))
        print(f"  ✔✔ d={d} MAC 校验通过！")
        print(f"     明文: {pt[:200]!r}")
        break
    # 也试 Q 无效时直接用 R 本身（d=1 的情形已覆盖）
else:
    print("  d ∈ [1, 20000] 无 MAC 命中")

if not found:
    # 再试"z = R"（即 d=1 且 Q=G）与 "z = d·R" 的其他解释
    print("\n=== 试 z = k·R for k in 1..2000（不假设 Q=d·G） ===")
    for k in range(1, 2001):
        z = mul(k, R)
        ok, pt, mac_ok = try_decrypt(z)
        if mac_ok:
            print(f"  ✔ k={k} 命中！明文前 200: {pt[:200]!r}")
            break
    else:
        print("  未命中")
        # 兜底：直接看可打印性（万一 MAC 长度猜错）
        print("\n=== 可打印性兜底（所有 mac_len × d=1..300） ===")
        for mac_len in (20, 26):
            m = body[:len(body) - mac_len]
            macc = body[len(body) - mac_len:]
            for d in range(1, 301):
                z = mul(d, R)
                if z is None: continue
                mask = cp_kdf2(z[0].to_bytes(FS, "big"), len(m))
                pt = bytes(a ^ b for a, b in zip(m, mask))
                score = sum(1 for b in pt[:40] if 32 <= b < 127) / max(1, min(40, len(pt)))
                if score > 0.85:
                    print(f"  d={d} mac_len={mac_len} 可打印率 {score:.0%}: {pt[:80]!r}")
