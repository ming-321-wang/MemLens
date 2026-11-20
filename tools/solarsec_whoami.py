# -*- coding: utf-8 -*-
"""搞清 dumped_4053 是哪个进程，并定向搜私钥 d / 公钥 Q 的多种可能编码。"""
import struct
from pathlib import Path

BASE = Path(r"E:\附件原件\solar应急响应\solarsec_202603")
P = 0xe2e20e64347abef0fef83d1a5901
GX = 0x881fb0676400f362aac2b6ae22e6
GY = 0x5ceeaeea8ed10a70ee90737c9efb
N = 0xe2e20e64347abea8720594c31783
R = (0x379f281c551556125a391fda096b, 0x79f6223b4cbc4d91b72a79be1f31)


def cp_le32(v: int) -> bytes:
    out = b""
    while v:
        out += struct.pack("<I", v & 0xFFFFFFFF)
        v >>= 32
    return out


def cp_le32_pad(v: int, words: int) -> bytes:
    """CryptoPP Integer 有时按固定 word 数（含前导零）存储。"""
    return b"".join(struct.pack("<I", (v >> (32 * i)) & 0xFFFFFFFF) for i in range(words))


encodings = {}
for nm, v in (("Gx", GX), ("Gy", GY), ("N", N), ("P", P),
              ("R.x", R[0]), ("R.y", R[1])):
    encodings[f"{nm}-LE32"] = cp_le32(v)
    encodings[f"{nm}-LE32pad4"] = cp_le32_pad(v, 4)
    encodings[f"{nm}-BE14"] = v.to_bytes(14, "big")
    encodings[f"{nm}-BE15"] = v.to_bytes(15, "big")
    encodings[f"{nm}-BE16"] = v.to_bytes(16, "big")
    encodings[f"{nm}-BE28"] = v.to_bytes(28, "big")   # 点编码宽度
    # ASCII 十进制
    encodings[f"{nm}-dec"] = str(v).encode()

for p in sorted(BASE.glob("dumped_4053_*.bin")):
    blob = p.read_bytes()
    hits = [k for k, v in encodings.items() if v in blob]
    print(f"{p.name} ({len(blob):,} B) → {len(hits)} 命中 {hits[:8]}")

# 大 ELF 也搜（也许命令行就写在 .rodata）
big = (BASE / "03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5").read_bytes()
hits = [k for k, v in encodings.items() if v in big]
print(f"15MB ELF → {len(hits)} 命中 {hits[:10]}")

# ---- 判断 PID 4053 是谁：找进程名/路径/符号 ----
print("\n=== dumped_4053 的身份线索 ===")
import re
for p in sorted(BASE.glob("dumped_4053_*.bin")):
    blob = p.read_bytes()
    names = set()
    for m in re.finditer(rb"(?i)[ -~]{0,40}(crypto|aes|rsa|ecdh|ecies|ecc|openssl|libgcrypt|gnupg|mbedtls|libsodium|python|java|\.so)[ -~]{0,40}", blob):
        names.add(m.group().decode("latin1").strip())
    print(f"  {p.name[16:30]}: {sorted(names)[:8]}")
