# -*- coding: utf-8 -*-
"""从符号表 + 调试串里定位加密逻辑与 key 来源。"""
import re
import struct
from pathlib import Path

P = Path(r"E:\附件原件\solar应急响应\solarsec_202603\03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5")
data = P.read_bytes()

e_shoff, = struct.unpack_from("<Q", data, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    v = struct.unpack_from("<IIQQQQIIQQ", data, o)
    secs.append((v[0], v[1], v[3], v[4], v[5], v[6], v[9]))
strtab_off = secs[e_shstrndx][3]
def sname(off):
    e = data.find(b"\x00", strtab_off + off)
    return data[strtab_off + off:e].decode("latin1", "replace")
S = {sname(s[0]): s for s in secs}

# ---------- 1. 从 .symtab 找非 C++ 运行时符号（用户代码函数）----------
sym = S[".symtab"]
st = S["​.strtab"] if "​.strtab" in S else S[".strtab"]
symtab, strtab = S[".symtab"], S[".strtab"]
n_syms = symtab[4] // symtab[6]
print(f"符号数: {n_syms}")

syms = []
for i in range(n_syms):
    o = symtab[3] + i * symtab[6]
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", data, o)
    if not st_name:
        continue
    e = data.find(b"\x00", strtab[3] + st_name)
    nm = data[strtab[3] + st_name:e].decode("latin1", "replace")
    syms.append((nm, st_value, st_size, st_info))

print("=== 与加密/flag 相关的符号 ===")
KEYWORDS = ("aes", "rc4", "rc5", "rc6", "blowfish", "chacha", "salsa", "cast",
            "md5", "sha", "hmac", "pbkdf", "kdf", "cbc", "ecb", "cfb", "ctr",
            "mars", "idea", "des", "twofish", "serpent", "gcm", "eax", "ccm",
            "crypt", "lock", "key", "seed", "iv", "nonce", "obfus", "encode", "decode")
hits = []
for nm, val, size, info in syms:
    low = nm.lower()
    if any(k in low for k in KEYWORDS):
        hits.append((nm, val, size))
print(f"命中 {len(hits)} 个（前 40）：")
for nm, val, size in sorted(hits, key=lambda x: -x[2])[:40]:
    print(f"  {nm[:110]:<112} val=0x{val:x} size={size:,}")

# ---------- 2. 主函数相关 ----------
print("\n=== main / 用户级函数 ===")
for nm, val, size in syms:
    if nm == "main" or (size and size > 200 and not nm.startswith(("_Z", "__"))) and "main" in nm.lower():
        print(f"  main-ish: {nm} 0x{val:x} size={size}")

# ---------- 3. 未解密前的字符串线索 ----------
print("\n=== 关键字符串 ===")
for pat in (rb"[ -~]{0,50}LOCKED[ -~]{0,60}",
            rb"[ -~]{0,60}solarsec[ -~]{0,60}",
            rb"[ -~]{0,40}flag[ -~]{0,40}\.locked",
            rb"[ -~]{4,80}key[ -~]{0,40}",
            rb"[ -~]{4,80}KEY[ -~]{0,40}",
            rb"[ -~]{0,30}getenv[ -~]{0,50}",
            rb"[ -~]{0,30}environment[ -~]{0,50}",
            rb"[ -~]{6,80}SOLAR[ -~]{0,60}"):
    found = set()
    for m in re.finditer(pat, data):
        s = m.group().decode("latin1", "replace")
        if s not in found:
            found.add(s)
    for s in sorted(found)[:12]:
        print(f"  {s!r}")

# ---------- 4. .debug_str 里与用户代码相关的 DWARF 名字 ----------
dbg = S.get(".debug_str")
if dbg:
    blob = data[dbg[3]:dbg[3] + dbg[4]]
    names = set()
    for kw in ("solarsec", "SOLAR", "flag", "encrypt", "decrypt", "AES", "RC4", "Blowfish"):
        for m in re.finditer(rb"[ -~]{4,80}", blob):
            s = m.group().decode("latin1", "replace")
            if kw in s and s not in names:
                names.add(s)
    print(f"\n=== .debug_str 相关名（{len(names)} 个，前 30）===")
    for s in sorted(names)[:30]:
        print(f"  {s!r}")
