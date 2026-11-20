# -*- coding: utf-8 -*-
"""筛出用户自己的代码：非 CryptoPP、非 libstdc++/glibc 的符号 + DWARF 编译单元名。"""
import re
import struct
from collections import Counter
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

symtab, strtab = S[".symtab"], S[".strtab"]
n_syms = symtab[4] // symtab[6]
FUNC, GLOBAL = 0x12, 0x12  # STB_GLOBAL|STT_FUNC

funcs = []
for i in range(n_syms):
    o = symtab[3] + i * symtab[6]
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", data, o)
    if st_info & 0xF != 0x02:      # 只要 FUNC
        continue
    if not st_name or not st_size:
        continue
    e = data.find(b"\x00", strtab[3] + st_name)
    nm = data[strtab[3] + st_name:e].decode("latin1", "replace")
    funcs.append((nm, st_value, st_size))

print(f"函数符号 {len(funcs)} 个")

def is_noise(nm: str) -> bool:
    return ("CryptoPP" in nm or nm.startswith("_ZN") or nm.startswith("_ZNK")
            or nm.startswith("_ZSt") or nm.startswith("__") or nm in ("main",)
            or nm.startswith("_ZN9__gnu_cxx") or nm.startswith("Iv.")
            or nm.startswith("_ZNSt"))

user = [f for f in funcs if not is_noise(f[0])]
print(f"非库函数（可能是用户代码）：{len(user)} 个\n")
for nm, val, size in sorted(user, key=lambda x: -x[2])[:60]:
    print(f"  0x{val:<10x} {size:>8,}  {nm}")

# DWARF 编译单元（.debug_info 的 DW_TAG_compile_unit 有 DW_AT_name）
print("\n=== DWARF 编译单元（源码文件名）===")
dbg = S.get(".debug_info")
if dbg:
    blob = data[dbg[3]:dbg[3] + min(dbg[4], 3_000_000)]
    # 宽松匹配可打印串里的 .c/.cpp/.cc 路径
    cands = set()
    for m in re.finditer(rb"[ -~]{4,120}\.(c|cc|cpp|cxx|c\+\+)\b", blob):
        s = m.group().decode("latin1", "replace")
        if "usr/include" not in s and "c++" not in s.split("/")[0:2]:
            cands.add(s)
    for s in sorted(cands)[:40]:
        print(f"  {s!r}")

# .note.gnu.build-id + .comment
print("\n=== .comment（编译器）===")
cm = S.get(".comment")
if cm:
    print(repr(data[cm[3]:cm[3]+cm[4]]))
