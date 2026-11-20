# -*- coding: utf-8 -*-
"""快速摸清 15MB ELF 的身份：节区、动态符号、字符串线索（不改 MemLens，先解题）。"""
import struct
from pathlib import Path

P = Path(r"E:\附件原件\solar应急响应\solarsec_202603\03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5")
data = P.read_bytes()
print("size:", len(data))

assert data[:4] == b"\x7fELF"
ei_class, ei_data = data[4], data[5]
is64 = ei_class == 2
print(f"ELF{64 if is64 else 32} {'little' if ei_data==1 else 'big'} endian")
e_type, e_machine = struct.unpack_from("<HH", data, 16)
print(f"e_type={e_type} (2=ET_EXEC, 3=ET_DYN)  e_machine=0x{e_machine:x} (0x3e=x86-64)")
e_shoff, = struct.unpack_from("<Q", data, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
print(f"e_shoff=0x{e_shoff:x} e_shnum={e_shnum} e_shstrndx={e_shstrndx}")

secs = []
for i in range(e_shnum):
    o = e_shoff + i * e_shentsize
    name_off, sh_type, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", data, o)
    secs.append((name_off, sh_type, flags, addr, off, size, link, entsize))

# shstrtab
strtab_off = secs[e_shstrndx][4]
def sname(off):
    e = data.find(b"\x00", strtab_off + off)
    return data[strtab_off + off:e].decode("latin1", "replace")

SH_TYPES = {1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 6: "DYNAMIC",
            8: "NOBITS", 9: "REL", 11: "DYNSYM", 14: "INIT_ARRAY",
            15: "FINI_ARRAY", 17: "GROUP", 18: "SYMTAB_SHNDX", 0x6FFFFFF5: "GNU_ATTRIBUTES",
            0x6FFFFFF6: "GNU_HASH", 0x6FFFFFFD: "GNU_verdef", 0x6FFFFFFE: "GNU_verneed", 0x6FFFFFFF: "GNU_versym"}

print("\n=== 节区 ===")
for i, s in enumerate(secs):
    nm = sname(s[0])
    print(f"  [{i:2d}] {nm:<22} {SH_TYPES.get(s[1], hex(s[1])):<12} addr=0x{s[3]:x} off=0x{s[4]:x} size={s[5]:,}")

# 动态符号
dynsym = [i for i, s in enumerate(secs) if s[1] == 11]
if dynsym:
    ds = secs[dynsym[0]]
    # 找对应 strtab（link 字段指向）
    stroff_sec = secs[ds[6]]
    stroff = stroff_sec[4]
    n_syms = ds[5] // ds[7]
    print(f"\n=== 动态符号（{n_syms} 个）===")
    names = []
    for i in range(n_syms):
        o = ds[4] + i * ds[7]
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", data, o)
        if st_name:
            e = data.find(b"\x00", stroff + st_name)
            names.append(data[stroff + st_name:e].decode("latin1", "replace"))
    print("  导入:", [n for n in names if not n.startswith("_")][:40])

# 版本需求（GLIBC 版本）
verneed = [i for i, s in enumerate(secs) if s[1] == 0x6FFFFFFE]
if verneed:
    vs = secs[verneed[0]]
    stroff_sec = secs[vs[6]]
    stroff = stroff_sec[4]
    print(f"\n=== GLIBC 版本需求 ===")
    o = vs[4]
    end = vs[4] + vs[5]
    while o < end:
        version, cnt, file_off, aux_off, next_off = struct.unpack_from("<HHIII", data, o)
        if file_off:
            e = data.find(b"\x00", stroff + file_off)
            print(f"  库: {data[stroff+file_off:e].decode()}")
        a = o + aux_off
        for _ in range(cnt):
            hash_, flags, other, name_off, a_next = struct.unpack_from("<IHHII", data, a)
            e = data.find(b"\x00", stroff + name_off)
            print(f"    符号: {data[stroff+name_off:e].decode()}")
            if not a_next:
                break
            a += a_next
        if not next_off:
            break
        o += next_off

# 关键字符串
print("\n=== 关键字符串（前 30 个 flag/LOCKED/key 相关）===")
seen = set()
import re
for pat in (rb"[ -~]{6,}LOCKED[ -~]{0,80}", rb"[ -~]{0,60}solarsec[ -~]{0,60}",
            rb"[ -~]{0,40}flag[ -~]{0,60}", rb"[ -~]{0,30}/tmp/[ -~]{4,60}",
            rb"[ -~]{0,30}ptrace[ -~]{0,40}"):
    for m in re.finditer(pat, data):
        s = m.group().decode("latin1", "replace")
        if s not in seen:
            seen.add(s)
            print(f"   {s!r}")
        if len(seen) > 30:
            break
