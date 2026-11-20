"""
MemLens · ELF 结构解析（Linux 取证域的第二块基石）

覆盖用户样本清单中的 Linux 可执行/库/core dump，以及**内存取证里从进程 dump 出来的 .so**。

与"只报 file 类型说这是 ELF"的区别：这里解析出可直接用于研判的结构化指标 ——
  1. 头部：位数/端序/类型(REL-EXEC-PIE-DYN-CORE)/机器/入口/解释器
  2. 节区：名称、类型、地址、大小、**熵**、是否可写可执行
  3. 动态符号：**导入**（未定义，即依赖外部提供什么）与**导出**（本文件提供什么）
  4. 动态库依赖（DT_NEEDED / DT_RPATH / DT_RUNPATH / DT_SONAME）
  5. 重定位：PLT/GOT 重定位条数与类型
  6. 符号表：是否 stripped、本地函数数、**非库函数（用户代码）**
  7. Notes：build-id、ABI tag
  8. 关键节字符串（.rodata / .dynstr / .comment），按取证关注点分类

设计要点：
  * 32/64 位通吃（结构偏移分开处理）；
  * 畸形文件只记 notes 不抛异常（取证对象经常被截断/故意破坏）；
  * 所有指标都进 records，检测器可直接消费。
"""

from __future__ import annotations

import dataclasses
import struct
from typing import Any, Iterator

# ---------------------------------------------------------------- 常量
ET_TYPES = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN(PIE/.so)", 4: "ET_CORE"}
MACHINES = {
    0x00: "None", 0x02: "SPARC", 0x03: "i386", 0x08: "MIPS", 0x14: "PPC",
    0x15: "PPC64", 0x16: "S390", 0x28: "ARM", 0x2A: "SuperH", 0x32: "IA-64",
    0x3E: "x86-64", 0xB7: "AArch64", 0xF3: "RISC-V", 0x101: "LoongArch",
}
OSABI = {
    0: "SYSV", 1: "HP-UX", 2: "NetBSD", 3: "Linux", 6: "Solaris",
    9: "FreeBSD", 12: "OpenBSD", 255: "Standalone",
}
SH_TYPES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
    6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 10: "SHLIB",
    11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY",
    17: "GROUP", 18: "SYMTAB_SHNDX", 0x6ffffff5: "GNU_ATTRIBUTES",
    0x6ffffff6: "GNU_HASH", 0x6ffffff7: "GNU_LIBLIST", 0x6ffffffd: "GNU_verdef",
    0x6ffffffe: "GNU_verneed", 0x6fffffff: "GNU_versym", 0x6ffffff0: "VERSYM",
    0x6ffffffe: "GNU_verneed",
}
SH_FLAGS = {
    0x1: "WRITE", 0x2: "ALLOC", 0x4: "EXECINSTR", 0x10: "MERGE",
    0x20: "STRINGS", 0x40: "INFO_LINK", 0x80: "LINK_ORDER", 0x200: "GROUP",
    0x400: "TLS", 0x80000000: "MASKOS",
}
DT_TAGS = {
    0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH",
    5: "STRTAB", 6: "SYMTAB", 7: "RELA", 8: "RELASZ", 9: "RELAENT",
    10: "STRSZ", 11: "SYMENT", 12: "INIT", 13: "FINI", 14: "SONAME",
    15: "RPATH", 16: "SYMBOLIC", 17: "REL", 18: "RELSZ", 19: "RELENT",
    20: "PLTREL", 21: "DEBUG", 22: "TEXTREL", 23: "JMPREL", 24: "BIND_NOW",
    25: "INIT_ARRAY", 26: "FINI_ARRAY", 27: "INIT_ARRAYSZ", 28: "FINI_ARRAYSZ",
    29: "RUNPATH", 30: "FLAGS", 32: "PREINIT_ARRAY", 33: "PREINIT_ARRAYSZ",
    0x6ffffef5: "GNU_HASH", 0x6ffffff0: "VERSYM", 0x6ffffff9: "RELACOUNT",
    0x6ffffffb: "FLAGS_1", 0x6ffffffe: "VERNEED", 0x6fffffff: "VERNEEDNUM",
    0x6ffffffc: "VERDEF", 0x6ffffffd: "VERDEFNUM",
}
STB = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE"}
STT = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE",
       5: "COMMON", 6: "TLS", 10: "GNU_IFUNC"}

MAX_READ = 32 << 20


@dataclasses.dataclass
class ELFInfo:
    bits: int = 64
    e_type: str = ""
    machine: str = ""
    osabi: str = ""
    entry: int | None = None
    interpreter: str = ""
    stripped: bool = True
    static_linked: bool = False
    build_id: str = ""
    abi_tag: str = ""
    soname: str = ""
    rpath: str = ""
    runpath: str = ""
    needed: list[str] = dataclasses.field(default_factory=list)
    sections: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    imports: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    exports: list[str] = dataclasses.field(default_factory=list)
    symbol_count: int = 0
    user_functions: list[str] = dataclasses.field(default_factory=list)
    reloc_plt: int = 0
    reloc_rela: int = 0
    notes: list[str] = dataclasses.field(default_factory=list)


def _sh_off(e_shoff: int, idx: int, is64: bool, shentsize: int) -> int:
    return e_shoff + idx * shentsize


def _read_sh(data: bytes, o: int, is64: bool) -> dict[str, Any]:
    if is64:
        (name, typ, flags, addr, off, size,
         link, info, align, entsize) = struct.unpack_from("<IIQQQQIIQQ", data, o)
    else:
        (name, typ, flags, addr, off, size,
         link, info, align, entsize) = struct.unpack_from("<IIIIIIIIII", data, o)
    return {"name_off": name, "type": typ, "flags": flags, "addr": addr,
            "offset": off, "size": size, "link": link, "info": info,
            "align": align, "entsize": entsize}


def parse_elf(path: str, data: bytes) -> ELFInfo:
    """解析 ELF。任何结构问题都记入 notes，绝不抛异常中断分析。"""
    info = ELFInfo()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        info.notes.append("非 ELF（无 \\x7fELF 头）")
        return info

    ei_class, ei_data = data[4], data[5]
    is64 = ei_class == 2
    info.bits = 64 if is64 else 32
    endian = "<" if ei_data == 1 else ">"
    info.osabi = OSABI.get(data[7], str(data[7]))
    if ei_data != 1:
        info.notes.append(f"大端序 ELF（ei_data={ei_data}），本机为小端，解析需谨慎")

    try:
        if is64:
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
            e_entry = struct.unpack_from(endian + "Q", data, 24)[0]
            e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 54)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 58)
            phoff = struct.unpack_from(endian + "Q", data, 32)[0]
        else:
            e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
            e_entry = struct.unpack_from(endian + "I", data, 24)[0]
            e_phoff = struct.unpack_from(endian + "I", data, 28)[0]
            e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 42)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 46)
    except struct.error:
        info.notes.append("ELF 头不完整（可能被截断）")
        return info

    info.e_type = ET_TYPES.get(e_type, f"0x{e_type:x}")
    info.machine = MACHINES.get(e_machine, f"0x{e_machine:x}")
    info.entry = e_entry

    # ---- 节区 ----
    if not (0 < e_shoff < len(data)) or e_shnum == 0:
        info.notes.append("无节区表（可能被 strip -s 过、或为 ET_CORE/畸形）")
        info.stripped = True
        return info

    raw_sh: list[dict[str, Any]] = []
    for i in range(e_shnum):
        o = _sh_off(e_shoff, i, is64, e_shentsize)
        if o + e_shentsize > len(data):
            info.notes.append("节区表越界，停止解析后续节")
            break
        raw_sh.append(_read_sh(data, o, is64))

    # 节名字符串表
    strtab = b""
    if e_shstrndx < len(raw_sh):
        st = raw_sh[e_shstrndx]
        if st["type"] in (3, 0) and st["offset"] + st["size"] <= len(data):
            strtab = data[st["offset"]:st["offset"] + st["size"]]

    def sname(off: int) -> str:
        if not strtab or off >= len(strtab):
            return ""
        e = strtab.find(b"\x00", off)
        return strtab[off:e if e > off else off].decode("latin1", "replace")

    for sh in raw_sh:
        if not sh["size"] and sh["type"] not in (8, 0):
            continue
        blob = b""
        if sh["type"] not in (8, 0) and sh["offset"] + sh["size"] <= len(data):
            blob = data[sh["offset"]:sh["offset"] + min(sh["size"], MAX_READ)]
        flags = "+".join(v for k, v in SH_FLAGS.items() if sh["flags"] & k)
        entry = {
            "name": sname(sh["name_off"]) or f"<{sh['type']}>",
            "type": SH_TYPES.get(sh["type"], hex(sh["type"])),
            "flags": flags,
            "addr": sh["addr"],
            "size": sh["size"],
            "entropy": round(_entropy_local(blob), 3),
            "is_wx": bool(sh["flags"] & 0x1 and sh["flags"] & 0x4),
        }
        info.sections.append(entry)

    # ---- 符号表 / 动态符号 ----
    symtabs = [(i, sh) for i, sh in enumerate(raw_sh)
               if sh["type"] in (2, 11) and sh["entsize"]]
    has_symtab = any(sh["type"] == 2 for _, sh in symtabs)
    info.stripped = not has_symtab
    # 静态链接判定：无 PT_INTERP 即静态（简化：无 .interp 节）
    has_interp = any((s.get("name") or sname(sh["name_off"])) == ".interp"
                     for s, sh in zip(info.sections, raw_sh))
    info.static_linked = not has_interp

    def str_of(sh) -> bytes:
        if sh["link"] >= len(raw_sh):
            return b""
        lk = raw_sh[sh["link"]]
        if lk["offset"] + lk["size"] <= len(data):
            return data[lk["offset"]:lk["offset"] + lk["size"]]
        return b""

    symsize = 24 if is64 else 16
    for _, sh in symtabs:
        st = str_of(sh)
        n = sh["size"] // max(1, sh["entsize"] or symsize)
        is_dyn = sh["type"] == 11
        undef: list[dict[str, Any]] = []
        defined: list[str] = []
        local_funcs: list[str] = []
        cnt = 0
        for i in range(min(n, 20000)):
            o = sh["offset"] + i * (sh["entsize"] or symsize)
            if o + symsize > len(data):
                break
            if is64:
                st_name, st_info, _other, st_shndx, st_value, st_size = struct.unpack_from(
                    endian + "IBBHQQ", data, o)
            else:
                st_name, st_value, st_size, st_info, _other, st_shndx = struct.unpack_from(
                    endian + "IIIBBH", data, o)
            if not st_name:
                continue
            e = st.find(b"\x00", st_name)
            nm = st[st_name:e if e > st_name else st_name].decode("latin1", "replace")
            if e <= st_name or not nm:
                continue
            cnt += 1
            bind = STB.get(st_info >> 4, str(st_info >> 4))
            typ = STT.get(st_info & 0xF, str(st_info & 0xF))
            if is_dyn:
                if st_shndx == 0 and typ == "FUNC":
                    undef.append({"symbol": nm, "bind": bind})
                elif typ == "FUNC" and bind in ("GLOBAL", "WEAK"):
                    defined.append(nm)
            else:
                if typ == "FUNC" and bind == "LOCAL":
                    local_funcs.append(nm)
        if is_dyn:
            info.imports = undef
            info.exports = defined
        else:
            info.symbol_count = cnt
            info.user_functions = local_funcs

    # 动态段
    dyn = [sh for sh in raw_sh if sh["type"] == 6]
    entsz = 16 if is64 else 8
    for sh in dyn:
        if not sh["size"]:
            continue
        # 找 .dynstr
        dynstr = str_of(sh)
        n = sh["size"] // entsz
        for i in range(min(n, 4000)):
            o = sh["offset"] + i * entsz
            if o + entsz > len(data):
                break
            if is64:
                d_tag, d_val = struct.unpack_from(endian + "QQ", data, o)
            else:
                d_tag, d_val = struct.unpack_from(endian + "II", data, o)
            t = DT_TAGS.get(d_tag, hex(d_tag))
            if d_tag in (14, 15, 29) and d_val < len(dynstr):
                e = dynstr.find(b"\x00", d_val)
                s = dynstr[d_val:e if e > d_val else d_val].decode("latin1", "replace")
                if d_tag == 14:
                    info.soname = s
                elif d_tag == 15:
                    info.rpath = s
                elif d_tag == 29:
                    info.runpath = s
            elif d_tag == 1 and d_val < len(dynstr):
                e = dynstr.find(b"\x00", d_val)
                s = dynstr[d_val:e if e > d_val else d_val].decode("latin1", "replace")
                if s and s not in info.needed:
                    info.needed.append(s)
            elif d_tag in (7, 17):
                info.reloc_rela += 1 if d_tag == 7 else 0
            elif d_tag == 23:  # JMPREL
                info.reloc_plt += 1
            elif d_tag == 8:
                pass
    # 用节区里的 RELA/REL 精确计数
    for sh in raw_sh:
        if sh["type"] == 4 and sh["entsize"]:
            info.reloc_rela += sh["size"] // sh["entsize"]
        elif sh["type"] == 9 and sh["entsize"]:
            info.reloc_rela += sh["size"] // sh["entsize"]

    # .interp
    for sh in raw_sh:
        nm_ = sname(sh["name_off"])
        if nm_ == ".interp" and sh["offset"] + sh["size"] <= len(data):
            info.interpreter = data[sh["offset"]:sh["offset"] + sh["size"]].split(b"\x00")[0].decode(
                "latin1", "replace")

    # notes：build-id
    for sh in raw_sh:
        if sh["type"] != 7:
            continue
        off, size = sh["offset"], sh["size"]
        if off + size > len(data):
            continue
        blob = data[off:off + size]
        p = 0
        while p + 12 <= len(blob):
            nsz, dsz, ntype = struct.unpack_from("<III", blob, p)
            if nsz < 4 or p + nsz + dsz > len(blob):
                break
            name = blob[p + 4:p + 4 + max(0, nsz - 4)].split(b"\x00")[0].decode("latin1", "replace")
            desc = blob[p + nsz:p + nsz + dsz]
            if name == "GNU" and ntype == 3 and desc:
                info.build_id = desc.hex()
            elif ntype == 1:
                info.abi_tag = f"{name}:{dsz}B"
            p += nsz + dsz

    # .comment（编译器）
    for sh in raw_sh:
        if sname(sh["name_off"]) == ".comment" and sh["size"]:
            blob = data[sh["offset"]:sh["offset"] + sh["size"]]
            info.notes.append("编译器: " + blob.split(b"\x00")[0].decode("latin1", "replace"))
            break

    # 静态链接但仍有节区间可用的 rodata 提取由 static.strings 负责
    if info.static_linked:
        info.notes.append("静态链接（无 .interp）—— 体积大且无外部依赖，常见于自包含恶意样本")
    if info.stripped:
        info.notes.append("符号表已剥离（.symtab 不存在）")
    if not info.build_id:
        info.notes.append("无 .note.gnu.build-id（可能被 strip/gcc -Wl,--build-id=none）")

    return info


def _entropy_local(blob: bytes) -> float:
    if not blob:
        return 0.0
    import math
    counts = [0] * 256
    for b in blob:
        counts[b] += 1
    total = len(blob)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


# ---------------------------------------------------------------- 记录化
def elf_to_records(base_file: str, info: ELFInfo) -> Iterator[dict[str, Any]]:
    """把 ELFInfo 摊平成 records（每行一个"指标类别"）。"""
    yield {
        "文件": base_file, "项": "ELF 头",
        "位数": info.bits,
        "类型": info.e_type,
        "机器": info.machine,
        "OS/ABI": info.osabi,
        "入口点": f"0x{info.entry:x}" if info.entry is not None else "",
        "解释器": info.interpreter or "(静态链接)",
        "SONAME": info.soname,
        "build-id": info.build_id or "(无)",
        "已剥离符号": info.stripped,
        "静态链接": info.static_linked,
        "节区数": len(info.sections),
        "符号数": info.symbol_count,
        "本地函数数": len(info.user_functions),
        "导入函数数": len(info.imports),
        "导出函数数": len(info.exports),
        "依赖库数": len(info.needed),
        "RPATH": info.rpath or "",
        "RUNPATH": info.runpath or "",
    }
    for s in info.sections:
        yield {
            "文件": base_file, "项": "节区", "节名": s["name"], "类型": s["type"],
            "地址": f"0x{s['addr']:x}", "大小": s["size"], "熵": s["entropy"],
            "标志": s["flags"], "可写可执行(W+X)": s["is_wx"],
        }
    if info.needed:
        yield {"文件": base_file, "项": "依赖库",
               "库": ", ".join(info.needed), "数量": len(info.needed)}
    if info.imports:
        by_dll: dict[str, list[str]] = {}
        for imp in info.imports:
            by_dll.setdefault(imp.get("bind", ""), []).append(imp["symbol"])
        yield {"文件": base_file, "项": "导入函数（未定义符号）",
               "数量": len(info.imports),
               "函数": ", ".join(i["symbol"] for i in info.imports[:200])}
    if info.exports:
        yield {"文件": base_file, "项": "导出函数",
               "数量": len(info.exports),
               "函数": ", ".join(info.exports[:200])}
    if info.user_functions:
        yield {"文件": base_file, "项": "本地函数（符号表）",
               "数量": len(info.user_functions),
               "函数": ", ".join(info.user_functions[:200])}
    if info.reloc_rela or info.reloc_plt:
        yield {"文件": base_file, "项": "重定位",
               "条目数": info.reloc_rela, "PLT 段存在": bool(info.reloc_plt)}
    if info.notes:
        for n in info.notes[:20]:
            yield {"文件": base_file, "项": "备注", "内容": n}
