"""
MemLens · 静态样本分析引擎（PE 域）

覆盖用户清单中的：`.exe` `.sys`（Windows 可执行/驱动）以及**无后缀/非 PE 的裸二进制**三类。

定位：镜像取证回答"这台机器发生了什么"，静态样本回答"这个文件是什么、可不可疑"。
两者共用同一套证据模型，因此 PE 分析结果同样可入库、可被检测器消费。

设计要点（与"直接跑 strings 完事"的区别）：
  1. **文件类型识别优先**：用魔数 + 结构校验区分 PE / ELF / 脚本 / 数据 / 高熵块，
     不靠扩展名（扩展名可以随便改，这是应急场景的常态）；
  2. **提取结构化"指标"而非堆字符串**：哈希、节区、导入/导出表、TLS 回调、时序、
     签名、编译语言、加壳检测 —— 每个都是可入库的字段；
  3. **检测器可消费**：所有指标进 records，上一层的规则引擎能直接写 SQL 查。
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import os
import re
import struct
import time
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from memlens.engines.elf import parse_elf, elf_to_records
from memlens.engines.archive import analyze_archive
from memlens.engines.pcap import analyze_pcap
from memlens.engines.memfrag import analyze_memfrag


def _is_probably_text(blob: bytes, limit: int = 65536) -> bool:
    """判定纯文本/脚本/配置（与 image_probe 同一判据，避免两处漂移）。"""
    if not blob:
        return False
    head = blob[:limit]
    if b"\x00" in head[:512]:
        return False
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(head) >= 0.90
from memlens.engines.base import (
    EngineAdapter,
    OutputKind,
    PluginMeta,
    RunSpec,
)

# ------------------------------------------------------------------ 常量

# 已知文件的"编译语言指纹"（Rich header / 段的特征串，宁少报不漏报）
GO_MARKERS = (b"Go build ID", b"\xff Go buildinf:", b"go:buildid")
RUST_MARKERS = (b"rustc\x00", b"/rustc/", b"cargo/registry")
DELPHI_MARKERS = (b"Borland Delphi", b"CodeGear Delphi", b"Embarcadero Delphi")
VBNET_MARKERS = (b"mscoree.dll", b"Microsoft.VisualBasic")
VBP_MARKERS = (b"MSVBVM", b"VB5!", b"VB6!")
PYTHON_MARKERS = (b"PyInstaller", b"python2", b"python3", b"PYZ-00.pyz")
NIM_MARKERS = (b"Nim", b"@mNimMain")
AUTOIT_MARKERS = (b"AutoIt", b"AU3!")

# 加壳/保护特征。**必须区分"节名特征"和"内容特征"**：
#   节名类几乎只会出现在加壳文件里，命中即可疑；
#   内容类在正常系统 PE 的 .rdata/.rsrc 里也可能偶然命中，因此额外要求"上下文可读"。
#
# ⚠ 维护提醒：下面的值**必须是元组**（单元素也要带尾逗号）。
#    写成 `"X": ".abc"` 会被 Python 解析成字符串，`for m in marks` 会逐字符迭代，
#    于是 `"." in ".text"` 为真 → 对所有 PE 误报。_as_tuple() 用于兜底防御这个坑。
PACKERS_SECTION_NAME: dict[str, tuple[str, ...]] = {
    "UPX": ("upx0", "upx1", "upx2"),
    "ASPack": (".adata", ".aspack"),
    "Themida/WinLicense": (".themida", ".winlice"),
    "VMProtect": (".vmp0", ".vmp1", ".vmp2"),
    "Enigma": (".enigma1", ".enigma2"),
    "MPRESS": (".mpress1", ".mpress2"),
    "PECompact": ("pec1", "pec2", ".pecompact"),
    "Obsidium": (".obsidiu",),
    "NsPack": (".nsp0", ".nsp1", ".nsp2"),
    "Armadillo": ("-armadillo", ".armadillo"),
    "Petite": (".petite",),
}
PACKERS_CONTENT: dict[str, tuple[bytes, ...]] = {
    "UPX": (b"UPX!", b"$Info: This file is packed with the UPX"),
    "PyInstaller": (b"PyInstaller", b"MEI\x0c\x0b\x0a\x0b\x0e"),
    "Themida/WinLicense": (b"Themida", b"WinLicense"),
    "VMProtect": (b"VMProtect",),
}

# 高价值 DLL（用于"这个文件会干什么"的初判）
SENSITIVE_DLLS = frozenset(
    name.lower()
    for name in (
        "wininet.dll", "urlmon.dll", "ws2_32.dll", "wsock32.dll",
        "advapi32.dll", "ntdll.dll", "winhttp.dll",
        "crypt32.dll", "bcrypt.dll", "ncrypt.dll",
        "user32.dll", "gdi32.dll", "shell32.dll", "shlwapi.dll",
        "psapi.dll", "dbghelp.dll", "imagehlp.dll",
        "netapi32.dll", "wtsapi32.dll", "samlib.dll",
        "secur32.dll", "cryptdll.dll", "vaultcli.dll",
        "taskschd.dll", "taskschd",
    )
)

# 敏感 API（按功能归类，用于"行为意图"初判）
SENSITIVE_APIS: dict[str, tuple[str, ...]] = {
    "进程注入/内存操作": ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                       "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
                       "RtlMoveMemory", "NtMapViewOfSection"),
    "进程创建/提权": ("CreateProcess", "CreateProcessAsUser", "CreateProcessWithTokenW",
                    "ShellExecute", "WinExec", "OpenProcess", "AdjustTokenPrivileges",
                    "CreateToolhelp32Snapshot", "Process32Next"),
    "持久化/服务": ("CreateService", "OpenSCManager", "StartService",
                  "RegSetValue", "RegCreateKey", "WriteProfileString"),
    "键盘/剪贴板": ("SetWindowsHookEx", "GetAsyncKeyState", "GetClipboardData",
                 "SetClipboardData", "GetKeyState"),
    "屏幕捕获": ("BitBlt", "CreateCompatibleBitmap", "GetWindowDC", "CreateCompatibleDC"),
    "网络通信": ("InternetOpen", "InternetConnect", "HttpSendRequest", "URLDownloadToFile",
              "WSAStartup", "connect", "send", "recv", "gethostbyname", "inet_addr"),
    "加密/反分析": ("CryptEncrypt", "CryptDecrypt", "IsDebuggerPresent",
                 "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                 "OutputDebugString", "GetTickCount"),
    "文件操作": ("CreateFile", "WriteFile", "ReadFile", "CopyFile", "MoveFile",
              "DeleteFile", "FindFirstFile"),
}

MAX_READ = 16 << 20          # 静态分析最多读 16 MiB（节区/字符串分析足够）
ENTROPY_BLOCK = 4096


# ------------------------------------------------------------------ 数据结构

@dataclasses.dataclass
class PEInfo:
    """PE 结构解析结果（只取取证关心的字段）。"""

    is_dll: bool = False
    is_driver: bool = False
    machine: str = ""
    subsystem: str = ""
    timestamp: int | None = None
    timestamp_iso: str = ""
    linker_version: str = ""
    entry_point: int | None = None
    image_base: int | None = None
    sections: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    imports: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    exports: list[str] = dataclasses.field(default_factory=list)
    tls_callbacks: list[str] = dataclasses.field(default_factory=list)
    rich_header: str = ""
    digital_signature: bool = False
    is_packed_suspect: bool = False
    packer_hint: str = ""
    file_type: str = "pe"
    bits: int = 0


@dataclasses.dataclass
class FileProfile:
    """一个文件的完整"画像"（不分 PE 与否，都能产出）。"""

    path: str
    size: int
    sha256: str
    md5: str
    file_type: str                       # pe/elf/script/archive/data/unknown
    pe: PEInfo | None = None
    elf: object = None                   # ELFInfo（来自 engines/elf.py），延迟导入避免循环
    entropy: float = 0.0
    strings_findings: dict[str, list[str]] = dataclasses.field(default_factory=dict)
    language: str = ""
    notes: list[str] = dataclasses.field(default_factory=list)


# ------------------------------------------------------------------ 工具函数

def sha256_file(path: str | os.PathLike, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        while True:
            b = fp.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def md5_file(path: str | os.PathLike, chunk: int = 1 << 20) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fp:
        while True:
            b = fp.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _entropy(data: bytes) -> float:
    """Shannon 熵（0–8）。>7.2 通常意味着压缩/加密/加壳。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def _as_tuple(value) -> tuple:
    """把"手滑写成单个字符串"的特征表规范化成元组（防御漏尾逗号导致逐字符迭代的坑）。"""
    if isinstance(value, (str, bytes)):
        return (value,)
    return tuple(value)


def _printable_context(data: bytes, idx: int, needle: bytes, span: int = 8) -> bool:
    """
    判断命中位置前后是否是可打印 ASCII —— 用来排除二进制流里偶然撞上的字节组合。

    加壳器标记（如 b"UPX!"）几乎总是出现在节首或可读字符串附近；
    而在随机/压缩数据里偶遇相同字节序列的概率不低，必须加这道闸。
    """
    lo = max(0, idx - span)
    hi = min(len(data), idx + len(needle) + span)
    around = data[lo:idx] + data[idx + len(needle):hi]
    if not around:
        return True
    good = sum(1 for b in around if 32 <= b < 127 or b in (0, 9))
    return good >= max(2, int(len(around) * 0.5))


MACHINE_TYPES = {
    0x014C: "i386", 0x8664: "AMD64", 0x01C0: "ARM", 0xAA64: "ARM64",
    0x01C4: "ARMNT", 0x0200: "IA64", 0x5032: "RISCV32", 0x5064: "RISCV64",
    0x0EBC: "EFI",
}
SUBSYSTEM_TYPES = {
    1: "Native", 2: "Windows GUI", 3: "Windows CUI", 5: "OS/2 CUI",
    7: "POSIX CUI", 9: "Windows CE GUI", 10: "EFI Application",
    11: "EFI Boot Service Driver", 12: "EFI Runtime Driver",
    13: "EFI ROM", 14: "Xbox",
}


def _rva_to_offset(rva: int, sections: Sequence[dict[str, Any]]) -> int | None:
    """把 RVA 换算成文件偏移（遍历节区）。"""
    for s in sections:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
            delta = rva - s["vaddr"]
            if delta < s["rsize"]:
                return s["offset"] + delta
            return s["offset"]
    return None


def parse_pe(path: str, data: bytes) -> PEInfo:
    """手工解析 PE —— 只依赖标准库，不引第三方便宜，也能覆盖加壳/畸形文件。"""
    info = PEInfo()
    if len(data) < 0x40 or data[:2] != b"MZ":
        info.notes.append("非 PE（无 MZ 头）")
        return info

    # DOS header -> e_lfanew (offset 0x3C)
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        info.notes.append("DOS 头不完整")
        return info
    if not (0 < pe_off < len(data) - 6) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        info.notes.append("PE 签名缺失（可能是伪装 MZ 或畸形文件）")
        return info

    coff = pe_off + 4
    machine, nsec, tstamp, sym_ptr, nsym, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
    info.machine = MACHINE_TYPES.get(machine, f"0x{machine:x}")
    info.bits = 64 if machine in (0x8664, 0xAA64, 0x0200, 0x5064, 0x0EBC) else 32
    info.timestamp = tstamp or None
    if tstamp:
        try:
            import datetime as _dt
            info.timestamp_iso = _dt.datetime.utcfromtimestamp(tstamp).isoformat() + "Z"
        except Exception:
            info.timestamp_iso = ""
    info.is_dll = bool(chars & 0x2000)
    # 驱动判定：NT native subsystem + 已知驱动扩展名 + 节名 ServiceMain 等
    info.is_driver = Path(path).suffix.lower() in (".sys",) or (info.subsystem == "Native")

    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32plus = magic == 0x20B
    info.linker_version = f"{data[opt + 2]}.{data[opt + 3]}"
    info.entry_point = struct.unpack_from("<I", data, opt + 16)[0]
    if pe32plus:
        info.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    else:
        info.image_base = struct.unpack_from("<I", data, opt + 28)[0]

    # 子系统位于可选头偏移 68 (PE32+) / 68 (PE32)
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    info.subsystem = SUBSYSTEM_TYPES.get(subsystem, str(subsystem))

    # 数据目录：在可选头偏移 96(PE32+)/96(PE32)；共 16 项，每项 8 字节
    dir_base = opt + (112 if pe32plus else 96)
    sec_off = opt + opt_size
    secs: list[dict[str, Any]] = []
    for i in range(nsec):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        name = data[o:o + 8].rstrip(b"\x00").decode("latin1", "replace")
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        raw_chars = struct.unpack_from("<I", data, o + 36)[0]
        sec_data = data[roff:roff + min(rsize, MAX_READ)] if rsize else b""
        secs.append({
            "name": name, "vsize": vsize, "vaddr": vaddr,
            "rsize": rsize, "offset": roff, "chars": raw_chars,
            "entropy": round(_entropy(sec_data), 3),
            "is_wx": bool(raw_chars & 0x20000000 and raw_chars & 0x80000000),  # 可写+可执行
        })
    info.sections = secs

    # ---- 导入表 ----
    try:
        imp_rva = struct.unpack_from("<I", data, dir_base + 1 * 8)[0]
    except struct.error:
        imp_rva = 0
    if imp_rva:
        off = _rva_to_offset(imp_rva, secs)
        if off:
            imports: list[dict[str, Any]] = []
            idx = 0
            while idx < 64:                      # 保护性上限
                try:
                    d = off + idx * 20
                    ilt_rva, _td, _fc, name_rva, first_thunk = struct.unpack_from("<IIIII", data, d)
                except struct.error:
                    break
                if not (ilt_rva or name_rva or first_thunk):
                    break
                noff = _rva_to_offset(name_rva, secs)
                if not noff:
                    break
                end = data.find(b"\x00", noff)
                dll = data[noff:end].decode("latin1", "replace") if end > noff else ""
                funcs: list[str] = []
                thunk_rva = ilt_rva or first_thunk
                toff = _rva_to_offset(thunk_rva, secs)
                if toff:
                    step = 8 if pe32plus else 4
                    j = 0
                    while j < 512:
                        try:
                            ent = data[toff + j * step: toff + j * step + step]
                            if len(ent) < step or ent == b"\x00" * step:
                                break
                            val = int.from_bytes(ent, "little")
                        except Exception:
                            break
                        # 高位为 1 = 按序号导入
                        if val & (1 << (8 * step - 1)):
                            funcs.append(f"#{val & 0xFFFF}")
                        else:
                            foff = _rva_to_offset(val & 0x7FFFFFFF, secs)
                            if foff is None:
                                break
                            e2 = data.find(b"\x00", foff + 2)
                            if e2 <= foff + 2:
                                break
                            funcs.append(data[foff + 2:e2].decode("latin1", "replace"))
                        j += 1
                if dll or funcs:
                    imports.append({"dll": dll, "functions": funcs[:300],
                                    "count": len(funcs)})
                idx += 1
            info.imports = imports

    # ---- 导出表 ----
    try:
        exp_rva = struct.unpack_from("<I", data, dir_base + 0)[0]
    except struct.error:
        exp_rva = 0
    if exp_rva:
        eoff = _rva_to_offset(exp_rva, secs)
        if eoff:
            try:
                _chars, _ts, _v, n_rva, n_named, a_rva, a_name = struct.unpack_from(
                    "<IIIIIII", data, eoff)
                aoff = _rva_to_offset(a_rva, secs)
                if aoff:
                    for i in range(min(n_named, 2000)):
                        nrva = struct.unpack_from("<I", data, aoff + i * 4)[0]
                        noff2 = _rva_to_offset(nrva, secs)
                        if noff2 is None:
                            continue
                        e3 = data.find(b"\x00", noff2)
                        if e3 > noff2:
                            info.exports.append(data[noff2:e3].decode("latin1", "replace"))
            except (struct.error, ValueError):
                pass

    # ---- TLS 回调（恶意代码常用） ----
    try:
        tls_rva = struct.unpack_from("<I", data, dir_base + 9 * 8)[0]
    except struct.error:
        tls_rva = 0
    if tls_rva:
        toff = _rva_to_offset(tls_rva, secs)
        if toff:
            try:
                cb_rva = struct.unpack_from("<I", data, toff + 12)[0]
                coff_ = _rva_to_offset(cb_rva, secs)
                if coff_:
                    for i in range(8):
                        cb = struct.unpack_from("<I", data, coff_ + i * 4)[0]
                        if not cb:
                            break
                        info.tls_callbacks.append(f"0x{info.image_base + cb:x}" if info.image_base else f"0x{cb:x}")
            except (struct.error, ValueError):
                pass

    # ---- 数字签名：数据目录第 4 项（Certificate） ----
    try:
        cert_rva, cert_size = struct.unpack_from("<II", data, dir_base + 4 * 8)
        info.digital_signature = bool(cert_rva and cert_size)
    except struct.error:
        pass

    # ---- Rich header 版本指纹 ----
    rich = data.find(b"Rich")
    if 0x40 < rich < 0x400:
        key = struct.unpack_from("<I", data, rich + 4)[0] if rich + 8 <= len(data) else 0
        info.rich_header = f"0x{key:x}" if key else "present"

    # ---- 加壳/保护启发式 ----
    blob = data[: min(len(data), MAX_READ)]
    hits: list[str] = []
    sec_names_low = [s["name"].lower() for s in secs]
    for name, marks in PACKERS_SECTION_NAME.items():
        for m in _as_tuple(marks):
            if any(m in sn or sn.endswith(m) for sn in sec_names_low):
                hits.append(f"{name}(节名:{m})")
                break
    for name, marks in PACKERS_CONTENT.items():
        for m in _as_tuple(marks):
            idx = blob.find(m)
            if idx >= 0 and _printable_context(blob, idx, m):
                hits.append(f"{name}(内容标记)")
                break

    if hits:
        info.packer_hint = ", ".join(hits)
        info.is_packed_suspect = True
    else:
        # 启发式：极少数节（≤2）+ 其中一节熵很高 → 疑似加壳
        # 注意：**有 Authenticode 签名的文件不套用这条**，因为签名文件几乎不会是加壳件
        #      （签名会在解包前校验，且系统文件普遍存在"少数节"的正常形态）。
        if not info.digital_signature and len(secs) <= 2:
            for s in secs:
                if s["entropy"] > 7.2:
                    info.is_packed_suspect = True
                    info.packer_hint = f"节 {s['name']} 高熵({s['entropy']})且节数极少"
                    break

    info.file_type = "pe"
    return info


def detect_language(blob: bytes) -> str:
    for markers, name in (
        (GO_MARKERS, "Go"), (RUST_MARKERS, "Rust"), (DELPHI_MARKERS, "Delphi"),
        (VBNET_MARKERS, ".NET/VisualBasic"), (VBP_MARKERS, "VisualBasic6"),
        (PYTHON_MARKERS, "Python(PyInstaller/PYZ)"), (NIM_MARKERS, "Nim"),
        (AUTOIT_MARKERS, "AutoIt"),
    ):
        if any(m in blob for m in markers):
            return name
    return ""


INTERESTING_STRINGS: dict[str, tuple[bytes, ...]] = {
    "URL 外联": (b"http://", b"https://", b"ftp://"),
    "IP 地址": (),                       # 用正则判定，见 _IPV4_RE
    "邮箱": (),                       # 邮箱用正则判定，见 _is_email()
    "注册表路径": (b"SOFTWARE\\", b"\\CurrentVersion\\Run", b"HKCU", b"HKLM"),
    "UNC/共享路径": (b"\\\\\\\\",),          # 反斜杠反斜杠：UNC 或 IPC$
    "命令行痕迹": (b"cmd.exe", b"powershell", b"schtasks", b"net user", b" reg add"),
    "互斥体": (b"Global\\", b"Local\\"),
    "SQL/数据库": (b"select ", b"insert into", b".mdb", b".sqlite"),
    "加壳标记": (b"VMProtect", b"Themida", b"UPX!"),
    "调试/分析工具": (b"Wireshark", b"Process Monitor", b"OllyDbg", b"x64dbg", b"IDA Pro"),
    # ---- 恶意软件行为特征（由真实 Agent Tesla 内存字符串清单驱动补充）----
    "SMTP/邮件外泄": (b"smtp", b"SMTP", b"mail.", b"@smtp.", b"smtpPassword",
                    b"smtpPort", b"smtpSender", b"smtpAddress"),
    "凭据/密码相关": (b"password", b"Password", b"credential", b"Credential",
                    b"passwd", b"keylogger", b"Keylogger", b"STEALING"),
    "PyInstaller 打包": (b"_MEI", b"python31", b"PyInstaller", b"PYZ-", b".pyz",
                       b"onefile", b"pyi-"),
    "C2/外联路径": (b"gate.php", b"/proxy/", b"%APPDATA%", b"/upload.php",
                  b"/panel/", b"c2.", b"?username="),
    "漏洞利用工具": (b"mimikatz", b"Mimikatz", b"sekurlsa", b"lsass.dmp",
                  b"procdump", b"psexec", b"cobaltstrike", b"beacon"),
    # 可执行文件路径/名称（恶意样本落点、自复制路径）。
    # 判据含 .exe/.dll/.bat/.ps1/.vbs 等，但排除系统目录（System32/Windows/SysWOW64）
    # —— 否则每个正常程序的全路径都会被报出来。
    "可执行文件路径": (b".exe", b".dll", b".bat", b".vbs", b".ps1", b".scr", b".pif"),
}

_EMAIL_RE = None
_IPV4_RE = None


def _is_email(s: str) -> bool:
    """真邮箱判定。子串 "@" 会把 x86 代码里的 0x40 全判成邮箱（真实踩过）。"""
    global _EMAIL_RE
    if _EMAIL_RE is None:
        import re
        _EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}")
    return bool(_EMAIL_RE.search(s))


def _is_ipv4(s: str) -> bool:
    """
    裸 IPv4 判定。**不能**用 `://` 当代理标记（会把 185.65.202.62 这类裸 IP 全漏），
    也不能走"字母占比"可读性判据（IP 字母占比为 0 会被当噪声）。
    """
    global _IPV4_RE
    if _IPV4_RE is None:
        import re
        _IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    m = _IPV4_RE.search(s)
    if not m:
        return False
    parts = m.group(0).split(".")
    return all(p.isdigit() and 0 <= int(p) <= 255 and (p == "0" or not p.startswith("0"))
               for p in parts) and len(parts) == 4

# 反模式：命中这些说明字符串来自"代码/脚本/配置模板"，而非真实 IOC。
# ⚠ 不要放 `//` —— 它会把 `http://`、`https://` 这类 URL 全部误杀（真实踩过：
#    Agent Tesla 的 C2 `http://marketingg.jino-net.ru/proxy/gate.php` 就是这么漏的）。
SCRIPT_NOISE_MARKERS = (
    "${", "$${", "awk ", "sed ", "printf", "grep ", "find ", "sort ",
    "||", "&&", ";;", "${1", "\\\"", "sub(", "gsub(", "match(",
    "#!", "#!/",
)


def _is_readable_context(s: str) -> bool:
    """
    判断字符串是否处在"可读上下文"中 —— 用来排除二进制流里偶然撞上的字节组合。

    判据（宁缺毋滥）：
      1. 长度 8~200；
      2. 不含脚本/代码模板特征（${...}、awk/grep 函数名、shebang 等）；
      3. **ASCII 字母占比 >= 0.55**（URL/路径/邮箱以字母为主；
         x86 代码片段符号密集、字母稀疏）。

    ⚠ 例外：**IP / 域名类**（数字加点为主）不能套用字母占比，否则 185.65.202.62
    会被当噪声丢掉。这类由调用方（正则命中分支）单独放行。
    """
    if not (8 <= len(s) <= 200):
        return False
    low = s.lower()
    for m in SCRIPT_NOISE_MARKERS:
        if m.lower() in low:
            return False
    if _is_ipv4(s):
        return True          # IP 例外：字母占比不适用
    letters = sum(1 for c in s if c.isalpha())
    return letters / len(s) >= 0.55


def _is_sys_path(s: str) -> bool:
    """判定是否系统目录路径（用于排除"可执行文件路径"类别里的正常系统文件）。"""
    low = s.lower()
    return any(k in low for k in (
        "\\windows\\system32", "\\windows\\syswow64", "\\windows\\", "\\winsxs\\",
        "c:\\windows\\", "/usr/bin/", "/usr/lib/", "/usr/sbin", "/bin/", "/sbin/",
        "\\microsoft\\", "\\common files\\",
    ))


def extract_interesting_strings(blob: bytes, limit_per_group: int = 12) -> dict[str, list[str]]:
    """从裸字节里抽"有取证价值的字符串"（按关键词分组 + 可读上下文过滤）。"""
    out: dict[str, list[str]] = {}
    # 可打印 ASCII 串（>=6）
    printable_runs: list[str] = []
    cur = bytearray()
    for b in blob:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= 6:
                printable_runs.append(cur.decode("latin1", "replace"))
            cur = bytearray()
    if len(cur) >= 6:
        printable_runs.append(cur.decode("latin1", "replace"))

    for group, marks in INTERESTING_STRINGS.items():
        found: list[str] = []
        # marks 里是 bytes，而候选串是可打印 ASCII 的 str —— 必须先统一成 str
        low_marks = [m.decode("latin1").lower() if isinstance(m, bytes) else str(m).lower()
                     for m in marks]
        for s in printable_runs:
            low = s.lower()
            # 正则判定的类别：邮箱 / 裸 IP（子串标记会漏或误杀）
            if group in ("邮箱", "IP 地址"):
                ok = _is_email(s) if group == "邮箱" else _is_ipv4(s)
                if not ok:
                    continue
            elif not any(m in low for m in low_marks):
                continue
            if group == "可执行文件路径" and _is_sys_path(s):
                continue          # 系统目录里的 exe 不是 IoC
            if not _is_readable_context(s):
                continue          # 过滤脚本/模板/代码字节噪声
            if s not in found:
                found.append(s)
            if len(found) >= limit_per_group:
                break
        if found:
            out[group] = found
    return out


def profile_file(path: str) -> FileProfile:
    """对任意文件做画像（这是"无后缀二进制"也能分析的关键）。"""
    p = Path(path)
    size = p.stat().st_size
    blob_head = b""
    with open(path, "rb") as fp:
        blob_head = fp.read(MAX_READ)

    ftype = "unknown"
    if blob_head[:2] == b"MZ":
        ftype = "pe"
    elif blob_head[:4] == b"\x7fELF":
        ftype = "elf"
    elif blob_head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                           b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        ftype = "pcap"
    elif blob_head[:4] == b"\x0a\x0d\x0d\x0a":
        ftype = "pcapng"
    elif blob_head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        ftype = "archive"           # zip / apk / jar
    elif blob_head.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07",
                                b"\x1f\x8b\x08", b"MSCF", b"\xfd7zXZ\x00")):
        ftype = "archive"           # 7z / rar / gzip / cab / xz
    elif blob_head.startswith(b"\x00\x05\x16\x07"):
        ftype = "appledouble"       # macOS ._ 元数据
    elif blob_head[:5] == b"%PDF-" or blob_head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        ftype = "document"          # PDF / OLE
    elif blob_head[:4] == b"EVTX":
        ftype = "evtx"
    elif blob_head.startswith((b"\xff\xd8\xff", b"\x89PNG", b"GIF87a", b"GIF89a", b"BM")):
        ftype = "image"
    elif blob_head.startswith(b"SQLite format 3\x00"):
        ftype = "sqlite"
    elif b"#!" == blob_head[:2]:
        ftype = "script"
    elif blob_head[:5].lower().startswith(b"<?xml"):
        ftype = "xml"
    elif _is_probably_text(blob_head, 65536):
        # 纯文本/脚本/配置：日志、Dockerfile、LICENCE 等（真实样本里大量出现）
        ftype = "text"

    prof = FileProfile(
        path=str(p), size=size,
        sha256=sha256_file(path) if size < (512 << 20) else "",
        md5=md5_file(path) if size < (512 << 20) else "",
        file_type=ftype,
        entropy=round(_entropy(blob_head[:1 << 20]), 3),
        language=detect_language(blob_head),
    )

    if ftype == "pe":
        prof.pe = parse_pe(path, blob_head)
    elif ftype == "elf":
        prof.elf = parse_elf(path, blob_head)
        # ELF 特有画像
        if prof.elf.static_linked and prof.elf.bits == 64:
            prof.notes.append(
                f"静态链接 ELF64（{len(prof.elf.sections)} 节 / "
                f"{prof.elf.symbol_count} 符号 / {len(prof.elf.imports)} 导入）"
            )
        if not prof.elf.build_id:
            pass  # notes 里已有

    # 高熵告警
    if prof.entropy > 7.2:
        prof.notes.append(f"整体熵 {prof.entropy}（>7.2）：可能被压缩/加密/加壳")
    if prof.pe and prof.pe.is_packed_suspect:
        prof.notes.append(f"加壳/保护特征：{prof.pe.packer_hint or '节区高熵'}")
    if prof.pe and not prof.pe.digital_signature and prof.file_type == "pe":
        # 注意：内嵌证书目录为空 ≠ 一定没有签名（可能走 catalog / 策略签名），
        # 所以这里用"未检测到"而不是"无签名"，避免对正常系统文件报假警。
        prof.notes.append("未检测到内嵌 Authenticode 证书目录（也可能走 catalog 签名，不代表一定无签名）")
    if prof.pe and prof.pe.timestamp:
        now_ts = int(time.time())
        if prof.pe.timestamp > now_ts + 30 * 86400:
            prof.notes.append(f"PE 时间戳在未来（{prof.pe.timestamp_iso}）：属可疑特征")
        else:
            # 微软工具链与 reproducible build 常把时间戳清零/随机化 —— 必须写明不可单凭此下结论
            prof.notes.append(
                f"PE 头时间戳 {prof.pe.timestamp_iso}（注：链接器常清零或随机化，"
                f"单看此项不能作为可疑依据）"
            )

    # 字符串抽种子集（两个来源：PE 全部 + 非 PE 头 16MB）
    prof.strings_findings = extract_interesting_strings(blob_head[:4 << 20], limit_per_group=10)
    return prof


def profile_to_records(prof: FileProfile) -> Iterator[dict[str, Any]]:
    """把 FileProfile 摊平成可入库的记录（每条一个"指标"或一张表）。"""
    base = {
        "文件": Path(prof.path).name,
        "路径": prof.path,
        "大小(字节)": prof.size,
        "文件类型": prof.file_type,
        "整体熵": prof.entropy,
        "语言/运行时": prof.language or "未知",
        "SHA-256": prof.sha256,
        "MD5": prof.md5,
    }
    if prof.notes:
        base["画像提醒"] = " | ".join(prof.notes)
    yield base

    if prof.pe:
        yield {
            "文件": base["文件"],
            "项": "PE 头",
            "位数": prof.pe.bits,
            "CPU": prof.pe.machine,
            "子系统": prof.pe.subsystem,
            "DLL": prof.pe.is_dll,
            "驱动(.sys)": prof.pe.is_driver,
            "入口点": f"0x{prof.pe.entry_point:x}" if prof.pe.entry_point is not None else "",
            "镜像基址": f"0x{prof.pe.image_base:x}" if prof.pe.image_base is not None else "",
            "链接器版本": prof.pe.linker_version,
            "编译时间": prof.pe.timestamp_iso,
            "Rich 头 Key": prof.pe.rich_header,
            "数字签名": prof.pe.digital_signature,
            "加壳嫌疑": prof.pe.is_packed_suspect,
            "加壳标记": prof.pe.packer_hint,
        }
        for s in prof.pe.sections:
            yield {
                "文件": base["文件"], "项": "节区", "节名": s["name"],
                "虚拟大小": s["vsize"], "原始大小": s["rsize"],
                "熵": s["entropy"], "可写且可执行(W+X)": s["is_wx"],
            }
        for imp in prof.pe.imports:
            yield {
                "文件": base["文件"], "项": "导入表", "DLL": imp["dll"],
                "函数数": imp["count"],
                "函数": ", ".join(imp["functions"][:200]),
            }
        if prof.pe.exports:
            yield {
                "文件": base["文件"], "项": "导出表",
                "导出函数数": len(prof.pe.exports),
                "函数": ", ".join(prof.pe.exports[:200]),
            }
        for cb in prof.pe.tls_callbacks:
            yield {"文件": base["文件"], "项": "TLS 回调", "地址": cb}
    if prof.elf is not None:
        for rec in elf_to_records(base["文件"], prof.elf):
            yield rec
    for group, items in prof.strings_findings.items():
        yield {"文件": base["文件"], "项": "字符串", "类别": group,
               "样本": " || ".join(items[:10])}


# ------------------------------------------------------------------ 引擎适配器


class StaticEngine(EngineAdapter):
    """静态样本分析引擎（PE/ELF/未知二进制）。"""

    name = "static"
    display = "静态样本分析"
    supported_containers = ("exe", "sys", "bin", "elf", "zip", "data", "unknown", "script")

    def __init__(self) -> None:
        self._cache: list[PluginMeta] | None = None

    # -------------------------------------------------------------- 环境
    def available(self) -> tuple[bool, str]:
        # 只依赖标准库，永远可用
        return True, "内置标准库解析器（PE / ELF / 内容识别）"

    # -------------------------------------------------------------- 插件
    def list_plugins(self, *, refresh: bool = False) -> list[PluginMeta]:
        """
        "插件"在这里是**分析维度**：每个维度产出一类记录。
        这样静态分析和内存分析走同一套 UI/入库逻辑。
        """
        if self._cache is not None and not refresh:
            return self._cache
        self._cache = [
            PluginMeta(name="static.profile", display="文件画像与类型识别",
                       category="静态分析", kind=OutputKind.TABLE,
                       description="哈希/类型/熵/语言/画像提醒，适用于任何文件（含无后缀）"),
            PluginMeta(name="static.pe", display="PE 结构解析",
                       category="静态分析", kind=OutputKind.TABLE,
                       description="头/节区/导入表/导出表/TLS 回调/Rich 头/签名"),
            PluginMeta(name="static.elf", display="ELF 结构解析",
                       category="静态分析", kind=OutputKind.TABLE,
                       description="头/节区/动态符号/导入导出/依赖库/重定位/build-id/本地函数"),
            PluginMeta(name="static.strings", display="高价值字符串提取",
                       category="静态分析", kind=OutputKind.TABLE,
                       description="URL/IP/注册表/命令行/互斥体等按类分组（含可读上下文过滤）"),
            PluginMeta(name="static.packer", display="加壳与保护检测",
                       category="静态分析", kind=OutputKind.TABLE,
                       description="PE 节名/标记/熵 + ELF 节熵与 W+X 节启发式"),
            PluginMeta(name="static.deps", display="依赖与导入导出汇总",
                       category="静态分析", kind=OutputKind.TABLE,
                       description="PE 导入表 DLL / ELF NEEDED 库与未定义符号，用于能力画像"),
            PluginMeta(name="static.pcap", display="流量包分析（pcap/pcapng）",
                       category="静态分析", kind=OutputKind.TABLE,
                       description="会话对/Top IP/端口/DNS/HTTP 与明文 flag 特征（应急与 CTF 向）"),
            PluginMeta(name="static.archive", display="压缩包内容清单（zip/apk/jar）",
                       category="静态分析", kind=OutputKind.TABLE,
                       description="逐项列出包内文件、标记内嵌可执行(PE/ELF/dex)、超大项与可疑名"),
            PluginMeta(name="static.memfrag", display="进程内存段扫描（memfrag）",
                       category="静态分析", kind=OutputKind.TABLE,
                       description="页画像/映射结构/IoC/长字符串 —— 无内核结构时把内存段当数据取证"),
        ]
        return self._cache

    # -------------------------------------------------------------- 执行
    def build_run(self, plugin: PluginMeta, image: str, params: dict[str, Any] | None = None) -> RunSpec:
        # 静态分析不需要子进程；用"内置解析器"作为执行单元
        return RunSpec(
            plugin=plugin,
            argv=["<internal>", "--file", str(image), "--plugin", plugin.name],
            output_kind=plugin.kind,
        )

    def parse_records(self, spec: RunSpec, stdout: str, stderr: str) -> Iterator[dict[str, Any]]:
        raise NotImplementedError("StaticEngine 不走子进程，请调用 analyze_file()")

    # -------------------------------------------------------------- 直接分析
    def analyze_file(self, image: str, plugin: PluginMeta) -> Iterator[dict[str, Any]]:
        """直接返回记录（由 runner 的特殊分支调用，不落子进程）。"""
        prof = profile_file(image)
        if plugin.name == "static.profile":
            yield from profile_to_records(prof)
        elif plugin.name == "static.pe":
            if not prof.pe:
                yield {"文件": Path(image).name, "项": "PE 结构", "结论": "非 PE 文件",
                       "文件类型": prof.file_type}
                return
            for rec in profile_to_records(prof):
                if rec.get("项") in ("PE 头", "节区", "导入表", "导出表", "TLS 回调"):
                    yield rec
        elif plugin.name == "static.elf":
            if prof.elf is None:
                yield {"文件": Path(image).name, "项": "ELF 结构", "结论": "非 ELF 文件",
                       "文件类型": prof.file_type}
                return
            elf_items = ("ELF 头", "节区", "依赖库", "导入函数（未定义符号）",
                         "导出函数", "本地函数（符号表）", "重定位", "备注")
            for rec in profile_to_records(prof):
                if rec.get("项") in elf_items:
                    yield rec
        elif plugin.name == "static.deps":
            # 依赖与导入导出汇总：PE 导入表 DLL / ELF NEEDED
            for rec in profile_to_records(prof):
                if rec.get("项") in ("导入表", "导入函数（未定义符号）", "依赖库",
                                     "导出函数", "导出表"):
                    yield rec
            if prof.pe is None and prof.elf is None:
                yield {"文件": Path(image).name, "项": "依赖",
                       "结论": f"该类型（{prof.file_type}）无导入/依赖概念"}
        elif plugin.name == "static.pcap":
            if prof.file_type not in ("pcap", "pcapng"):
                yield {"文件": Path(image).name, "项": "流量分析",
                       "结论": f"非流量包（类型={prof.file_type}）"}
                return
            yield from analyze_pcap(image)
        elif plugin.name == "static.archive":
            if prof.file_type not in ("archive", "apk", "jar", "zip"):
                yield {"文件": Path(image).name, "项": "压缩包",
                       "结论": f"非压缩包（类型={prof.file_type}）"}
                return
            yield from analyze_archive(image)
        elif plugin.name == "static.memfrag":
            # 进程内存段：vol3 跑不了（缺内核层），但段内仍有大量可取证内容
            if prof.file_type not in ("memfrag", "unknown", "data", "bin"):
                yield {"文件": Path(image).name, "项": "内存段",
                       "结论": f"非进程内存段（类型={prof.file_type}）"}
                return
            yield from analyze_memfrag(image)
        elif plugin.name == "static.strings":
            for group, items in prof.strings_findings.items():
                for s in items:
                    yield {"文件": Path(image).name, "类别": group, "字符串": s}
        elif plugin.name == "static.packer":
            rec = next(iter(profile_to_records(prof)))
            yield {
                "文件": Path(image).name,
                "加壳嫌疑": bool(prof.pe and prof.pe.is_packed_suspect),
                "加壳标记": (prof.pe.packer_hint if prof.pe else "") or "",
                "整体熵": prof.entropy,
                "画像提醒": " | ".join(prof.notes),
            }
        else:
            raise ValueError(f"未知静态插件：{plugin.name}")
