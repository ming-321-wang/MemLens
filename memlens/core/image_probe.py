"""
MemLens · 镜像容器格式探测（probe）

职责：在不依赖任何第三方库的前提下，回答四个问题
  1. 这个文件是什么容器格式？（裸内存镜像 / LiME / Windows 崩溃转储 / minidump / VMware / ELF core / kdump / hiberfil）
  2. 它大概是什么操作系统？（Windows / Linux / macOS / 未知）
  3. 它可读吗？（大小、对齐、稀疏程度、是否存在大段空洞）
  4. 有什么需要提醒用户的？（分段容器需先解包、部分内存不能出完整进程表…）

设计取舍（与"随便猜一下"的区别）：
  - 探测结论一律带 **evidence（证据）** 与 **confidence（置信度）**，不做无依据的断言；
  - 大文件只做**分层采样**（头部/尾部/按步长抽样），绝不整文件读入；
  - 容器格式与操作系统是**两件事**：先定容器，再定系统；
  - 结论用尽枚举与数据类表达，便于上层路由与 UI 展示。

本模块只依赖标准库。
"""

from __future__ import annotations

import dataclasses
import enum
import math
import os
import struct
from typing import Callable, Iterable

# --------------------------------------------------------------------------------------
# 常量：各类容器的特征
# --------------------------------------------------------------------------------------

# LiME (Linux Memory Extractor) 每段起始处的魔数，小端序 0x4C694D45 == b"EMiL"
LIME_MAGIC = b"EMiL"
# Windows 崩溃转储：offset 0x00 = Signature "PAGE"，offset 0x04 = ValidDump "DUMP"/"DU64"
WIN_DUMP_SIG = b"PAGE"
WIN_DUMP_VALID = (b"DUMP", b"DU64")
# Windows 用户态 minidump
MINIDUMP_MAGIC = b"MDMP"
# Linux kdump (kexec) 压缩转储的魔数
KDUMP_MAGIC = b"KDUMP   "
# Windows 休眠文件
HIBER_MAGIC = b"hibr"
# ELF（含 Linux core dump）
ELF_MAGIC = b"\x7fELF"
# QEMU 的 ELF core 常见注释
QEMU_NOTE = b"QEMU"

# 操作系统指纹：在镜像里高频出现的字符串
WINDOWS_FINGERPRINTS: tuple[bytes, ...] = (
    b"System\x00",
    b"smss.exe",
    b"csrss.exe",
    b"wininit.exe",
    b"services.exe",
    b"lsass.exe",
    b"winlogon.exe",
    b"\\SystemRoot\\",
    b"\\Device\\HarddiskVolume",
    b"Windows NT",
)
LINUX_FINGERPRINTS: tuple[bytes, ...] = (
    b"Linux version ",
    b"swapper/0",
    b"kthreadd",
    b"/sbin/init",
    b"systemd\x00",
    b"/lib/systemd/",
)
MACOS_FINGERPRINTS: tuple[bytes, ...] = (
    b"Darwin Kernel Version",
    b"launchd\x00",
    b"/System/Library/",
)

# VMware / Hyper-V 容器的启发式标记（注意：这些是"启发式"，不是规范魔数）
VMWARE_MARKERS: tuple[bytes, ...] = (b"VMware", b"VMWARE", b"vmx\0")
VMSN_MARKERS: tuple[bytes, ...] = (b"SnSh", b"vmsn")
VMSS_MARKERS: tuple[bytes, ...] = (b"vmss", b"VMSS", b"Hyper-V")

# 采样参数
HEAD_BYTES = 1 << 20          # 头部 1 MiB 精读
TAIL_BYTES = 1 << 16          # 尾部 64 KiB
SCAN_WINDOW = 192 << 20       # 指纹扫描窗口：前 192 MiB
SCAN_CHUNK = 4 << 20          # 每次读 4 MiB
ZERO_SAMPLE_BLOCK = 1 << 16   # 稀疏度采样块大小 64 KiB
ZERO_SAMPLE_COUNT = 48        # 稀疏度采样点数


class ContainerFormat(str, enum.Enum):
    """容器/文件格式。"""

    RAW = "raw"                    # 裸物理内存镜像（最常见）
    LIME = "lime"                  # LiME 分段镜像
    WIN_CRASH_DUMP = "windmp"      # Windows 崩溃转储（PAGEDUMP / PAGEDU64）
    MINIDUMP = "minidump"          # Windows minidump（用户态）
    VMWARE_VMEM = "vmem"           # VMware 内存文件（可直接当 raw 读）
    VMWARE_VMSN = "vmsn"           # VMware 快照状态（含内存，需解包）
    VMWARE_SAV = "sav"             # VMware 挂起状态（含内存，需解包）
    HYPERV_VMSS = "vmss"           # Hyper-V 保存状态（需解包）
    ELF_CORE = "elfcore"           # ELF core dump（Linux/QEMU）
    KDUMP = "kdump"                # Linux kdump 压缩转储
    HIBER = "hiber"                # hiberfil.sys
    EXECUTABLE = "exe"             # Windows PE（exe/sys/dll）—— 静态分析对象
    ELF_BIN = "elf"                # Linux ELF 可执行/库 —— 静态分析对象
    PCAP = "pcap"                  # 经典 libpcap 流量包
    PCAPNG = "pcapng"              # pcapng 流量包
    ARCHIVE = "archive"            # zip/7z/rar/tar/gz —— 可能内嵌镜像或样本
    APK = "apk"                    # Android APK（zip 容器，常内嵌 .so）
    DISK_IMAGE = "disk"            # 磁盘镜像（MBR/GPT 分区表）—— dd 取证对象
    FILESYSTEM = "filesystem"      # 裸文件系统镜像（FAT/NTFS/exFAT/ext）
    AFF4 = "aff4"                  # AFF4 取证容器（Autopsy/Libyal）
    EWF = "ewf"                    # E01 / EnCase 取证镜像
    VMDK = "vmdk"                  # VMware VMDK 虚拟磁盘
    AVML = "avml"                  # AVML 内存归档（zip：lime.txt + 内存分段）
    IMAGE = "image"                # JPEG/PNG/GIF/BMP —— 隐写或图片证据
    DOCUMENT = "document"          # PDF/Office
    APPLEDOUBLE = "appledouble"    # macOS 压缩产生的 ._ 元数据文件（无取证价值）
    TEXT = "text"                  # 纯文本/脚本/配置
    SQLITEDB = "sqlite"            # SQLite 数据库
    MEMORY_FRAGMENT = "memfrag"    # 进程内存段 / 部分内存转储（非整机镜像）
    ENCRYPTED_BLOB = "encblob"     # 高熵且无签名 → 疑似加密/压缩数据
    LOCKED_CONTAINER = "locked"    # 自定义加密容器（如 LOCKED/ECIES 赛题格式）
    OTHER = "other"                # 其它文件（数据/压缩包/脚本…）
    UNKNOWN = "unknown"

    @property
    def readable_as_raw(self) -> bool:
        """能否直接交给内存解析引擎（当作线性物理内存）读取。"""
        return self in (
            ContainerFormat.RAW,
            ContainerFormat.LIME,
            ContainerFormat.WIN_CRASH_DUMP,
            ContainerFormat.VMWARE_VMEM,
        )

    @property
    def needs_unpack(self) -> bool:
        """是否为"容器"，需要先提取内存段才能分析。"""
        return self in (
            ContainerFormat.VMWARE_VMSN,
            ContainerFormat.VMWARE_SAV,
            ContainerFormat.HYPERV_VMSS,
            ContainerFormat.AFF4,
            ContainerFormat.EWF,
            ContainerFormat.VMDK,
            ContainerFormat.AVML,
        )

    @property
    def is_memory_image(self) -> bool:
        """是否为"内存镜像"类证据（决定默认走内存取证引擎）。"""
        return self in (
            ContainerFormat.RAW, ContainerFormat.LIME, ContainerFormat.WIN_CRASH_DUMP,
            ContainerFormat.MINIDUMP, ContainerFormat.VMWARE_VMEM, ContainerFormat.VMWARE_VMSN,
            ContainerFormat.VMWARE_SAV, ContainerFormat.HYPERV_VMSS, ContainerFormat.ELF_CORE,
            ContainerFormat.KDUMP, ContainerFormat.HIBER,
        )

    @property
    def is_memory_related(self) -> bool:
        """是否与"内存"相关（整机镜像或进程内存段）——比 is_memory_image 更宽。"""
        return self.is_memory_image or self is ContainerFormat.MEMORY_FRAGMENT


class OSType(str, enum.Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


@dataclasses.dataclass
class Evidence:
    """一条探测证据。"""

    source: str        # 谁来证（detector 名）
    detail: str        # 证据内容（人可读）
    weight: float = 1.0  # 该证据的分量

    def __str__(self) -> str:  # pragma: no cover - 展示用
        return f"[{self.source}] {self.detail}"


@dataclasses.dataclass
class ProbeResult:
    """探测结果。"""

    path: str
    size: int
    container: ContainerFormat = ContainerFormat.UNKNOWN
    container_confidence: float = 0.0
    os_type: OSType = OSType.UNKNOWN
    os_confidence: float = 0.0
    os_strings: dict[str, int] = dataclasses.field(default_factory=dict)
    zero_ratio: float = 0.0
    size_aligned_4k: bool = False
    evidence: list[Evidence] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)
    # "基础警告"条数：_post_checks 之前就存在的（容器/系统探测阶段产生）。
    # 用来支持**按引擎重算提醒**（引擎切换后丢弃上一次的引擎相关警告）。
    warn_base: int = -1

    # ---- 便捷属性 ----
    @property
    def analysable(self) -> bool:
        """当前版本能否直接分析（不需要先解包）。"""
        return self.container.readable_as_raw

    def summary(self) -> str:
        mb = self.size / (1024 * 1024)
        return (
            f"{os.path.basename(self.path)} | {mb:,.1f} MiB | "
            f"容器={self.container.value}({self.container_confidence:.0%}) | "
            f"系统={self.os_type.value}({self.os_confidence:.0%})"
        )


# --------------------------------------------------------------------------------------
# 基础读取工具
# --------------------------------------------------------------------------------------


def _read_at(fp, offset: int, length: int) -> bytes:
    fp.seek(offset)
    return fp.read(length)


def _scan_fingerprints(path: str, keywords: Iterable[bytes], window: int = SCAN_WINDOW) -> dict[str, int]:
    """
    在文件前 `window` 字节内统计各关键词出现次数（分块扫描，内存占用恒定）。

    只统计出现次数，不做位置记录；用于"操作系统指纹投票"。
    """
    hits: dict[str, int] = {kw.decode("utf-8", "replace"): 0 for kw in keywords}
    kw_list = list(keywords)
    if not kw_list:
        return hits

    total = min(window, os.path.getsize(path))
    read = 0
    carry = b""
    with open(path, "rb", buffering=0) as fp:
        while read < total:
            chunk = fp.read(min(SCAN_CHUNK, total - read))
            if not chunk:
                break
            buf = carry + chunk
            for kw in kw_list:
                name = kw.decode("utf-8", "replace")
                hits[name] += buf.count(kw)
            # 保留尾部重叠，避免关键词恰好跨块被漏掉
            carry = buf[-64:]
            read += len(chunk)
    return hits


def _zero_ratio(path: str, sample_count: int = ZERO_SAMPLE_COUNT, block: int = ZERO_SAMPLE_BLOCK) -> float:
    """
    抽样估算"全零数据"占比 —— 用于判断稀疏镜像/大量未分配页。

    采样点均匀分布在整个文件上，每个点读 block 字节。
    """
    size = os.path.getsize(path)
    if size == 0:
        return 1.0
    zeros = 0
    sampled = 0
    with open(path, "rb", buffering=0) as fp:
        for i in range(sample_count):
            off = int(size * (i + 0.5) / sample_count)
            off = max(0, min(off, size - block)) if size > block else 0
            fp.seek(off)
            data = fp.read(block)
            if not data:
                continue
            sampled += 1
            if not data.strip(b"\x00"):
                zeros += 1
    return zeros / sampled if sampled else 0.0


# --------------------------------------------------------------------------------------
# 容器格式检测器：每个 detector 返回 (format, confidence, evidence) 或 None
# --------------------------------------------------------------------------------------

DetectorResult = tuple[ContainerFormat, float, Evidence]


def detect_lime(fp, size: int) -> DetectorResult | None:
    """LiME：每段以 b'EMiL' 开头，紧跟 version/start/end/reserved（4 个 u32/u64）。"""
    head = _read_at(fp, 0, 32)
    if head[:4] != LIME_MAGIC:
        return None
    try:
        ver, start, end, _res = struct.unpack("<IIQQ", head[4:28])
        seg_mb = (end - start) / (1024 * 1024)
        detail = f"头部魔数 b'EMiL'，段 version={ver} start=0x{start:x} end=0x{end:x} ({seg_mb:.1f} MiB)"
    except struct.error:  # pragma: no cover
        detail = "头部魔数 b'EMiL'"
    return ContainerFormat.LIME, 0.98, Evidence("detect_lime", detail, 0.98)


def detect_win_crash_dump(fp, size: int) -> DetectorResult | None:
    """Windows 崩溃转储：PAGEDUMP/PAGEDU64 头。"""
    head = _read_at(fp, 0, 8)
    if head[:4] != WIN_DUMP_SIG or head[4:8] not in WIN_DUMP_VALID:
        return None
    kind = "PAGEDU64（64 位）" if head[4:8] == b"DU64" else "PAGEDUMP（32 位）"
    return (
        ContainerFormat.WIN_CRASH_DUMP,
        0.95,
        Evidence("detect_win_crash_dump", f"offset0=Signature 'PAGE', offset4=ValidDump '{head[4:8].decode()}' → {kind}", 0.95),
    )


def detect_minidump(fp, size: int) -> DetectorResult | None:
    head = _read_at(fp, 0, 4)
    if head != MINIDUMP_MAGIC:
        return None
    return ContainerFormat.MINIDUMP, 0.97, Evidence("detect_minidump", "头部魔数 b'MDMP'（用户态 minidump）", 0.97)


def detect_kdump(fp, size: int) -> DetectorResult | None:
    head = _read_at(fp, 0, 8)
    if head[:8] != KDUMP_MAGIC:
        return None
    return ContainerFormat.KDUMP, 0.9, Evidence("detect_kdump", "头部魔数 b'KDUMP   '（Linux kexec 转储）", 0.9)


def detect_hiber(fp, size: int) -> DetectorResult | None:
    head = _read_at(fp, 0, 4)
    if head != HIBER_MAGIC:
        return None
    return ContainerFormat.HIBER, 0.95, Evidence("detect_hiber", "头部魔数 b'hibr'（Windows 休眠文件）", 0.95)


def detect_elf_core(fp, size: int) -> DetectorResult | None:
    """
    ELF：区分 core dump 与普通 ELF 可执行/库（e_type 位于偏移 16，2 字节小端）。
    取证场景里 core dump 是"进程级内存证据"，普通 ELF 是"样本"。
    """
    head = _read_at(fp, 0, 64)
    if head[:4] != ELF_MAGIC:
        return None
    detail = "ELF 头"
    conf = 0.75
    e_type = None
    if len(head) >= 18:
        e_type = struct.unpack_from("<H", head, 16)[0]
    if e_type == 4:
        detail += "，e_type=ET_CORE（core dump）"
        conf = 0.9
        if QEMU_NOTE in head or b"qemu" in head.lower():
            detail += "，且含 QEMU 标记"
            conf = 0.95
        return ContainerFormat.ELF_CORE, conf, Evidence("detect_elf_core", detail, conf)
    # 非 core：需要进一步判断"这是完整 ELF 文件，还是进程内存里的一段 ELF 映射"。
    # 判据：e_shoff（节区表偏移，ELF64 在 0x28 / ELF32 在 0x20）必须落在文件内且 e_shnum>0。
    # 进程内存段里常包含 libc 等库的代码页（开头正是 \x7fELF），但**节区表不在该段内**
    # —— 这种必须判为 MEMORY_FRAGMENT，否则会把内存段当样本文件送去静态分析（真实踩过）。
    if e_type is not None and e_type != 4:
        is64 = len(head) > 4 and head[4] == 2
        try:
            if is64:
                e_shoff = struct.unpack_from("<Q", head, 0x28)[0]
                e_shnum = struct.unpack_from("<H", head, 60)[0]
            else:
                e_shoff = struct.unpack_from("<I", head, 0x20)[0]
                e_shnum = struct.unpack_from("<H", head, 48)[0]
        except struct.error:
            e_shoff, e_shnum = 0, 0
        sections_usable = (0 < e_shoff < size) and e_shnum > 0
        if not sections_usable:
            return (
                ContainerFormat.MEMORY_FRAGMENT,
                0.7,
                Evidence(
                    "detect_elf_core",
                    f"头部是 ELF 头（e_type={e_type}），但节区表偏移 0x{e_shoff:x} / "
                    f"节数 {e_shnum} 不在本文件内 → 这是**进程内存里的一段 ELF 映射**"
                    f"（如 libc 代码页），不是完整样本",
                    0.7,
                ),
            )
        detail += f"，e_type={e_type}，节区表可用（{e_shnum} 节 @0x{e_shoff:x}）"
        return ContainerFormat.ELF_BIN, 0.85, Evidence("detect_elf", detail, 0.85)


def detect_executable(fp, size: int) -> DetectorResult | None:
    """
    Windows PE 识别：MZ 头 + PE 签名。
    用途：把 exe/sys/dll 与内存镜像区分开，走静态分析引擎。
    注意：**加壳文件可能没有 PE 签名**（壳自己解析），因此有 MZ 头但无 PE 签名时
    只给中等置信度，且描述里写清楚原因。
    """
    head = _read_at(fp, 0, 0x400)
    if head[:2] != b"MZ":
        return None
    try:
        pe_off = struct.unpack_from("<I", head, 0x3C)[0]
    except struct.error:
        pe_off = -1
    if 0 < pe_off < len(head) - 4 and head[pe_off:pe_off + 4] == b"PE\x00\x00":
        try:
            machine, nsec, _ts, _sp, _ns, _os, _chars = struct.unpack_from("<HHIIIHH", head, pe_off + 4)
            is_dll = bool(_chars & 0x2000)
            kind = "DLL" if is_dll else "可执行文件"
            ext = os.path.splitext(fp.name)[1].lower()
            if ext == ".sys":
                kind = "内核驱动(.sys)"
            return (
                ContainerFormat.EXECUTABLE,
                0.95,
                Evidence(
                    "detect_executable",
                    f"offset0=MZ、offset0x3C→PE 签名；machine=0x{machine:x} 节数={nsec} → PE {kind}",
                    0.95,
                ),
            )
        except struct.error:
            pass
    return (
        ContainerFormat.EXECUTABLE,
        0.6,
        Evidence("detect_executable", "有 MZ 头但未找到 PE 签名（可能被加壳/裁剪，或非标准 PE）", 0.6),
    )


def detect_vmware_container(fp, size: int) -> DetectorResult | None:
    """
    VMware 系列容器（启发式）。

    说明：.vmem/.vmsn/.sav 没有公开的规范魔数，这里用"头部标记 + 扩展名 + 内容特征"投票，
    置信度刻意压低；可靠做法是解析容器元数据（后续版本实现）。
    """
    head = _read_at(fp, 0, HEAD_BYTES)
    ext = os.path.splitext(fp.name)[1].lower()
    has_vmware = any(m in head for m in VMWARE_MARKERS)

    if ext == ".vmsn" or any(m in head for m in VMSN_MARKERS):
        if has_vmware or ext == ".vmsn":
            return (
                ContainerFormat.VMWARE_VMSN,
                0.6 if not has_vmware else 0.75,
                Evidence("detect_vmware_container", f"扩展名={ext or '(无)'}，头部含 VMware/快照标记（启发式，需解包）", 0.6),
            )
    if ext == ".sav":
        return (
            ContainerFormat.VMWARE_SAV,
            0.65,
            Evidence("detect_vmware_container", "扩展名 .sav（VMware 挂起状态，含内存，需解包）", 0.65),
        )
    if ext == ".vmem":
        return (
            ContainerFormat.VMWARE_VMEM,
            0.8,
            Evidence("detect_vmware_container", "扩展名 .vmem（VMware 内存文件，通常可按线性物理内存读取）", 0.8),
        )
    return None


def detect_hyperv_container(fp, size: int) -> DetectorResult | None:
    head = _read_at(fp, 0, HEAD_BYTES)
    ext = os.path.splitext(fp.name)[1].lower()
    if ext in (".vmss", ".vsv", ".bin") and any(m in head for m in VMSS_MARKERS):
        return (
            ContainerFormat.HYPERV_VMSS,
            0.6,
            Evidence("detect_hyperv_container", f"扩展名={ext}，头部含 Hyper-V 标记（启发式，需解包）", 0.6),
        )
    return None


PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "pcap (microsecond, little-endian)",
    b"\xa1\xb2\xc3\xd4": "pcap (microsecond, big-endian)",
    b"\x4d\x3c\xb2\xa1": "pcap (nanosecond, little-endian)",
    b"\xa1\xb2\x3c\x4d": "pcap (nanosecond, big-endian)",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"     # Section Header Block

# ---- pcap linktype → 链路头长度与名称 ----
LINKTYPES = {
    0: "LINKTYPE_NULL(BSD loopback)", 1: "LINKTYPE_ETHERNET",
    101: "LINKTYPE_RAW(IP)", 113: "LINKTYPE_LINUX_SLL",
    12: "LINKTYPE_RAW", 276: "LINKTYPE_LINUX_SLL2",
}

# ---- 常用文件魔数（141 个真实赛题样本批量分析后补充）----
# 背景：批量扫描平台附件时发现 JPEG/PDF/zip(APK)/AppleDouble 全被归为 unknown，
# 而文本文件因"可读串多"被误判成进程内存段 —— 都需要显式识别。
FILE_MAGICS: tuple[tuple[bytes, str, str, float], ...] = (
    (b"\x00\x05\x16\x07", ContainerFormat.APPLEDOUBLE, "AppleDouble（macOS 压缩元数据，通常是 ._ 前缀，无取证价值）", 0.95),
    (b"SQLite format 3\x00", ContainerFormat.SQLITEDB, "SQLite 数据库", 0.95),
    (b"\x89PNG\r\n\x1a\n", ContainerFormat.IMAGE, "PNG 图片", 0.95),
    (b"\xff\xd8\xff", ContainerFormat.IMAGE, "JPEG 图片", 0.95),
    (b"GIF87a", ContainerFormat.IMAGE, "GIF 图片", 0.95),
    (b"GIF89a", ContainerFormat.IMAGE, "GIF 图片", 0.95),
    (b"BM", ContainerFormat.IMAGE, "BMP 图片", 0.7),
    (b"%PDF-", ContainerFormat.DOCUMENT, "PDF 文档", 0.95),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ContainerFormat.DOCUMENT, "OLE 复合文档（旧版 Office/VCF）", 0.9),
    (b"PK\x03\x04", ContainerFormat.ARCHIVE, "ZIP / APK / JAR（zip 容器）", 0.9),
    (b"PK\x05\x06", ContainerFormat.ARCHIVE, "ZIP（空归档）", 0.9),
    (b"PK\x07\x08", ContainerFormat.ARCHIVE, "ZIP（跨卷）", 0.9),
    (b"7z\xbc\xaf\x27\x1c", ContainerFormat.ARCHIVE, "7-Zip 归档", 0.95),
    (b"Rar!\x1a\x07", ContainerFormat.ARCHIVE, "RAR 归档", 0.95),
    (b"\x1f\x8b\x08", ContainerFormat.ARCHIVE, "GZIP 压缩数据", 0.95),
    (b"MSCF", ContainerFormat.ARCHIVE, "Microsoft Cabinet", 0.95),
    (b"\xfd7zXZ\x00", ContainerFormat.ARCHIVE, "XZ 压缩数据", 0.95),
)


def _is_probably_text(blob: bytes, limit: int = 4096) -> bool:
    """判定纯文本/脚本/配置：高可打印比例且无明显二进制结构。"""
    if not blob:
        return False
    head = blob[:limit]
    if b"\x00" in head[:512]:
        return False
    printable = sum(1 for b in head if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(head) >= 0.90


def detect_disk_filesystem(fp, size: int) -> DetectorResult | None:
    """
    识别磁盘镜像 / 裸文件系统镜像（`.dd` 类）。

    这是 DFRWS 2009 磁盘镜像（nssal-thumb-fs.dd，FAT16）暴露的缺口：
    此前被归为 unknown，而 `dd` 在用户需求清单里明确列出。

    区分三类：
      * **裸文件系统**（无分区表）：FAT/NTFS/exFAT 的跳转指令 + OEM 名，或 ext 的 0xEF53 魔数
      * **MBR 磁盘**：引导代码（可含上述跳转）+ 偏移 446 起 4 个分区项 + 55AA 签名
      * **GPT 磁盘**：LBA1 处 "EFI PART"
    """
    head = _read_at(fp, 0, 2048)
    if len(head) < 512:
        return None

    # ---- GPT：在 LBA1（偏移 512） ----
    if len(head) >= 520 and head[512:520] == b"EFI PART":
        try:
            part_lba, _num, _sz = struct.unpack_from("<QQQ", head, 520)
        except struct.error:
            part_lba = 0
        return (
            ContainerFormat.DISK_IMAGE,
            0.9,
            Evidence("detect_disk_filesystem",
                     f"GPT 磁盘镜像（EFI PART，分区表起始 LBA={part_lba}）", 0.9),
        )

    # ---- 裸文件系统：FAT / NTFS / exFAT ----
    jmp = head[:3]
    oem = head[3:11].decode("latin1", "replace").strip()
    fs_name = None
    if oem.startswith("NTFS"):
        fs_name = "NTFS"
    elif oem.startswith("EXFAT"):
        fs_name = "exFAT"
    elif head[82:90].decode("latin1", "replace").startswith("FAT"):
        fs_name = head[82:90].decode("latin1", "replace").strip()
    elif head[54:62].decode("latin1", "replace").startswith("FAT"):
        fs_name = head[54:62].decode("latin1", "replace").strip()
    elif len(head) >= 12 and jmp in (b"\xeb\x3c\x90", b"\xeb\x58\x90",
                                      b"\xeb\x76\x90", b"\xe9\x00\x00"):
        # 有 FAT 跳转指令但 OEM/FS 名不认识，用 BPB 佐证
        try:
            bps = struct.unpack_from("<H", head, 11)[0]
            if bps in (512, 1024, 2048, 4096) and 0 < head[13] <= 16:
                fs_name = "FAT(未知版本，BPB 有效)"
        except struct.error:
            pass

    if fs_name:
        return (
            ContainerFormat.FILESYSTEM,
            0.85,
            Evidence("detect_disk_filesystem",
                     f"裸文件系统镜像：{fs_name}（OEM={oem!r}，跳转={jmp.hex(' ')}）"
                     f"—— 含文件与目录，需按文件系统解析而非内存解析", 0.85),
        )

    # ---- ext2/3/4：超级块魔数 0xEF53 在偏移 1080 ----
    if size > 2048:
        ext_head = _read_at(fp, 1024, 64)
        if len(ext_head) >= 58 and struct.unpack_from("<H", ext_head, 56)[0] == 0xEF53:
            return (
                ContainerFormat.FILESYSTEM,
                0.9,
                Evidence("detect_disk_filesystem",
                         "ext 文件系统镜像（超级块魔数 0xEF53 @1024+56）", 0.9),
            )

    # ---- MBR：分区表 + 55AA ----
    if len(head) >= 512 and head[510:512] == b"\x55\xaa":
        parts = []
        for i in range(4):
            e = head[446 + i * 16:446 + (i + 1) * 16]
            if not any(e):
                continue
            ptype = e[4]
            lba = int.from_bytes(e[8:12], "little")
            cnt = int.from_bytes(e[12:16], "little")
            if ptype or lba:
                parts.append(f"type=0x{ptype:02x} lba={lba} size={cnt*512/1048576:.0f}MiB")
        if parts:
            return (
                ContainerFormat.DISK_IMAGE,
                0.85,
                Evidence("detect_disk_filesystem",
                         f"MBR 磁盘镜像（签名 55AA，分区：{'; '.join(parts)}）"
                         f"—— 含分区表，需先提取分区再解析文件系统", 0.85),
            )

    return None


def detect_common_files(fp, size: int) -> DetectorResult | None:
    """识别常用文件类型（魔数 + 文本判定），覆盖 141 个真实样本暴露的缺口。"""
    head = _read_at(fp, 0, 8192)
    for magic, kind, desc, conf in FILE_MAGICS:
        if head.startswith(magic):
            return kind, conf, Evidence("detect_common_files",
                                        f"{desc}（魔数 {magic[:6].hex(' ')}）", conf)
    if _is_probably_text(head):
        if _read_at(fp, 0, 4096).startswith(b"#!"):
            return ContainerFormat.TEXT, 0.9, Evidence("detect_common_files",
                                                       "脚本文件（shebang）", 0.9)
        return ContainerFormat.TEXT, 0.85, Evidence("detect_common_files",
                                                    "纯文本/脚本/配置文件", 0.85)
    return None


def detect_pcap(fp, size: int) -> DetectorResult | None:
    """
    识别网络流量包：经典 pcap（24 字节全局头）与 pcapng（Section Header Block）。

    背景：用户需求清单明确包含"流量包"，而它此前被探测归为 unknown —— 这是真实缺口。
    """
    head = _read_at(fp, 0, 64)
    if len(head) < 4:
        return None
    for magic, desc in PCAP_MAGICS.items():
        if head[:4] == magic:
            try:
                vmaj, vmin = struct.unpack_from("<HH", head, 4)
                snaplen, network = struct.unpack_from("<II", head, 16)
            except struct.error:
                vmaj = vmin = snaplen = network = 0
            return (
                ContainerFormat.PCAP,
                0.95,
                Evidence(
                    "detect_pcap",
                    f"{desc}，version {vmaj}.{vmin}，snaplen={snaplen}，"
                    f"linktype={network}（{LINKTYPES.get(network, '未知')}）",
                    0.95,
                ),
            )
    if head[:4] == PCAPNG_MAGIC:
        try:
            blen, bom = struct.unpack_from("<II", head, 4)
        except struct.error:
            blen = bom = 0
        return (
            ContainerFormat.PCAPNG,
            0.95,
            Evidence(
                "detect_pcapng",
                f"pcapng Section Header Block（block_len={blen}，"
                f"byte-order magic {'有效' if bom == 0x1A2B3C4D else '异常'}）",
                0.95,
            ),
        )
    return None


def detect_locked_container(fp, size: int) -> DetectorResult | None:
    """
    识别自定义加密容器：头部是 ASCII tag + 明确的长度/参数结构。

    赛题常见形态（如本次 solarsec 的 `flag.solarsec.locked`）：
        b"LOCKED" + u64(明文长度) + 密文
    特征是：前 4~8 字节是**可打印 ASCII 且不是已知魔数**，随后紧跟小端 u64 长度字段，
    且该长度与文件剩余字节数吻合。
    """
    head = _read_at(fp, 0, 32)
    if len(head) < 14:
        return None
    # 前 4~8 字节必须全是可打印 ASCII（且不含已知魔数首字节）
    tag_len = 0
    for b in head[:8]:
        if 32 <= b < 127:
            tag_len += 1
        else:
            break
    if tag_len < 4:
        return None
    tag = head[:tag_len]
    if tag in (LIME_MAGIC, WIN_DUMP_SIG, MINIDUMP_MAGIC, KDUMP_MAGIC,
               HIBER_MAGIC, ELF_MAGIC, b"MZ", b"PK\x03\x04", b"%PDF-", b"EVTX",
               b"Rich", b"BZh", b"\x1f\x8b", b"\xfd7zXZ"):
        return None
    # 尝试把 tag 之后的 8 字节当 u64 明文长度，看是否与文件大小自洽。
    # 判据：明文长度 > 0，且"密文区"（size - tag - 8）不小于明文的一半
    #      （加密通常有膨胀而非收缩），同时明文不超过 95% 的文件体积。
    head_len = len(head)
    for off in (tag_len, tag_len + 1):
        if off + 8 > head_len:
            continue
        try:
            plen = struct.unpack_from("<Q", head, off)[0]
        except struct.error:
            continue
        body_len = size - off - 8
        if plen and body_len > 0 and body_len >= plen // 2 and plen <= size * 0.95:
            return (
                ContainerFormat.LOCKED_CONTAINER,
                0.8,
                Evidence(
                    "detect_locked_container",
                    f"头部 tag={tag!r} + u64 长度={plen} + 尾部 {body_len} 字节密文，"
                    f"符合「tag + 长度 + 密文」的自定义加密容器特征",
                    0.8,
                ),
            )
    return None


def detect_cross_platform_container(fp, size: int) -> DetectorResult | None:
    """
    识别**跨平台取证容器**：AFF4 / EWF(E01) / VMDK。

    为什么必须自己写（LovelyMem 没有这一层）：
    跨平台（Windows/Linux/macOS）的内存镜像在云取证与虚拟化场景里
    常被封装成"磁盘容器"再分发 —— 这些容器必须先解包才能取到内存段。
    工具如果不认识格式，就只能把路径原样丢给外部引擎碰运气。

    魔数：
      * AFF4  → ``AFF4\\r\\n\\x00``（Autopsy/Libyal AFF4 容器）
      * EWF   → ``EVF\\x09\\x0d\\x0a\\xff\\x00``（E01 新格式）/ ``LVF\\x09``（EnCase v5）
      * VMDK  → ``KDMV``（稀疏 VMDK 头）/ ``# Disk DescriptorFile``（描述符文件）
    """
    head = _read_at(fp, 0, 512)
    if len(head) < 4:
        return None
    if head.startswith(b"AFF4\r\n\x00"):
        return (
            ContainerFormat.AFF4,
            0.9,
            Evidence("detect_cross_platform_container",
                     "AFF4 取证容器（Autopsy/Libyal 格式），内含磁盘/内存流，需先解包", 0.9),
        )
    if head.startswith(b"EVF\x09\x0d\x0a\xff\x00") or head.startswith(b"LVF\x09"):
        return (
            ContainerFormat.EWF,
            0.9,
            Evidence("detect_cross_platform_container",
                     "EWF/E01 取证镜像（Expert Witness Format），需先解包", 0.9),
        )
    if head.startswith(b"KDMV"):
        return (
            ContainerFormat.VMDK,
            0.85,
            Evidence("detect_cross_platform_container",
                     "VMware VMDK 虚拟磁盘（稀疏格式），内可能含内存快照", 0.85),
        )
    if head.startswith(b"# Disk DescriptorFile"):
        return (
            ContainerFormat.VMDK,
            0.85,
            Evidence("detect_cross_platform_container",
                     "VMware VMDK 描述符文件（指向多个 extent 磁盘）", 0.85),
        )
    return None


def detect_avml(fp, size: int) -> DetectorResult | None:
    """
    识别 AVML / 其它"内存归档 zip"（LiME 打包）。

    AVML 是 Velociraptor 产出的内存归档：一个 zip，里面有
    `lime.txt`（采集元信息）与 `memory.ve` / `ml.raw`（LiME 分段）。
    zip 的本地文件头里**文件名是不压缩的**，所以在前 1 MiB 里搜
    "lime.txt" 就能可靠判定，无需解压。
    """
    head = _read_at(fp, 0, 1 << 20)
    if not head.startswith(b"PK\x03\x04"):
        return None
    blob = head.lower()
    if b"lime.txt" in blob or b"memory.ve" in blob or b"ml.raw" in blob or b"avml" in blob:
        return (
            ContainerFormat.AVML,
            0.95,          # 必须高于 ARCHIVE(0.9)，否则会被通用 zip 判定抢走
            Evidence("detect_avml",
                     "AVML/LiME 内存归档（zip 容器，内含 lime.txt 与内存分段）", 0.95),
        )
    return None


DETECTORS: tuple[Callable[[object, int], DetectorResult | None], ...] = (
    detect_lime,
    detect_win_crash_dump,
    detect_minidump,
    detect_kdump,
    detect_hiber,
    detect_cross_platform_container,   # AFF4 / EWF / VMDK（跨平台取证容器）
    detect_avml,                      # AVML（zip 内存归档）—— 要在 archive 之前
    detect_pcap,               # 流量包（pcap/pcapng）
    detect_executable,          # 必须在 elf 之前：MZ 优先
    detect_elf_core,
    detect_common_files,        # 常用文件魔数 + 文本判定（141 个真实样本后补）
    detect_disk_filesystem,     # 磁盘镜像 / 裸文件系统（DFRWS .dd 暴露的缺口）
    detect_locked_container,    # ELF/PE 之后再判（tag 是 ASCII，容易和别的撞）
    detect_vmware_container,
    detect_hyperv_container,
)


# --------------------------------------------------------------------------------------
# 操作系统探测
# --------------------------------------------------------------------------------------


def guess_os(path: str, size: int) -> tuple[OSType, float, dict[str, int], list[Evidence]]:
    """
    用"指纹投票"猜操作系统：以最强的两类指纹（Windows / Linux）为主，macOS 为辅。

    评分规则：命中种类数 / 该类别指纹总数，取最高者；同时给出命中统计作为证据。
    """
    ev: list[Evidence] = []
    win = _scan_fingerprints(path, WINDOWS_FINGERPRINTS)
    lin = _scan_fingerprints(path, LINUX_FINGERPRINTS)
    mac = _scan_fingerprints(path, MACOS_FINGERPRINTS)

    win_hit = sum(1 for v in win.values() if v)
    lin_hit = sum(1 for v in lin.values() if v)
    mac_hit = sum(1 for v in mac.values() if v)

    candidates = [
        (OSType.WINDOWS, win_hit / len(WINDOWS_FINGERPRINTS), win),
        (OSType.LINUX, lin_hit / len(LINUX_FINGERPRINTS), lin),
        (OSType.MACOS, mac_hit / len(MACOS_FINGERPRINTS), mac),
    ]
    candidates.sort(key=lambda x: x[1], reverse=True)
    best_os, best_ratio, best_hits = candidates[0]

    if best_ratio == 0:
        return OSType.UNKNOWN, 0.0, {}, [Evidence("guess_os", "未命中任何操作系统指纹", 0.0)]

    # macOS 很容易被 Linux 类指纹误伤，要求更高门槛
    if best_os is OSType.MACOS and best_ratio < 0.34:
        best_os, best_ratio = OSType.UNKNOWN, 0.0

    detail = "、".join(f"{k}={v}" for k, v in best_hits.items() if v)
    ev.append(Evidence("guess_os", f"{best_os.value} 指纹命中 {best_ratio:.0%}（{detail}）", best_ratio))
    return best_os, min(best_ratio * 1.6, 0.98), best_hits, ev


# --------------------------------------------------------------------------------------
# 对外主入口
# --------------------------------------------------------------------------------------


def probe_image(path: str, *, deep: bool = True, for_engine: str | None = None) -> ProbeResult:
    """
    探测一个镜像文件。

    Args:
        path: 文件路径
        deep: 是否做深度采样（指纹扫描 + 稀疏度估算）。大文件上关掉可提速。
        for_engine: 调用方打算使用的引擎（"vol3" / "static"）。
                    **仅用于抑制不适用的告警** —— 例如用户明确要用 static 引擎时，
                    就不该再提示"请改用 static 引擎"这种自相矛盾的话。

    Returns:
        ProbeResult
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"文件不存在：{path}")

    size = os.path.getsize(path)
    res = ProbeResult(path=path, size=size)
    res.size_aligned_4k = (size % 4096 == 0)

    with open(path, "rb") as fp:
        for det in DETECTORS:
            try:
                hit = det(fp, size)
            except Exception as exc:  # 探测失败不应阻断流程
                res.warnings.append(f"检测器 {det.__name__} 出错：{exc}")
                continue
            if hit:
                fmt, conf, ev = hit
                if conf > res.container_confidence:
                    res.container = fmt
                    res.container_confidence = conf
                    res.evidence.append(ev)

    # ← 注意顺序：fallback 依赖操作系统指纹，因此必须放在 guess_os 之后。
    #    曾经把它放在 deep 之前，导致 os_type 恒为 UNKNOWN、所有内存镜像都被判成 other。

    if deep and size > 0:
        os_type, conf, hits, ev = guess_os(path, size)
        res.os_type, res.os_confidence, res.os_strings = os_type, conf, hits
        res.evidence.extend(ev)
        try:
            res.zero_ratio = _zero_ratio(path)
        except Exception as exc:  # pragma: no cover
            res.warnings.append(f"稀疏度采样失败：{exc}")

    if res.container is ContainerFormat.UNKNOWN:
        # 排除掉已知容器后：有操作系统指纹且体积较大 → 按裸内存镜像处理（中等置信度）；
        # 否则若呈现"进程内存"特征（大量可读字符串但无内核结构）→ 内存段；
        # 否则若高熵且体积可观 → 疑似加密/压缩块；
        # 最后才归 other，绝不"一律当成 raw"（那会让用户拿垃圾文件去跑 vol3 还以为是自己用错了）。
        if res.os_type is not OSType.UNKNOWN and size >= (1 << 20):
            res.container = ContainerFormat.RAW
            res.container_confidence = 0.5
            res.evidence.append(Evidence(
                "fallback", f"未命中容器魔数，但操作系统指纹命中（{res.os_type.value}）"
                            f"且体积 {size / 1048576:.1f} MiB → 按裸内存镜像处理", 0.5))
        elif _looks_like_memory_fragment(path, res.os_strings):
            res.container = ContainerFormat.MEMORY_FRAGMENT
            res.container_confidence = 0.55
            res.evidence.append(Evidence(
                "fallback", "无容器魔数、无内核级系统指纹，但可读字符串密度符合"
                            "进程内存特征（环境变量/库路径/堆字符串）→ 判定为进程内存段", 0.55))
        elif size >= 4096 and _estimate_entropy(path) > 7.2:
            res.container = ContainerFormat.ENCRYPTED_BLOB
            res.container_confidence = 0.5
            res.evidence.append(Evidence(
                "fallback", "无可识别结构但熵 > 7.2 → 疑似加密/压缩数据块", 0.5))
        else:
            res.container = ContainerFormat.OTHER
            res.container_confidence = 0.4
            res.evidence.append(Evidence(
                "fallback", "未命中任何容器魔数，也未检出操作系统指纹 → 归为其它文件"
                            "（可用静态分析引擎处理）", 0.4))

    _post_checks(res, for_engine)
    return res


# 进程内存的典型内容：环境变量、加载器路径、SSH/终端痕迹。
# 这些在整机镜像里也有，但在**只含这些、没有内核结构**的小文件里，基本可断定是进程内存段。
FRAGMENT_FINGERPRINTS: tuple[bytes, ...] = (
    b"LD_PRELOAD", b"LD_LIBRARY_PATH", b"/lib/x86_64-linux-gnu/",
    b"/usr/lib/", b"/lib64/ld-linux", b"/etc/ld.so",
    b"HOME=", b"PATH=", b"USER=", b"LOGNAME=", b"TERM=", b"PWD=",
    b"/proc/self", b"/proc/", b"/tmp/", b"/var/",
    b"bash_history", b".bashrc", b"SSH_AUTH_SOCK", b"GNOME_KEYRING",
    b"libc.so.6", b"ld-linux-x86-64", b"__libc_start_main",
    b"kernel32.dll", b"ntdll.dll", b"KERNEL32", b"NTDLL",
)


def _looks_like_memory_fragment(path: str, os_strings: dict | None) -> bool:
    """
    判定"进程内存段"：无容器魔数、无内核级指纹，但可读字符串密度与内容符合进程内存。

    判据（同时满足）：
      1. 命中 >= 2 类不同的进程内存指纹（库路径 / 环境变量 / 终端痕迹）；
      2. 文件不是纯随机（有一定可读字符串密度）；
      3. **不是文本/脚本/配置**（141 个真实样本后发现 Dockerfile、LICENSE 等
         因含 `/tmp/`、`/var/` 路径被误判成内存段）；
      4. **没有已知文件魔数**（zip/pcap 等已在前面按容器处理）。
    """
    try:
        with open(path, "rb") as fp:
            blob = fp.read(8 << 20)
    except OSError:
        return False
    if not blob:
        return False
    # 排除纯文本（含路径的 Dockerfile/脚本会被"库路径指纹"骗到）
    if _is_probably_text(blob, 65536) and blob[:65536].count(b"\n") >= 2:
        return False
    # 排除已知魔数（后半程才走到这里，保险起见再判一次）
    for magic, *_ in FILE_MAGICS:
        if blob.startswith(magic):
            return False
    hits = {}
    for m in FRAGMENT_FINGERPRINTS:
        c = blob.count(m)
        if c:
            hits[m.decode("latin1", "replace")] = c
    if len(hits) < 2:
        return False

    chunk = blob[:1 << 20]
    runs = 0
    cur = 0
    for b in chunk:
        if 32 <= b < 127:
            cur += 1
        else:
            if cur >= 8:
                runs += 1
            cur = 0
    if cur >= 8:
        runs += 1
    return runs >= 20


def looks_synthetic(path: str, size_limit: int = 64 << 20) -> dict | None:
    """
    判定"疑似合成/占位样本"（MemLens 自带的 synthetic_*.raw 等测试样本）。

    这类样本**模拟了部分字符串/进程名，但没有真实内核结构**，因此：
      · MemProcFS 打不开（DEVICE_OPEN failed）——缺真实内存采集元数据；
      · vol3 认不出内核（未定位到 Windows 内核符号层）——无 ntkrnl/内核结构。

    判据（同时满足，只对 **≤64 MB** 的小文件判定，避免误判真实大镜像）：
      1. 零字节占比 ≥ 50%（合成样本多为大量零填充）；
      2. 无 MZ/PE 头；
      3. 无内核特征字符串（ntkrnl / ntoskrnl / kernel）；
      4. 无已知文件魔数（zip/pcap/dmp 等真实小文件不误判）。

    Returns:
        {"synthetic": bool, "zero_pct": float, "detail": str, ...}，无法判断时 None。
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size == 0 or size > size_limit:
        return None
    try:
        with open(path, "rb") as fp:
            blob = fp.read(8 << 20)
    except OSError:
        return None
    if not blob:
        return None
    # 零字节占比：均匀采样（不用 _zero_ratio——它统计"全零块"，分散的零会被漏掉）
    size = os.path.getsize(path)
    zeros = total = 0
    with open(path, "rb", buffering=0) as fp:
        for i in range(16):
            off = int(size * (i + 0.5) / 16)
            off = max(0, min(off, size - (1 << 20))) if size > (1 << 20) else 0
            fp.seek(off)
            d = fp.read(1 << 20)
            if d:
                zeros += d.count(0)
                total += len(d)
    zero = zeros / total if total else 0.0
    has_pe = blob[:2] == b"MZ" or b"PE\x00\x00" in blob[:4096]
    has_kernel = any(k in blob for k in (b"ntkrnl", b"ntoskrnl", b"kernel"))
    has_magic = any(blob.startswith(m) for m, *_ in FILE_MAGICS)
    reasons = []
    if zero >= 0.5:
        reasons.append(f"零字节 {zero * 100:.1f}%")
    if not has_pe:
        reasons.append("无 MZ/PE 头")
    if not has_kernel:
        reasons.append("无内核特征(ntkrnl/ntoskrnl)")
    synthetic = (zero >= 0.5) and (not has_pe) and (not has_kernel) and (not has_magic)
    return {
        "synthetic": synthetic,
        "zero_pct": round(zero * 100, 1),
        "has_pe": has_pe,
        "has_kernel": has_kernel,
        "has_magic": has_magic,
        "size": size,
        "detail": ("，".join(reasons)) if reasons else "",
    }


def _estimate_entropy(path: str, limit: int = 1 << 20) -> float:
    """估算前 limit 字节的 Shannon 熵（用于"疑似加密块"判定）。"""
    try:
        with open(path, "rb") as fp:
            blob = fp.read(limit)
    except OSError:
        return 0.0
    if not blob:
        return 0.0
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


def refresh_warnings(res: ProbeResult, engine_name: str | None) -> ProbeResult:
    """
    按（新的）引擎重算提醒。引擎自动切换后调用，消除语境不符的噪音。

    典型场景：打开 PE 文件 → 探测按内存镜像语境加了"非 4KiB 对齐"警告
    → 自动切到 static 引擎 → 调本函数刷新 → 该警告消失。
    """
    _post_checks(res, for_engine=engine_name)
    return res


def can_analyze(probe: ProbeResult, engine_name: str | None) -> tuple[bool, str]:
    """
    统一判定"当前证据 + 当前引擎"能否分析。**GUI 与 CLI 必须都调这里**。

    起因（真实 bug）：static 引擎的"可用性"与内存引擎完全不同 ——
    PE / ELF / zip / pcap / 甚至未知文件都能做静态画像（static.profile 永不失败），
    所以它们 `analysable=False` 是**正常的、不该拦**。
    早期 GUI 的按钮状态判断做了 static 豁免，但 worker 内部没做，
    结果用户点"开始分析"后弹"需要先解包/转换才能分析" —— 逻辑漂移的典型后果。
    现在只有这一份判断，三处（按钮状态 / worker / CLI）共用。
    """
    # 字节级引擎对**任何**容器都能扫：它只看原始字节，不需要结构化解析。
    # 与 static 同理豁免，否则 memfrag / other 这类"出不了进程表但字符串就在里面"
    # 的证据会被误判为不可分析——而那恰恰是镜像字节扫描最有价值的地方。
    if (engine_name or "").lower() in ("static", "memstrings"):
        return True, ""
    if probe.analysable:
        return True, ""
    return False, (
        f"当前镜像容器为 {probe.container.value}，需要先解包/转换才能分析。"
        f"（{'; '.join(probe.warnings) or '无更多信息'}）"
    )


def _post_checks(res: ProbeResult, for_engine: str | None = None) -> None:
    """
    根据探测结果生成面向用户的提醒（这是"工具帮用户想一步"的地方）。

    支持**重复调用**：引擎切换后可再次调用以重算提醒。
    首次调用记下"基础警告"条数，后续调用先回退到该长度再重建 ——
    这样"文件大小不是 4KiB 整数倍"这类内存镜像专属提醒不会残留在
    静态样本语境里（真实 bug：GUI 探测早于自动切引擎，噪音留在提醒区）。
    """
    if res.warn_base < 0:
        res.warn_base = len(res.warnings)
    else:
        del res.warnings[res.warn_base:]

    # 用户已明确要用 static 引擎时，内存镜像专属的提醒全是噪音 → 整类抑制
    # memstrings 同理：它是字节级扫描，"4KiB 对齐""识别不出 OS"对它没有意义
    static_mode = (for_engine in ("static", "memstrings"))
    # 用户已明确要用 static 引擎时，"请改用 static" 这类提示就是噪音 → 直接抑制
    suppress_static_hint = static_mode

    if not res.size_aligned_4k and not static_mode:
        # 对 PE/ELF/pcap/zip 这类样本，"4KiB 对齐"没有意义，只在内存镜像语境下才提
        res.warnings.append("文件大小不是 4 KiB 的整数倍，可能被截断或不是标准内存镜像")
    if (res.container is ContainerFormat.RAW and res.os_type is OSType.UNKNOWN
            and res.size > 0 and not static_mode):
        res.warnings.append("未能识别操作系统：请确认这是内存镜像而非磁盘镜像/压缩包；"
                            "也可尝试在引擎面板直接跑 banners 插件判定")
    if res.container.needs_unpack:
        res.warnings.append(f"{res.container.value} 是容器格式，需要先解包提取内存段才能分析")
    if res.container is ContainerFormat.WIN_CRASH_DUMP:
        res.warnings.append("Windows 崩溃转储只包含部分物理内存（内核转储更少），"
                            "进程/网络结果可能不完整；优先使用完整内存镜像")
    if res.container in (ContainerFormat.ELF_CORE, ContainerFormat.MINIDUMP):
        res.warnings.append("这是进程级转储而非整机内存镜像，只能做有限分析（不能出完整进程表）")
    if res.container is ContainerFormat.HIBER:
        res.warnings.append("hiberfil.sys 是休眠文件（结构与完整镜像不同），需按休眠镜像方式解析")
    if res.container in (ContainerFormat.DISK_IMAGE, ContainerFormat.FILESYSTEM):
        res.warnings.append(
            "这是**磁盘镜像/文件系统**，不是内存镜像：内存取证插件不会工作。"
            "应改用文件系统解析（分区表 → FAT/NTFS/ext → 文件与目录），"
            "或专门的磁盘取证工具；若要分析内存请提供内存转储。"
        )
    if res.container is ContainerFormat.MEMORY_FRAGMENT:
        res.warnings.append(
            "这是**进程内存段/部分内存转储**，不是整机镜像："
            "可以对其做 strings / 正则 / 熵 分析，或经 vol3 windows.dumpfile 处理，"
            "但**跑不出完整进程表和网络表**（缺内核数据结构）"
        )
    if res.container is ContainerFormat.LOCKED_CONTAINER:
        res.warnings.append(
            "这看起来是**自定义加密容器**（tag + 长度 + 密文）："
            "需先找到对应的加密程序/算法才能还原；可用 static 引擎做画像与熵分析"
        )
    if res.container is ContainerFormat.EXECUTABLE and not suppress_static_hint:
        res.warnings.append("这是 Windows 可执行文件（样本），请改用 **static 静态分析引擎**："
                            "python -m memlens.cli analyze <文件> --engine static")
    if res.container is ContainerFormat.ELF_BIN and not suppress_static_hint:
        res.warnings.append("这是 Linux ELF 可执行/库（样本），请改用 **static 静态分析引擎**："
                            "python -m memlens.cli analyze <文件> --engine static")
    if res.container is ContainerFormat.OTHER and not suppress_static_hint:
        res.warnings.append("未识别为已知证据类型；可先用 static 引擎做画像"
                            "（类型/哈希/熵/字符串），再决定下一步")
    if res.zero_ratio > 0.6:
        res.warnings.append(f"抽样显示约 {res.zero_ratio:.0%} 为全零数据："
                            f"可能是稀疏格式（VMware vmem）或大量未分配页，属正常现象但会影响遍历速度")
    if res.os_confidence < 0.34 and res.os_type is not OSType.UNKNOWN:
        res.warnings.append("操作系统判定置信度偏低，建议以引擎 banners/info 插件结果为准")


def describe(res: ProbeResult) -> str:
    """把探测结果渲染成可读报告（CLI 与 GUI 共用）。"""
    if res.container.is_memory_image:
        tag = "[可直接分析]" if res.analysable else "[需先解包/有限分析]"
    elif res.container is ContainerFormat.MEMORY_FRAGMENT:
        tag = "[进程内存段 → 有限分析：strings/正则/dumpfile，出不了完整进程表]"
    elif res.container is ContainerFormat.LOCKED_CONTAINER:
        tag = "[自定义加密容器 → 需先逆出算法]"
    elif res.container in (ContainerFormat.DISK_IMAGE, ContainerFormat.FILESYSTEM):
        tag = "[磁盘镜像/文件系统 → 内存插件不适用，需按文件系统解析]"
    elif res.container in (ContainerFormat.EXECUTABLE, ContainerFormat.ELF_BIN):
        tag = "[样本文件 → 用 static 引擎做静态分析]"
    else:
        tag = "[尚未识别为已知证据类型]"
    lines: list[str] = []
    lines.append("=" * 68)
    lines.append(f"镜像：{res.path}")
    lines.append(f"大小：{res.size:,} 字节（{res.size / 1048576:,.1f} MiB）"
                 f"{'（4KiB 对齐）' if res.size_aligned_4k else '（⚠ 非 4KiB 对齐）'}")
    lines.append(f"容器格式：{res.container.value}   置信度 {res.container_confidence:.0%}   {tag}")
    lines.append(f"操作系统：{res.os_type.value}   置信度 {res.os_confidence:.0%}"
                 f"   全零抽样比例 {res.zero_ratio:.0%}")
    lines.append("-" * 68)
    lines.append("证据：")
    for ev in res.evidence:
        lines.append(f"  · {ev}")
    if res.os_strings:
        lines.append("系统指纹命中：")
        for k, v in res.os_strings.items():
            if v:
                lines.append(f"  · {k} × {v}")
    if res.warnings:
        lines.append("-" * 68)
        lines.append("提醒：")
        for w in res.warnings:
            lines.append(f"  ! {w}")
    lines.append("=" * 68)
    return "\n".join(lines)
