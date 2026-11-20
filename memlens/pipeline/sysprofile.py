"""
MemLens · 系统画像合成器（System Profile）

## 要解决的痛点

用户反馈："很多内存取证的信息根本分析不出来，比如系统信息、版本、内存大小等。"

根因不是"没数据"，而是**数据散落在不同产物里、而且没人把它们拼成一张表**：

| 想要的信息 | 真正在哪 | MemProcFS | vol3 | vol2 |
|---|---|---|---|---|
| 系统版本 | `sys/sysinfo/sysinfo.txt` 的 `Version:` | ✅ | `windows.verinfo` | `imageinfo` |
| **物理内存大小** | `sysinfo.txt` 的 `Physical Memory: 2 GB` | ✅ | `windows.statistics` | — |
| CPU 型号 | `sysinfo.txt` 的 `CPU:` | ✅ | — | — |
| 开机时间 | `sysinfo.txt` 的 `Boot Time:` | ✅ | — | — |
| 计算机名 | `sysinfo.txt` 的 `Computer Name:` | ✅ | — | — |
| 用户 + SID | `sys/users/users.txt` | ✅ | `windows.getsids` | — |
| 机器 ID | 注册表 `MachineGuid` | ✅ | — | — |

本模块把这些**归一化**成一张结构化的"系统画像"表：
字段固定、值带**来源**与**置信度**，前端直接渲染成概览卡片。

## 跨平台

* **Windows**：MemProcFS `sysinfo.txt` 为主，vol3 `windows.statistics` / `windows.verinfo` 交叉验证。
* **Linux**：vol3 `banners`（内核版本）/ `linux.boottime` / `linux.vmcoreinfo`；
  物理内存用**字节扫描兜底**（内存里常驻 `/proc/meminfo` 的 `MemTotal:` 文本）。
* **macOS**：vol3 `mac.check_sysctl`（`hw.memsize` 等）/ `mac.pslist`（主机名线索）。

## 为什么要"多来源 + 置信度"

同一个字段可能有三个来源，值不一致时必须**说出来**，而不是随便挑一个。
本模块的做法：按优先级收集候选 → 记录每个候选的来源 → 一致则提升置信度，
不一致则保留全部并标"来源不一致"。
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Iterable, Sequence

# ------------------------------------------------------------------ 归一化字段

#: 系统画像的字段定义（顺序 = 前端展示顺序）
#: (字段名, 中文标签, 分组, 单位)
PROFILE_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("os_name", "操作系统", "系统"),
    ("os_version", "版本", "系统"),
    ("build", "构建号", "系统"),
    ("architecture", "架构", "系统"),
    ("kernel", "内核", "系统"),
    ("hostname", "计算机名", "系统"),
    ("computer_name", "计算机名", "系统"),
    ("domain", "域 / 工作组", "系统"),
    ("cpu_model", "CPU", "硬件"),
    ("cpu_cores", "CPU 核心数", "硬件"),
    ("ram_total_bytes", "物理内存", "硬件"),
    ("ram_free_bytes", "可用内存", "硬件"),
    ("ram_used_bytes", "已用内存", "硬件"),
    ("system_drive", "系统盘", "硬件"),
    ("machine_id", "机器 ID", "标识"),
    ("security_id", "安全 ID", "标识"),
    ("product_id", "产品 ID", "标识"),
    ("registered_owner", "注册所有者", "标识"),
    ("organization", "组织", "标识"),
    ("boot_time", "开机时间", "时间"),
    ("uptime_seconds", "已运行", "时间"),
    ("timezone", "时区", "时间"),
    ("install_date", "安装日期", "时间"),
    ("current_time", "镜像采集时刻", "时间"),
)

#: 分组顺序
PROFILE_GROUPS: tuple[str, ...] = ("系统", "硬件", "标识", "时间")

#: 字节字段（前端要格式化成 GB/MB）
BYTE_FIELDS: frozenset[str] = frozenset(
    {"ram_total_bytes", "ram_free_bytes", "ram_used_bytes", "image_size"}
)


@dataclasses.dataclass
class FieldValue:
    """一个字段的取值 + 来源 + 置信度。"""

    value: Any
    source: str = ""
    confidence: float = 0.5
    alternatives: list[dict[str, Any]] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "source": self.source,
            "confidence": round(float(self.confidence), 3),
            "alternatives": self.alternatives,
        }


@dataclasses.dataclass
class SystemProfile:
    """系统画像。"""

    fields: dict[str, FieldValue] = dataclasses.field(default_factory=dict)
    users: list[dict[str, str]] = dataclasses.field(default_factory=list)
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)
    warnings: list[str] = dataclasses.field(default_factory=list)

    # -------------------------------------------------------------- 写入
    def set(self, field: str, value: Any, source: str, confidence: float = 0.6) -> None:
        """写入一个字段（多来源时合并，不覆盖已有更高置信度的值）。"""
        if value in (None, "", []):
            return
        cur = self.fields.get(field)
        if cur is None:
            self.fields[field] = FieldValue(value, source, confidence)
            return
        if str(cur.value) == str(value):
            # 同一值多来源 → 置信度提升
            cur.confidence = min(0.99, cur.confidence + 0.2)
            if source and source not in cur.source:
                cur.source = f"{cur.source} + {source}"
            return
        # 值不一致 → 记录为候选，按置信度决胜
        alt = {"value": value, "source": source, "confidence": confidence}
        if confidence > cur.confidence:
            cur.alternatives.append({"value": cur.value, "source": cur.source,
                                     "confidence": cur.confidence})
            self.fields[field] = FieldValue(value, source, confidence, cur.alternatives)
        else:
            cur.alternatives.append(alt)

    def add_user(self, name: str, sid: str = "", home: str = "") -> None:
        if not name:
            return
        for u in self.users:
            if u.get("name") == name and u.get("sid") == sid:
                return
        self.users.append({"name": name, "sid": sid, "home": home})

    # -------------------------------------------------------------- 输出
    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {}
        for key, label, group in PROFILE_FIELDS:
            fv = self.fields.get(key)
            if fv is None:
                continue
            data[key] = {
                "label": label,
                "group": group,
                **fv.to_dict(),
            }
        for key, fv in self.fields.items():
            if key in data:
                continue
            data[key] = {"label": key, "group": "其它", **fv.to_dict()}
        return {
            "fields": data,
            "users": list(self.users),
            "extra": dict(self.extra),
            "warnings": list(self.warnings),
            "field_count": len(self.fields),
        }


# ------------------------------------------------------------------ 工具

_SIZE_UNITS: dict[str, int] = {
    "b": 1, "byte": 1, "bytes": 1,
    "k": 1024, "kb": 1024, "kib": 1024,
    "m": 1024 ** 2, "mb": 1024 ** 2, "mib": 1024 ** 2,
    "g": 1024 ** 3, "gb": 1024 ** 3, "gib": 1024 ** 3,
    "t": 1024 ** 4, "tb": 1024 ** 4, "tib": 1024 ** 4,
}

_SIZE_RE = re.compile(
    r"(?i)\s*([0-9][0-9,_]*(?:\.[0-9]+)?)\s*([kmgt]?i?b?)\s*$"
)


def parse_size(text: Any) -> int | None:
    """
    把 "2 GB" / "16,384 MB" / "8388608 KB" / "1.5 GiB" / "0x7fff0000" 解析成字节数。

    这是"内存大小取不到"的第一道坎：MemProcFS 给的是 **"2 GB"** 这种带单位的字符串，
    直接当数字用会得到 2（字节），界面上就显示成"2 B"，看起来像"没分析出来"。
    """
    if text is None:
        return None
    if isinstance(text, (int, float)) and not isinstance(text, bool):
        return int(text)
    s = str(text).strip()
    if not s:
        return None
    if s.lower().startswith("0x"):
        try:
            return int(s, 16)
        except ValueError:
            return None
    m = _SIZE_RE.search(s)
    if not m:
        try:
            return int(s.replace(",", "").strip())
        except ValueError:
            return None
    num = float(m.group(1).replace(",", ""))
    unit = m.group(2).lower()
    if unit in ("", "b"):
        mult = 1
    else:
        mult = _SIZE_UNITS.get(unit, 1)
    return int(num * mult)


def human_size(num: Any) -> str:
    """字节数 → 人类可读。"""
    try:
        n = int(num)
    except (TypeError, ValueError):
        return ""
    if n <= 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            if unit == "B":
                return f"{n} B"
            return f"{n:.2f} {unit}".rstrip("0").rstrip(".") if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.2f} TB"


def _norm(k: str) -> str:
    return "".join(ch for ch in str(k).lower() if ch.isalnum())


def _lookup(record: dict[str, Any], *patterns: str) -> Any:
    """在异构记录里按"包含"匹配找值（忽略大小写/下划线/空格）。"""
    if not isinstance(record, dict):
        return None
    normed = {_norm(k): v for k, v in record.items()}
    for pat in patterns:
        key = _norm(pat)
        if key in normed:
            v = normed[key]
            if v not in (None, ""):
                return v
    for pat in patterns:
        key = _norm(pat)
        for k, v in normed.items():
            if key in k and v not in (None, ""):
                return v
    return None


def _to_int(value: Any) -> int | None:
    try:
        if isinstance(value, str):
            value = value.strip().replace(",", "")
            if not value:
                return None
            return int(float(value))
        return int(value)
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ MemProcFS sysinfo

_SECTION_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 \-/]{2,40}):\s*$")
_KV_RE = re.compile(r"^([^:]{1,60}):\s*(.*)$")
_USER_SID_RE = re.compile(r"^(?P<path>.*?)\s*\((?P<sid>S-1-[0-9\-]+)\)\s*$")


def parse_memprocfs_sysinfo(text: str) -> dict[str, Any]:
    """
    解析 MemProcFS 的 `sys/sysinfo/sysinfo.txt`。

    实测结构（MemProcFS 5.x / 13.x 一致）：

        Windows Information:
        -------------------
        Computer Name: WIN-ABC
        Current Time: 2024-01-01 10:00:00
        Boot Time: 2023-12-31 22:00:00
        Time Zone: (UTC+08:00) 北京,标准时间
        Version: 6.1 (build 7601)

        Hardware Information:
        --------------------
        Architecture: X64
        Physical Memory: 2 GB
        CPU: 12th Gen Intel Core i7-12700
        ...

        Users:
        ------
        Administrator (S-1-5-21-...-500)
        C:\\Users\\Administrator (S-1-5-21-...-500-1)

    Returns: 归一化字段 dict + 原始 section 数据
    """
    out: dict[str, Any] = {}
    sections: dict[str, dict[str, str]] = {}
    raw_sections: dict[str, list[str]] = {}
    current = "General"
    sections.setdefault(current, {})
    raw_sections.setdefault(current, [])

    for raw in (text or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        m_sec = _SECTION_RE.match(line.strip())
        if m_sec:
            current = m_sec.group(1).strip()
            sections.setdefault(current, {})
            raw_sections.setdefault(current, [])
            continue
        if set(line.strip()) <= set("-= ") and len(line.strip()) >= 3:
            continue                        # 分隔线
        raw_sections[current].append(line.strip())
        m = _KV_RE.match(line.strip())
        if m:
            key, val = m.group(1).strip(), m.group(2).strip()
            if key and val:
                sections[current].setdefault(key, val)

    flat: dict[str, Any] = {}
    for sec in sections.values():
        for k, v in sec.items():
            # ⚠ **首次出现优先**，不能"后者覆盖前者"：
            #   sysinfo.txt 里 `Windows Information: Version: 6.1 (build 7601)`
            #   与 `MemProcFS Information: Version: 5.18.1 (build 240)` **键名完全相同**。
            #   后者覆盖前者 ⇒ 系统版本变成 MemProcFS 自己的版本号
            #   （实测踩过：画像显示 "Windows 5.18 / build 240"，完全不是被检系统）。
            flat.setdefault(k, v)
    lower = {_norm(k): v for k, v in flat.items()}

    def get(*keys: str) -> Any:
        for k in keys:
            kk = _norm(k)
            if kk in lower:
                return lower[kk]
        for k in keys:
            kk = _norm(k)
            for kk2, v in lower.items():
                if kk in kk2:
                    return v
        return None

    # ---- 操作系统 / 版本 ----
    ver = get("version", "osversion", "operatingsystemversion")
    if ver:
        out["os_version"] = str(ver)
        m = re.search(r"(?i)build\s*([0-9]+)", str(ver))
        if m:
            out["build"] = m.group(1)
        m2 = re.match(r"\s*([0-9]+(?:\.[0-9]+)*)", str(ver))
        if m2:
            out["os_version_short"] = m2.group(1)

    # ---- 架构 ----
    arch = get("architecture", "arch", "processarch", "osarch")
    if arch:
        out["architecture"] = str(arch)

    # ---- 物理内存（★ 用户最关心的"内存大小"）----
    phys = get("physicalmemory", "physicalmemorysize", "totalphysicalmemory",
               "ram", "memsize", "totalmemory", "memorysize")
    if phys:
        n = parse_size(phys)
        if n:
            out["ram_total_bytes"] = n
            out["ram_total_text"] = str(phys)

    # ---- CPU ----
    cpu = get("cpu", "cpumodel", "processor", "processorname", "modelname")
    if cpu:
        out["cpu_model"] = str(cpu)
    cores = get("cpucores", "processorcount", "numberofprocessors", "logicalprocessors",
                "cpucount", "cpucountlogical")
    if cores:
        n = _to_int(cores)
        if n:
            out["cpu_cores"] = n

    # ---- 主机 / 时间 ----
    for key, names in (
        ("computername", ("computername", "hostname", "systemname", "machinename")),
        ("time_zone", ("timezone", "timezonename", "tz")),
        ("boot_time", ("boottime", "lastboottime", "startup")),
        ("current_time", ("currenttime", "now", "time", "capturetime")),
        ("max_address", ("maxaddress",)),
        ("system_vendor", ("systemvendor", "vendor")),
        ("bios_vendor", ("biosvendor",)),
        ("mb_vendor", ("mbvendor", "mainboardvendor")),
        ("mb_product", ("mbproduct", "mainboardproduct")),
        ("product_id", ("productid",)),
    ):
        v = get(*names)
        if v:
            out[key] = str(v)

    # ---- 用户（含 SID）----
    users: list[dict[str, str]] = []
    for line in raw_sections.get("Users", []) + raw_sections.get("Users Information", []):
        m = _USER_SID_RE.match(line)
        if not m:
            continue
        path = m.group("path").strip()
        sid = m.group("sid")
        name = path
        home = ""
        if "\\" in path or "/" in path:
            home = path
            name = path.replace("\\", "/").rstrip("/").split("/")[-1]
        users.append({"name": name, "sid": sid, "home": home})
    if users:
        out["users"] = users

    # ---- 进程数 ----
    active = get("active")
    inactive = get("inactive")
    if active is not None:
        out["active_processes"] = _to_int(active)
    if inactive is not None:
        out["inactive_processes"] = _to_int(inactive)

    out["_sections"] = {k: v for k, v in sections.items()}
    out["_raw_sections"] = raw_sections
    return out


# ------------------------------------------------------------------ vol3 记录解析


def parse_vol3_statistics(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """从 vol3 `windows.statistics` 的记录里抽内存/系统信息。"""
    out: dict[str, Any] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        label = _lookup(rec, "statistic", "name", "key", "variable")
        value = _lookup(rec, "value", "val", "amount")
        if label is None or value is None:
            continue
        label_s = str(label)
        low = _norm(label_s)
        # ⚠ 顺序很重要："Available Physical Memory" 里**也**含 "physicalmemory"，
        #    若先判总量就会把"可用内存"误当成"总内存"（实测踩过：总内存被写成 1 GB）。
        if "availablephysicalmemory" in low or "freephysicalmemory" in low:
            n = _to_int(value)
            if n:
                out.setdefault("ram_free_bytes", n)
                out.setdefault("_ram_free_source", f"vol3 windows.statistics · {label_s}")
        elif "physicalmemory" in low or low == "totalphysicalmemory":
            n = _to_int(value)
            if n:
                out.setdefault("ram_total_bytes", n)
                out.setdefault("_ram_source", f"vol3 windows.statistics · {label_s}")
        elif "virtualmemory" in low and "total" in low:
            n = _to_int(value)
            if n:
                out.setdefault("total_virtual_memory", n)
        elif low in ("systemuptime", "uptime", "uptimeinseconds"):
            n = _to_int(value)
            if n:
                out.setdefault("uptime_seconds", n)
        elif "processtime" in low or "systemtime" in low:
            pass
    return out


def parse_linux_records(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """从 vol3 linux.* 记录里抽内核版本 / 内存大小 / 主机名。"""
    out: dict[str, Any] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        low_keys = [_norm(k) for k in rec.keys()]
        joined = " ".join(low_keys)
        if "osrelease" in joined or "linuxversion" in joined or "kernelversion" in joined:
            for k, v in rec.items():
                if _norm(k) in ("osrelease", "linuxversion", "kernelversion") and v:
                    out.setdefault("kernel", str(v))
                    out.setdefault("os_version", str(v))
        if "cmdline" in joined or "commandline" in joined:
            v = _lookup(rec, "cmdline", "commandline", "bootargs", "args")
            if v:
                out.setdefault("boot_command_line", str(v))
        if "hostname" in joined or "nodename" in joined:
            v = _lookup(rec, "hostname", "nodename")
            if v:
                out.setdefault("hostname", str(v))
        if "physical" in joined and "memory" in joined:
            n = _to_int(_lookup(rec, "value", "count", "pages", "size"))
            if n:
                # 页数 → 字节
                out.setdefault("ram_total_bytes", n * 4096)
                out.setdefault("_ram_source", "vol3 linux.vmcoreinfo · 物理内存页数×4K")
        if "memsize" in joined or "memtotal" in joined or "totalam" in joined:
            n = _to_int(_lookup(rec, "value", "size", "bytes"))
            if n:
                out.setdefault("ram_total_bytes", n)
        if "boot" in joined and "time" in joined:
            v = _lookup(rec, "value", "boottime", "time")
            if v:
                out.setdefault("boot_time", str(v))
    return out


def parse_macos_records(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """从 vol3 mac.* 记录里抽 sysctl（hw.memsize 等）与主机名。"""
    out: dict[str, Any] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        name = _lookup(rec, "name", "sysctl", "key")
        value = _lookup(rec, "value", "val")
        if name is None or value is None:
            continue
        n = str(name)
        if "hw.memsize" in n:
            num = _to_int(value)
            if num:
                out.setdefault("ram_total_bytes", num)
                out.setdefault("_ram_source", f"vol3 mac.check_sysctl · {n}")
        elif "hw.ncpu" in n or "hw.physicalcpu" in n:
            num = _to_int(value)
            if num:
                out.setdefault("cpu_cores", num)
        elif "kern.osrelease" in n:
            out.setdefault("kernel", str(value))
            out.setdefault("os_version", str(value))
        elif "kern.version" in n:
            out.setdefault("os_version", str(value))
        elif "hw.model" in n:
            out.setdefault("cpu_model", str(value))
    return out


# ------------------------------------------------------------------ 字节扫描兜底

_MEMTOTAL_RE = re.compile(rb"MemTotal:\s*(\d+)\s*kB")
_HWMEMSIZE_RE = re.compile(rb"hw\.memsize\s*[:=]\s*(\d{6,})")
_TOTPHYS_RE = re.compile(rb"Total Physical Memory\s*[:=]\s*([0-9,]+)")
_PHYSMEM_RE = re.compile(rb"Physical Memory\s*[:=]\s*([0-9,]+)\s*(MB|GB|KB)?", re.IGNORECASE)


def scan_memory_size_from_bytes(path: str, *, window: int = 512 << 20) -> dict[str, Any]:
    """
    在镜像字节里找内存大小的"文本残留"（兜底通道）。

    原理：内存镜像里经常残留 /proc/meminfo 的副本（htop/top 会缓存），
    以及 Windows 的 "Total Physical Memory" 文本；macOS 则是 `hw.memsize` 缓存。
    这条通道**独立于任何引擎**，因此在 vol3 符号表拿不到时依然能给出内存大小。

    只扫前 `window` 字节（默认 512 MiB），避免大镜像全盘扫。
    """
    out: dict[str, Any] = {}
    try:
        import os

        size = os.path.getsize(path)
        with open(path, "rb") as fp:
            read = 0
            tail = b""
            chunk = 8 << 20
            while read < min(size, window):
                blob = fp.read(chunk)
                if not blob:
                    break
                buf = tail + blob
                if "ram_total_bytes" not in out:
                    m = _MEMTOTAL_RE.search(buf)
                    if m:
                        kb = int(m.group(1))
                        out["ram_total_bytes"] = kb * 1024
                        out["_ram_source"] = "镜像字节残留 /proc/meminfo: MemTotal"
                if "ram_total_bytes" not in out:
                    m = _HWMEMSIZE_RE.search(buf)
                    if m:
                        out["ram_total_bytes"] = int(m.group(1))
                        out["_ram_source"] = "镜像字节残留 sysctl: hw.memsize"
                if "ram_total_bytes" not in out:
                    m = _TOTPHYS_RE.search(buf)
                    if m:
                        out["ram_total_bytes"] = parse_size(m.group(1).decode("ascii", "ignore"))
                        out["_ram_source"] = "镜像字节残留: Total Physical Memory"
                if "ram_total_bytes" not in out:
                    m = _PHYSMEM_RE.search(buf)
                    if m:
                        raw = m.group(1).decode("ascii", "ignore")
                        unit = (m.group(2) or "MB").upper()
                        n = parse_size(f"{raw} {unit}")
                        if n:
                            out["ram_total_bytes"] = n
                            out["_ram_source"] = "镜像字节残留: Physical Memory"
                if "ram_total_bytes" in out:
                    break
                tail = buf[-256:]
                read += len(blob)
    except Exception:
        pass
    return out


# ------------------------------------------------------------------ 组装


def build_profile(
    *,
    probe_os: str = "unknown",
    sysinfo_text: str | None = None,
    users_text: str | None = None,
    vol3_records: dict[str, list[dict[str, Any]]] | None = None,
    image_path: str | None = None,
    image_size: int | None = None,
    image_sha256: str | None = None,
    container: str = "",
    extra: dict[str, Any] | None = None,
    scan_bytes: bool = True,
) -> SystemProfile:
    """
    把多来源的原始数据合成一张系统画像。

    Args:
        probe_os: 探测出的操作系统（windows/linux/macos/unknown）
        sysinfo_text: MemProcFS `sys/sysinfo/sysinfo.txt` 全文
        users_text:   MemProcFS `sys/users/users.txt` 全文
        vol3_records: {"<插件名>": [记录…]}，来自各 vol3 产物
        image_path / image_size / image_sha256: 镜像自身信息
        scan_bytes:  是否允许"镜像字节兜底扫描"（扫前 256 MiB 找内存大小残留）。
                    ⚠ **建案阶段必须传 False** —— 实测这一项要读 256–512 MB，
                    2 GB 镜像上就是 **3.6 秒**，会让"打开文件"看起来卡住。
                    它属于**分析阶段**的工作（那时已经在后台跑、有进度可看）。
    """
    p = SystemProfile()
    vol3_records = vol3_records or {}

    # ---------------- ① MemProcFS sysinfo（Windows 主力）----------------
    if sysinfo_text:
        d = parse_memprocfs_sysinfo(sysinfo_text)
        src = "MemProcFS sys/sysinfo/sysinfo.txt"

        def put(field: str, value: Any, conf: float = 0.85) -> None:
            if value in (None, ""):
                return
            p.set(field, value, src, conf)

        ver = d.get("os_version")
        if ver:
            p.set("os_version", str(ver), src, 0.85)
            m = re.search(r"(?i)build\s*([0-9]+)", str(ver))
            if m:
                p.set("build", m.group(1), src, 0.85)
            p.set("os_name", _windows_name(str(ver)), src, 0.7)
        put("architecture", d.get("architecture"))
        put("cpu_model", d.get("cpu_model"))
        put("cpu_cores", d.get("cpu_cores"))
        put("ram_total_bytes", d.get("ram_total_bytes"))
        put("boot_time", d.get("boot_time"))
        put("timezone", d.get("time_zone"))
        put("current_time", d.get("current_time"))
        put("computer_name", d.get("computername"))
        put("product_id", d.get("product_id"))
        put("system_drive", d.get("systemdrive"))
        put("registered_owner", d.get("registeredowner"))
        put("organization", d.get("organization"))
        put("machine_id", d.get("machineguid") or d.get("machineid"))
        put("security_id", d.get("securityid"))
        put("install_date", d.get("installdate"))
        for u in d.get("users", []) or []:
            p.add_user(u.get("name", ""), u.get("sid", ""), u.get("home", ""))
        for k in ("max_address", "system_vendor", "bios_vendor", "mb_vendor",
                  "mb_product", "active_processes", "inactive_processes"):
            if d.get(k) not in (None, ""):
                p.extra.setdefault(k, d[k])

    # ---------------- ② MemProcFS users.txt ----------------
    if users_text:
        for line in (users_text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            m = _USER_SID_RE.match(line)
            if m:
                path, sid = m.group("path").strip(), m.group("sid")
                name = path.replace("\\", "/").rstrip("/").split("/")[-1] or path
                p.add_user(name, sid, path)
            elif " " in line:
                name, rest = line.split(" ", 1)
                p.add_user(name, rest.strip())

    # ---------------- ③ vol3 记录 ----------------
    for plugin, records in vol3_records.items():
        low = plugin.lower()
        if "statistics" in low or "statistic" in low:
            d = parse_vol3_statistics(records)
        elif low.startswith("linux") or "banners" in low:
            d = parse_linux_records(records)
        elif low.startswith("mac."):
            d = parse_macos_records(records)
        else:
            continue
        for k, v in d.items():
            if k.startswith("_"):
                continue
            p.set(k, v, f"vol3 {plugin}", 0.6)
        if d.get("_ram_source"):
            p.set("ram_total_bytes", d["ram_total_bytes"], d["_ram_source"], 0.75)

    # ---------------- ④ 字节扫描兜底 ----------------
    if scan_bytes and image_path and "ram_total_bytes" not in p.fields:
        d = scan_memory_size_from_bytes(image_path)
        if d.get("ram_total_bytes"):
            p.set("ram_total_bytes", d["ram_total_bytes"], d.get("_ram_source", "镜像字节扫描"), 0.45)
            p.warnings.append("物理内存大小来自镜像字节残留（置信度较低），非结构化来源")

    # ---------------- ⑤ 镜像自身 ----------------
    if image_size:
        p.extra["image_size"] = image_size
    if image_sha256:
        p.extra["image_sha256"] = image_sha256
    if container:
        p.extra["container"] = container
    if probe_os:
        p.set("os_family", probe_os, "MemLens 探测", 0.9)
        if "os_name" not in p.fields:
            p.set("os_name", {"windows": "Windows", "linux": "Linux",
                               "macos": "macOS"}.get(probe_os, "未知"), "MemLens 探测", 0.5)

    # ---------------- ⑥ 派生量 ----------------
    total = p.fields.get("ram_total_bytes")
    free = p.fields.get("ram_free_bytes")
    if total and free:
        try:
            p.set("ram_used_bytes", int(total.value) - int(free.value),
                  "由总内存−可用内存推算", 0.5)
        except Exception:
            pass

    if extra:
        for k, v in extra.items():
            if v not in (None, ""):
                p.extra[k] = v

    return p


def _windows_name(version: str) -> str:
    """从 "6.1 (build 7601)" 推出 "Windows 7 SP1"。"""
    m = re.match(r"\s*(\d+)\.(\d+)", version or "")
    if not m:
        return "Windows"
    major, minor = int(m.group(1)), int(m.group(2))
    base = {
        (5, 0): "Windows 2000", (5, 1): "Windows XP", (5, 2): "Windows XP",
        (6, 0): "Windows Vista", (6, 1): "Windows 7", (6, 2): "Windows 8",
        (6, 3): "Windows 8.1", (10, 0): "Windows 10 / 11",
    }.get((major, minor), f"Windows {major}.{minor}")
    return base


# ------------------------------------------------------------------ 报告用


def profile_to_markdown(profile: SystemProfile, *, case: dict[str, Any] | None = None) -> str:
    """系统画像 → Markdown 表格（可直接贴进报告）。"""
    data = profile.to_dict()
    lines = ["| 项目 | 值 | 来源 | 置信度 |", "|---|---|---|---|"]
    for key, label, group in PROFILE_FIELDS:
        f = data["fields"].get(key)
        if not f:
            continue
        val = f["value"]
        if key in BYTE_FIELDS:
            val = f"{human_size(val)}（{val} 字节）"
        lines.append(f"| {label} | {val} | {f['source']} | {int(f['confidence'] * 100)}% |")
    if profile.users:
        lines.append("")
        lines.append("**本机用户**")
        lines.append("")
        lines.append("| 用户名 | SID | 用户目录 |")
        lines.append("|---|---|---|")
        for u in profile.users:
            lines.append(f"| {u.get('name','')} | {u.get('sid','')} | {u.get('home','')} |")
    if profile.warnings:
        lines.append("")
        for w in profile.warnings:
            lines.append(f"> ⚠ {w}")
    return "\n".join(lines)
