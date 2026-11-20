"""
MemLens · 分析计划（Plan）

## 为什么要"计划"这一层

LovelyMem 那一类工具的做法是：**上百个按钮**，用户自己点。
问题是"点哪个"本身就是取证知识门槛，而且**分析深度取决于用户会不会点**。

MemLens 的做法相反：**打开附件 = 全量深度分析**。
本模块负责回答一个问题：

> 给定这个文件（容器 + 操作系统），**应该跑哪些引擎、哪些插件、按什么顺序**？

计划是**数据**（PlanItem 列表），不是 if-else 分支：
UI 可以显示"将要做什么"、CLI 可以 `--explain-plan`、Web 前端可以画流水线图。

## 计划的生成原则

1. **声明式 + 运行时枚举**：vol3 的插件清单在运行时枚举（`vol.py --help`），
   再按操作系统前缀（windows./linux./mac.）筛选 —— 绝不把几十个插件名写死在代码里。
2. **按"价值 × 速度"排序**：先跑能立刻给结论的（系统信息、进程、网络），
   再跑慢的（yarascan / dumpfiles），这样即使中途取消也已经有可用结果。
3. **能力探测**：MemProcFS 的产物清单随版本变化，缺失的产物要"跳过并说明"，
   而不是让上层报"产物不存在"（这是 LovelyMem 的静默失败坑）。
4. **跨平台**：Windows / Linux / macOS 各自走各自的插件族；
   通用层（字节扫描、静态分析、时间线、情报、旗标）对三者一视同仁。
"""

from __future__ import annotations

import dataclasses
from typing import Any, Iterable, Sequence

from memlens.core.image_probe import ContainerFormat, OSType, ProbeResult
from memlens.engines.base import EngineAdapter, OutputKind, PluginMeta


# ------------------------------------------------------------------ 数据结构


@dataclasses.dataclass
class PlanItem:
    """计划中的一个待执行项。"""

    engine: str                 # 引擎名（memprocfs / vol3 / memstrings / static）
    plugin: str                 # 插件名（引擎内部标识）
    display: str = ""           # 中文显示名
    category: str = ""          # 分组
    kind: str = "table"         # 输出形态
    required: bool = False      # 失败是否要中断整体
    heavy: bool = False         # 慢任务（界面要单独提示耗时）
    note: str = ""              # 备注（为什么跑它）
    params: dict[str, Any] = dataclasses.field(default_factory=dict)

    def key(self) -> str:
        return f"{self.engine}:{self.plugin}"


@dataclasses.dataclass
class AnalysisPlan:
    """一份完整的分析计划。"""

    os_type: str = "unknown"
    container: str = "unknown"
    items: list[PlanItem] = dataclasses.field(default_factory=list)
    notes: list[str] = dataclasses.field(default_factory=list)
    skipped: list[dict[str, str]] = dataclasses.field(default_factory=list)
    engines: list[str] = dataclasses.field(default_factory=list)

    def by_engine(self, engine: str) -> list[PlanItem]:
        return [i for i in self.items if i.engine == engine]

    def summary(self) -> dict[str, Any]:
        by_engine: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        for i in self.items:
            by_engine[i.engine] = by_engine.get(i.engine, 0) + 1
            by_cat[i.category or "其他"] = by_cat.get(i.category or "其他", 0) + 1
        return {
            "os_type": self.os_type,
            "container": self.container,
            "total": len(self.items),
            "by_engine": by_engine,
            "by_category": by_cat,
            "notes": list(self.notes),
            "skipped": list(self.skipped),
            "items": [
                {
                    "engine": i.engine, "plugin": i.plugin, "display": i.display,
                    "category": i.category, "kind": i.kind, "required": i.required,
                    "heavy": i.heavy, "note": i.note,
                }
                for i in self.items
            ],
        }


# ------------------------------------------------------------------ vol3 插件筛选

#: 明确排除的 vol3 插件（理由写清楚，避免以后有人"顺手加回来"）
#:
#: ⚠ 排除的都是**"会产出巨大文件 / 与其它插件重复"**的，不是"不重要"的：
#:   - `windows.vadregexscan` / `windows.yarascan`：需要 YARA 规则库，空跑几分钟还常 0 行；
#:   - `windows.dumpfiles` / `windows.procdump` / `windows.memmap`：产出上百 MB 的落盘文件，
#:     必须在界面上"按需"触发，不能塞进"打开就跑"的全量流程（磁盘会被塞爆）。
VOL3_EXCLUDE: dict[str, str] = {
    "windows.vadregexscan": "需要正则/YARA 规则库，空跑成本高（可在界面上按需单独执行）",
    "windows.yarascan": "需要 YARA 规则库，空跑成本高（可在界面上按需单独执行）",
    "windows.dumpfiles": "产出体积极大（可达数百 MB），改为按需导出",
    "windows.procdump": "产出体积极大（可达数百 MB），改为按需导出",
    "windows.memmap": "产出体积极大，改为按需导出",
    "windows.vadwalk": "与 vadinfo 重复，收益低",
    "windows.netstat": "与 netscan 重复，保留 netscan",
    "windows.info": "框架插件，只在预检里跑；不重复出现在全量清单",
    "windows.verinfo": "PE 版本信息，MemProcFS 的 modules.csv 已覆盖",
    "windows.statistics": "框架统计插件，内存大小走系统画像通道",
}

#: 需要额外参数、单独跑才有意义的 vol3 插件
VOL3_NEEDS_PARAM: dict[str, str] = {
    "windows.registry.printkey": "需要 -K 键路径",
    "windows.registry.getcellroutine": "需要 -K 键路径",
    "windows.memmap": "需要 --pid",
    "windows.dumpfiles": "需要 --pid",
    "windows.procdump": "需要 --pid",
    "windows.vadinfo": "需要 --pid",
    "windows.vadwalk": "需要 --pid",
    "windows.dlllist": "需要 --pid（无 pid 时产出全量但意义不大）",
    "windows.handles": "需要 --pid",
    "windows.ldrmodules": "需要 --pid",
    "windows.getsids": "需要 --pid",
    "windows.privileges": "需要 --pid",
    "windows.envars": "需要 --pid",
    "windows.threads": "需要 --pid",
    "windows.cmdline": "需要 --pid",
    "windows.pscallstack": "需要 --pid",
    "windows.suspicious_threads": "需要 --pid",
    "windows.suspended_threads": "需要 --pid",
    "windows.processghosting": "需要 --pid",
}

#: 优先级表（越小越先跑）。理由写在旁边 —— 这是"先给结论"的顺序设计。
VOL3_PRIORITY: tuple[tuple[str, int], ...] = (
    # ① 系统画像：最先跑，失败要早知道
    ("windows.info", 1),
    ("windows.statistics", 2),
    ("windows.verinfo", 3),
    ("windows.modules", 5),
    ("windows.modscan", 6),
    # ② 进程：分析的主干
    ("windows.pslist", 10),
    ("windows.psscan", 11),
    ("windows.pstree", 12),
    ("windows.cmdline", 13),
    ("windows.getsids", 14),
    ("windows.envars", 15),
    ("windows.threads", 16),
    ("windows.dlllist", 17),
    ("windows.ldrmodules", 18),
    ("windows.handles", 19),
    ("windows.privileges", 20),
    ("windows.vadinfo", 21),
    # ③ 网络
    ("windows.netscan", 25),
    ("windows.netstat", 26),
    # ④ 恶意代码
    ("windows.malfind", 30),
    ("windows.hollowprocesses", 31),
    ("windows.processghosting", 32),
    ("windows.psxview", 33),
    ("windows.suspicious_threads", 34),
    ("windows.suspended_threads", 35),
    # ⑤ 注册表
    ("windows.registry.hivelist", 40),
    ("windows.registry.hivescan", 41),
    ("windows.registry.userassist", 42),
    ("windows.registry.certificates", 43),
    # ⑥ 服务 / 驱动 / 内核
    ("windows.svcscan", 45),
    ("windows.svclist", 46),
    ("windows.svcdiff", 47),
    ("windows.driverscan", 48),
    ("windows.driverirp", 49),
    ("windows.devicetree", 50),
    ("windows.modules", 51),
    ("windows.ssdt", 52),
    ("windows.callbacks", 53),
    ("windows.unloadedmodules", 54),
    # ⑦ 文件 / 其它
    ("windows.filescan", 60),
    ("windows.mutantscan", 61),
    ("windows.crashinfo", 62),
    ("windows.consoles", 63),
    ("windows.clipboard", 64),
    ("windows.strings", 65),
    # ⑧ 凭据（只做存在性提示）
    ("windows.hashdump", 70),
    ("windows.lsadump", 71),
    ("windows.cachedump", 72),
)

#: Linux 插件优先级
LINUX_PRIORITY: tuple[tuple[str, int], ...] = (
    ("banners", 1),
    ("linux.boottime", 2),
    ("linux.vmcoreinfo", 3),
    ("linux.pslist", 10),
    ("linux.psscan", 11),
    ("linux.pstree", 12),
    ("linux.psaux", 13),
    ("linux.envars", 14),
    ("linux.capabilities", 15),
    ("linux.pscallstack", 16),
    ("linux.proc.Maps", 17),
    ("linux.elfs", 18),
    ("linux.library_list", 19),
    ("linux.bash", 20),
    ("linux.lsof", 25),
    ("linux.sockscan", 26),
    ("linux.sockstat", 27),
    ("linux.ip.Addr", 28),
    ("linux.ip.Link", 29),
    ("linux.netfilter", 30),
    ("linux.malfind", 33),
    ("linux.modxview", 34),
    ("linux.lsmod", 40),
    ("linux.check_modules", 41),
    ("linux.hidden_modules", 42),
    ("linux.check_syscall", 43),
    ("linux.check_idt", 44),
    ("linux.check_afinfo", 45),
    ("linux.check_creds", 46),
    ("linux.keyboard_notifiers", 47),
    ("linux.mountinfo", 50),
    ("linux.pagecache.Files", 51),
    ("linux.pagecache.InodePages", 52),
    ("linux.kthreads", 53),
    ("linux.kallsyms", 54),
    ("linux.iomem", 55),
    ("linux.kmsg", 56),
    ("linux.ebpf", 57),
    ("linux.ptrace", 58),
)

#: macOS 插件优先级
MAC_PRIORITY: tuple[tuple[str, int], ...] = (
    ("mac.pslist", 10),
    ("mac.pstree", 11),
    ("mac.psaux", 12),
    ("mac.proc_maps", 13),
    ("mac.lsof", 25),
    ("mac.netstat", 26),
    ("mac.ifconfig", 27),
    ("mac.malfind", 33),
    ("mac.lsmod", 40),
    ("mac.check_sysctl", 41),
    ("mac.check_syscall", 42),
    ("mac.check_trap_table", 43),
    ("mac.kauth_listeners", 44),
    ("mac.kauth_scopes", 45),
    ("mac.dmesg", 50),
    ("mac.list_files", 51),
    ("mac.vfsevents", 52),
    ("mac.timers", 53),
    ("mac.bash", 20),
    ("mac.kevents", 54),
    ("mac.socket_filters", 55),
    ("mac.graphics.fbdev", 56),
)


def _prio_of(name: str, table: Sequence[tuple[str, int]]) -> int:
    for key, p in table:
        if name == key or name.startswith(key + "."):
            return p
    return 100


def _short(full: str) -> str:
    """`windows.pslist.PsList` → `windows.pslist`（与 vol3 引擎内部口径一致）。"""
    parts = full.split(".")
    if len(parts) >= 2 and parts[-1][:1].isupper():
        return ".".join(parts[:-1])
    return full


def _vol3_items(
    plugins: Iterable[PluginMeta],
    prefixes: Sequence[str],
    priority: Sequence[tuple[str, int]],
    *,
    exclude: dict[str, str],
    notes: list[str],
    skipped: list[dict[str, str]],
) -> list[PlanItem]:
    """按操作系统前缀挑 vol3 插件并排序。"""
    items: list[PlanItem] = []
    for p in plugins:
        short = _short(p.name)
        if not any(short.startswith(pfx) or p.name.startswith(pfx) for pfx in prefixes):
            continue
        if short in exclude or p.name in exclude:
            skipped.append({"plugin": p.name, "reason": exclude.get(short) or exclude.get(p.name, "")})
            continue
        if short in VOL3_NEEDS_PARAM or p.name in VOL3_NEEDS_PARAM:
            skipped.append({
                "plugin": p.name,
                "reason": VOL3_NEEDS_PARAM.get(short) or VOL3_NEEDS_PARAM.get(p.name, ""),
            })
            continue
        items.append(PlanItem(
            engine="vol3",
            plugin=p.name,
            display=p.display,
            category=p.category,
            kind=p.kind.value,
            heavy=_prio_of(short, priority) >= 45,
            note=f"vol3 · {p.category}",
        ))
    items.sort(key=lambda i: (_prio_of(_short(i.plugin), priority), i.plugin))
    return items


# ------------------------------------------------------------------ MemProcFS 产物

#: MemProcFS 产物里"优先级靠前"的（先拿系统画像与主干数据）
MPROCFFS_ORDER: tuple[str, ...] = (
    "mprocfs.harvest",
    "mprocfs.sysinfo",
    "mprocfs.users",
    "mprocfs.productid",
    "mprocfs.procinfo",
    "mprocfs.process",
    "mprocfs.net",
    "mprocfs.netdns",
    "mprocfs.threads",
    "mprocfs.modules",
    "mprocfs.unloaded_modules",
    "mprocfs.handles",
    "mprocfs.services",
    "mprocfs.drivers",
    "mprocfs.devices",
    "mprocfs.findevil",
    "mprocfs.yara",
    "mprocfs.files",
    "mprocfs.registry_run",
    "mprocfs.registry_hives",
    "mprocfs.eventlog",
    "mprocfs.bitlocker",
    "mprocfs.virtualmachines",
    "mprocfs.timeline_process",
    "mprocfs.timeline_net",
    "mprocfs.timeline_registry",
    "mprocfs.timeline_ntfs",
    "mprocfs.timeline_thread",
    "mprocfs.timeline_kernelobject",
    "mprocfs.timeline_web",
    "mprocfs.timeline_all",
)


def _memprocfs_items(plugins: Iterable[PluginMeta], notes: list[str]) -> list[PlanItem]:
    by_name = {p.name: p for p in plugins}
    items: list[PlanItem] = []
    for name in MPROCFFS_ORDER:
        p = by_name.get(name)
        if p is None:
            continue
        if p.needs_params:
            # 需要 pid/key 的在线产物：全量流程不跑（改为按需），但要说明。
            notes.append(f"MemProcFS 产物「{p.display}」需要参数，已归入按需执行")
            continue
        items.append(PlanItem(
            engine="memprocfs", plugin=p.name, display=p.display, category=p.category,
            kind=p.kind.value, required=(name == "mprocfs.harvest"),
            note="MemProcFS 虚拟盘取证",
        ))
    # 计划外的产物也补进来（上游新增产物时自动跟上）
    for p in plugins:
        if p.name in MPROCFSS_SET:
            continue
        if p.needs_params:
            continue
        items.append(PlanItem(
            engine="memprocfs", plugin=p.name, display=p.display, category=p.category,
            kind=p.kind.value, note="MemProcFS 虚拟盘取证（新增产物）",
        ))
    return items


MPROCFSS_SET = set(MPROCFFS_ORDER)


# ------------------------------------------------------------------ 主入口


def build_plan(
    probe: ProbeResult,
    engines: dict[str, EngineAdapter] | None = None,
    *,
    include_bytescan: bool = True,
    include_static: bool = True,
) -> AnalysisPlan:
    """
    依据探测结果生成分析计划。

    Args:
        probe: 探测结果
        engines: 引擎名 → 实例（用于运行时枚举插件清单）
        include_bytescan: 是否包含全镜像字节扫描（flag / IOC 挖掘）
        include_static: 是否包含静态分析（PE/ELF 头、字符串、熵）
    """
    engines = engines or {}
    plan = AnalysisPlan(
        os_type=probe.os_type.value,
        container=probe.container.value,
    )
    notes, skipped = plan.notes, plan.skipped

    container = probe.container
    os_type = probe.os_type

    # ---------- 非内存类证据：走静态分析 ----------
    if not container.is_memory_related and container not in (
        ContainerFormat.UNKNOWN, ContainerFormat.OTHER, ContainerFormat.MEMORY_FRAGMENT,
    ):
        static = engines.get("static")
        if static is not None:
            for p in static.list_plugins():
                plan.items.append(PlanItem(
                    engine="static", plugin=p.name, display=p.display, category=p.category,
                    kind=p.kind.value, note=f"静态分析 · {container.value}",
                ))
        plan.engines = sorted({i.engine for i in plan.items})
        notes.append(f"容器为 {container.value}，按静态/文件分析流程处理")
        return plan

    # ---------- 内存类证据 ----------
    is_memory = container.is_memory_image or container is ContainerFormat.MEMORY_FRAGMENT

    # ① 字节扫描（跨平台通用）：flag / IOC / 凭据碎片
    if include_bytescan and is_memory:
        ms = engines.get("memstrings")
        if ms is not None:
            for p in ms.list_plugins():
                plan.items.append(PlanItem(
                    engine="memstrings", plugin=p.name, display=p.display, category=p.category,
                    kind=p.kind.value, heavy=True,
                    note="全镜像字节扫描：找 flag / IOC / 凭据碎片",
                ))

    # ② 平台专属引擎
    if os_type is OSType.WINDOWS:
        mp = engines.get("memprocfs")
        if mp is not None:
            ok, why = mp.available()
            if ok:
                plan.items.extend(_memprocfs_items(mp.list_plugins(), notes))
                notes.append(f"MemProcFS 可用：{why}")
            else:
                notes.append(f"MemProcFS 不可用（{why}）——Windows 侧将只依赖 vol3")
                skipped.append({"engine": "memprocfs", "reason": why})
        vol3 = engines.get("vol3")
        if vol3 is not None:
            plan.items.extend(_vol3_items(
                vol3.list_plugins(), ("windows.",), VOL3_PRIORITY,
                exclude=VOL3_EXCLUDE, notes=notes, skipped=skipped,
            ))
    elif os_type is OSType.LINUX:
        vol3 = engines.get("vol3")
        if vol3 is not None:
            plan.items.extend(_vol3_items(
                vol3.list_plugins(), ("linux.", "banners"), LINUX_PRIORITY,
                exclude={}, notes=notes, skipped=skipped,
            ))
        notes.append("Linux 镜像：走 vol3 linux.* 插件族 + 字节扫描（MemProcFS 仅支持 Windows）")
    elif os_type is OSType.MACOS:
        vol3 = engines.get("vol3")
        if vol3 is not None:
            plan.items.extend(_vol3_items(
                vol3.list_plugins(), ("mac.",), MAC_PRIORITY,
                exclude={}, notes=notes, skipped=skipped,
            ))
        notes.append("macOS 镜像：走 vol3 mac.* 插件族 + 字节扫描（MemProcFS 仅支持 Windows）")
    else:
        vol3 = engines.get("vol3")
        if vol3 is not None:
            plan.items.extend(_vol3_items(
                vol3.list_plugins(), ("banners",), (),
                exclude={}, notes=notes, skipped=skipped,
            ))
        notes.append("操作系统未能确定：只跑通用插件（banners）+ 字节扫描 + 静态分析")

    # ③ 静态分析（对内存镜像也有价值：可执行文件页的 PE 信息）
    if include_static:
        static = engines.get("static")
        if static is not None and os_type is not OSType.WINDOWS:
            for p in static.list_plugins():
                plan.items.append(PlanItem(
                    engine="static", plugin=p.name, display=p.display, category=p.category,
                    kind=p.kind.value, note="静态分析（PE/ELF 头、字符串、熵）",
                ))

    plan.engines = sorted({i.engine for i in plan.items})
    if not plan.items:
        notes.append("⚠ 计划为空：没有可用引擎（检查 vol3 / MemProcFS 是否就绪）")
    return plan
