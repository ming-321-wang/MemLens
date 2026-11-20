r"""
MemLens · MemProcFS 引擎（虚拟盘取证）

## 为什么要有这个引擎（这是补上"工具没结果"的关键一环）

Volatility3 是"一次一个插件、每次重新解析镜像"的模型：跑 6 个插件要 40 秒，
跑一次 filescan/registry 动辄几分钟，且**几乎不产出注册表与事件日志**。
MemProcFS（ufrisk）是另一种模型：**常驻进程把内存镜像挂成一个虚拟盘**（如 `M:\`），
内核符号解析、页表重建只做一次，之后所有取证数据都是**读文件**：

    M:\\forensic\\csv\\process.csv      进程（PID/父进程/用户/命令行/PEB 偏移）
    M:\\forensic\\csv\\net.csv          网络连接（含所属进程与进程路径）
    M:\\forensic\\csv\\findevil.csv     异常检测（高熵可执行内存 = 注入/木马）
    M:\\forensic\\csv\\timeline_*.csv   进程/线程/注册表/文件/网络 时间线
    M:\\sys\\sysinfo\\sysinfo.txt       系统信息（版本/启动时间/硬件）
    M:\\sys\\users\\users.txt           用户与 SID
    M:\\registry\\HKLM\\...             **注册表按文件系统读**（键=目录，值=文件）
    M:\\registry\\hive_files\\*.reghive 原始配置单元（可离线解 SAM/LSA 凭据）
    M:\\misc\\eventlog\\*.evtx          事件日志
    M:\\misc\\bitlocker\\                BitLocker 恢复信息
    M:\\pid\\<PID>\\memory.vmem         单个进程的完整内存 dump（CTF 常客）

实测（2 GB Windows 7 SP1 x64 镜像）：`-forensic 1` 43 秒产出 22 个 CSV + 全部注册表 hive。

## 与上层契约的对接方式

MemProcFS 不是"命令行跑一次拿一份 stdout"，所以本引擎实现 `analyze_file(...)`，
走 TaskRunner 的**内置引擎分支**：

    第一次调用：启动 MemProcFS（forensic）→ 等 "Forensic mode completed" → 把产物
                复制进工作目录（脱离挂载点，之后不再依赖 M:）→ 记 manifest
    后续调用：  直接读已收获的本地文件（毫秒级），不再启动进程

## 安全与工程约定（血泪条款）

1. **绝不写 MemProcFS 自己的安装目录**：本机 E: 盘那份是用户购买的比赛工具包，只读红线。
   MemLens 用的是自己的副本（tools/MemProcFS），符号也只下载到自己这边。
2. **自己挑一个空闲盘符挂载**（默认从 Z 往下找）：用户可能同时开着 LovelyMem（占 M:），
   直接抢 M: 会让两边都废。
3. **收获完必须杀进程**：否则留下常驻服务与盘符，用户下次跑会因为"盘符被占"失败。
4. **失败要说真话**：进程提前退出、挂载点不出现、forensic 未完成 —— 都要抛异常或给出
   明确 error，绝不返回"空结果 + 成功"。
"""

from __future__ import annotations

import csv
import dataclasses
import hashlib
import io
import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

from memlens.engines.base import EngineAdapter, OutputKind, PluginMeta, RunSpec

# ---------------------------------------------------------------- 常量

EXE_NAME = "memprocfs.exe"
#: 挂载盘符候选（从后往前找空闲的；M 是 MemProcFS 默认，留给别人的工具）
_MOUNT_CANDIDATES = "ZYXWVUTSRQPONLKJI"
#: 产物收获的总体超时（首次含符号下载；实测 2GB 镜像 43s，给足余量）
DEFAULT_HARVEST_TIMEOUT = 1800.0
#: 轻量挂载（不跑 forensic，用于按需 dump/读注册表键）超时
DEFAULT_LIVE_TIMEOUT = 300.0
#: 单个 CSV 入库的行数上限（timeline_all 可达十万行级，防止一次塞爆数据库）
DEFAULT_MAX_ROWS = 200_000
#: 收获布局版本。**改动收获路径/字段时必须 +1**：旧 manifest 会被判为过期并重新收集，
#: 否则用户会一直吃"旧格式缓存"的亏（真实踩过：路径映射改了但缓存不失效）。
HARVEST_VERSION = 2
_FORENSIC_DONE_RE = re.compile(r"Forensic mode completed in\s+([\d.]+)s", re.IGNORECASE)
#: 单进程内存 dump 的实际写入硬上限（字节）：稀疏文件展开的风险兜底（2 GB）
_DUMP_HARD_LIMIT = 2 * 1024 * 1024 * 1024
#: 自动挑"值得 dump 的进程"时用的启发式（与检测器口径一致，避免两套标准）
_SUSP_PATH_RE = re.compile(
    r"(\\Temp\\|\\AppData\\|\\Users\\Public\\|\\Downloads\\|\\PerfLogs\\)", re.IGNORECASE)
_TOOL_HINT_RE = re.compile(
    r"(antsword|behinder|冰蝎|godzilla|哥斯拉|mimikatz|procdump|pwdump|wce|"
    r"nc\.exe|frp|ngrok|chisel|meterpreter|beacon|evil|hack|backdoor|webshell)",
    re.IGNORECASE)
_FORENSIC_STEP_RE = re.compile(r"\[FORENSIC\]\s+(?:FC_)?([A-Z0-9_]+)\s*(.*)$")
_FATAL_RE = re.compile(
    r"(Failed to open|Unable to open|unsupported|not supported|"
    r"ReadProcessMemory failed|DEVICE: Failed|Symbol|access denied|Out of memory)",
    re.IGNORECASE,
)


class MemProcFSUnavailable(RuntimeError):
    """引擎环境不满足（找不到 exe / 无法启动）。"""


class HarvestFailed(RuntimeError):
    """取证收集失败。"""


# ---------------------------------------------------------------- 产物目录


@dataclasses.dataclass(frozen=True)
class Artifact:
    """一个可收获的取证产物（= MemLens 里的一个"插件"）。"""

    name: str
    display: str
    category: str
    kind: OutputKind
    rel: str = ""                      # 相对挂载根的路径（CSV / 文本类）
    description: str = ""
    needs_params: tuple[str, ...] = ()
    online: bool = False               # True = 需要挂载点仍然在线（live 挂载按需读）


#: 产物目录：**数据驱动**，新增一个产物只需加一行（上层 GUI/CLI 零改动）。
ARTIFACTS: tuple[Artifact, ...] = (
    # ---- 汇总（第一条触发收集，给用户一个可见的起点）----
    Artifact("mprocfs.harvest", "① 取证收集（启动 MemProcFS 并收获产物）", "系统",
             OutputKind.SCALAR, description="启动 MemProcFS 取证模式，等待其完成并把产物收到工作目录"),
    Artifact("mprocfs.sysinfo", "系统信息（版本/启动时间/硬件）", "系统",
             OutputKind.SCALAR, rel="sys/sysinfo/sysinfo.txt"),
    Artifact("mprocfs.users", "本机用户与 SID", "凭据",
             OutputKind.TABLE, rel="sys/users/users.txt"),
    Artifact("mprocfs.productid", "系统 ProductId / 安装信息", "系统",
             OutputKind.SCALAR, rel="registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/ProductId"),
    # ---- 进程 / 线程 ----
    Artifact("mprocfs.process", "进程列表（含命令行与用户）", "进程",
             OutputKind.TABLE, rel="forensic/csv/process.csv",
             description="MemProcFS process.csv：PID/PPID/用户/完整性级别/命令行/PEB"),
    Artifact("mprocfs.threads", "线程列表", "进程",
             OutputKind.TABLE, rel="forensic/csv/threads.csv"),
    Artifact("mprocfs.modules", "进程模块（DLL/SYS，含版本信息）", "进程",
             OutputKind.TABLE, rel="forensic/csv/modules.csv"),
    Artifact("mprocfs.unloaded_modules", "已卸载模块（无文件 DLL 线索）", "恶意代码",
             OutputKind.TABLE, rel="forensic/csv/unloaded_modules.csv"),
    Artifact("mprocfs.handles", "句柄列表", "进程",
             OutputKind.TABLE, rel="forensic/csv/handles.csv"),
    Artifact("mprocfs.proc_view", "单进程视图（命令行/环境变量/当前目录）", "进程",
             OutputKind.TABLE, needs_params=("pid",),
             description="读 M:\\pid\\<PID>\\ 下的文本信息（需挂载点在线）", online=True),
    Artifact("mprocfs.dump_process", "导出单进程内存（memory.vmem）", "进程",
             OutputKind.FILE_SET, needs_params=("pid",), online=True,
             description="把 M:\\pid\\<PID>\\memory.vmem 复制到工作目录，再用字符串/静态分析找 flag 与凭据"),
    Artifact("mprocfs.envs", "全部进程环境变量（flag 经典藏身处）", "凭据",
             OutputKind.TABLE,
             description="来自收获的 pid\\<PID>\\win-environment.txt；比全镜像字节扫快几个数量级"),
    Artifact("mprocfs.cmdlines", "全部进程命令行/路径/窗口标题/创建时间", "进程",
             OutputKind.TABLE,
             description="来自收获的 pid\\<PID>\\{win-cmdline,win-path,win-title,time-create}.txt"),
    Artifact("mprocfs.flag_hits", "★ flag 速扫（在全部收获文本里找 flag）", "凭据",
             OutputKind.TABLE,
             description="秒级：对 process/timeline/注册表/环境变量等收获文本做 flag 正则扫描"),
    # ---- 网络 ----
    Artifact("mprocfs.net", "网络连接（TCP/UDP + 归属进程）", "网络",
             OutputKind.TABLE, rel="forensic/csv/net.csv"),
    Artifact("mprocfs.netdns", "DNS 缓存/解析记录", "网络",
             OutputKind.TABLE, rel="forensic/csv/netdns.csv"),
    # ---- 恶意代码 / 异常 ----
    Artifact("mprocfs.findevil", "异常检测 findevil（高熵内存/注入）", "恶意代码",
             OutputKind.TABLE, rel="forensic/csv/findevil.csv",
             description="MemProcFS 内建异常检测：HIGH_ENTROPY/PAGE_EXECUTE 等"),
    Artifact("mprocfs.yara", "YARA 命中（内置规则集）", "恶意代码",
             OutputKind.TABLE, rel="forensic/csv/yara.csv"),
    Artifact("mprocfs.drivers", "驱动列表", "恶意代码",
             OutputKind.TABLE, rel="forensic/csv/drivers.csv"),
    Artifact("mprocfs.services", "服务列表（含镜像路径与启动类型）", "服务",
             OutputKind.TABLE, rel="forensic/csv/services.csv"),
    Artifact("mprocfs.devices", "设备对象", "其他",
             OutputKind.TABLE, rel="forensic/csv/devices.csv"),
    Artifact("mprocfs.virtualmachines", "虚拟机痕迹", "其他",
             OutputKind.TABLE, rel="forensic/csv/virtualmachines.csv"),
    # ---- 文件 ----
    Artifact("mprocfs.files", "文件对象", "文件",
             OutputKind.TABLE, rel="forensic/csv/files.csv"),
    # ---- 注册表 ----
    Artifact("mprocfs.registry_run", "自启动项 Run / RunOnce（HKLM + 各用户）", "注册表",
             OutputKind.TABLE, description="键值在收集阶段抓取（键=目录，值=文件）"),
    Artifact("mprocfs.registry_proxy", "代理配置（HKLM/HKU Internet Settings）", "注册表",
             OutputKind.TABLE,
             description="系统级与用户级代理设置（ProxyEnable/ProxyServer/AutoConfigURL），"
                         "通道配置维度的核心数据源"),
    Artifact("mprocfs.registry_hives", "注册表配置单元（原始 hive，可离线解凭据）", "注册表",
             OutputKind.TABLE, rel="registry/hive_files"),
    Artifact("mprocfs.registry_key", "读取任意注册表键（在线）", "注册表",
             OutputKind.TABLE, needs_params=("key",), online=True),
    # ---- 日志与其它 ----
    Artifact("mprocfs.eventlog", "事件日志清单（.evtx 已收获）", "其他",
             OutputKind.TABLE, rel="misc/eventlog"),
    Artifact("mprocfs.bitlocker", "BitLocker 恢复信息", "其他",
             OutputKind.TABLE, rel="misc/bitlocker"),
    Artifact("mprocfs.procinfo", "内存/进程信息（DTB 等）", "系统",
             OutputKind.SCALAR, rel="misc/procinfo"),
    # ---- 时间线 ----
    Artifact("mprocfs.timeline_process", "时间线·进程（创建/退出）", "时间线",
             OutputKind.TABLE, rel="forensic/csv/timeline_process.csv"),
    Artifact("mprocfs.timeline_net", "时间线·网络", "时间线",
             OutputKind.TABLE, rel="forensic/csv/timeline_net.csv"),
    Artifact("mprocfs.timeline_registry", "时间线·注册表（改动即持久化线索）", "时间线",
             OutputKind.TABLE, rel="forensic/csv/timeline_registry.csv"),
    Artifact("mprocfs.timeline_ntfs", "时间线·文件系统（MFT 访问/写入）", "时间线",
             OutputKind.TABLE, rel="forensic/csv/timeline_ntfs.csv"),
    Artifact("mprocfs.timeline_thread", "时间线·线程", "时间线",
             OutputKind.TABLE, rel="forensic/csv/timeline_thread.csv"),
    Artifact("mprocfs.timeline_kernelobject", "时间线·内核对象", "时间线",
             OutputKind.TABLE, rel="forensic/csv/timeline_kernelobject.csv"),
    Artifact("mprocfs.timeline_web", "时间线·Web 访问", "时间线",
             OutputKind.TABLE, rel="forensic/csv/timeline_web.csv"),
    Artifact("mprocfs.timeline_all", "时间线·全量合并（最大）", "时间线",
             OutputKind.TABLE, rel="forensic/csv/timeline_all.csv"),
)

ARTIFACT_BY_NAME: dict[str, Artifact] = {a.name: a for a in ARTIFACTS}

#: 收集阶段要复制的目录/文件（相对挂载根）。规则见 _harvest。
_HARVEST_FILES: tuple[str, ...] = (
    "sys/sysinfo/sysinfo.txt",
    "sys/users/users.txt",
    "registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/ProductId",
    "misc/procinfo/dtb.txt",
    "misc/procinfo/progress_percent.txt",
)
_HARVEST_DIRS: tuple[tuple[str, int], ...] = (
    # (挂载内目录, 单文件大小上限 MB)
    #
    # ⚠ 统一**镜像挂载布局**到 harvest/<同路径>：产物在挂载里叫什么、在本地就叫什么。
    # 踩过的坑（真实 bug）：早期版本把 `forensic/csv` 复制到 `harvest/csv/`，
    # 而查找却按 `forensic/csv/process.csv` 走 → 22 个 CSV 明明收获成功，
    # 上层却报"产物不存在"，最终表现为"分析跑完了什么都没有"。
    ("forensic/csv", 0),
    ("forensic/findevil", 32),          # findevil 的非 csv 产物（yara.txt 等）
    ("registry/hive_files", 0),         # 原始注册表配置单元（离线解凭据）
    ("misc/eventlog", 0),
    ("misc/bitlocker", 8),
    ("misc/procinfo", 8),
    ("misc/search", 64),                # 物理内存搜索结果（yara/string 等）
    ("conf", 8),                        # MemProcFS 配置/版本信息
)
#: 单进程视图里要抓的文本文件（不抓 memory.vmem，那个按需 dump）
_PROC_VIEW_FILES: tuple[str, ...] = (
    "pid.txt", "ppid.txt", "name.txt", "name-long.txt", "state.txt", "dtb.txt",
    "win-path.txt", "win-cmdline.txt", "win-curdir.txt", "win-environment.txt",
    "win-title.txt", "time-create.txt", "win-eprocess.txt", "win-peb.txt",
)


# ---------------------------------------------------------------- 工具函数


def _project_root() -> Path:
    """MemLens 项目根（打包后即 exe 所在目录）。"""
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def find_executable(explicit: str | os.PathLike | None = None) -> Path | None:
    """
    定位 memprocfs.exe。

    优先级：显式路径 > 环境变量 MEMLENS_MEMPROCFS > 可执行文件旁的 tools/MemProcFS >
    项目 tools/MemProcFS。**不去猜用户别处的目录**（写死外部路径迟早失效）。
    """
    cands: list[Path] = []
    if explicit:
        cands.append(Path(explicit))
    env = os.environ.get("MEMLENS_MEMPROCFS")
    if env:
        cands.append(Path(env))
    root = _project_root()
    cands += [
        root / "tools" / "MemProcFS" / EXE_NAME,
        root / "tools" / EXE_NAME,
        root / "MemProcFS" / EXE_NAME,
    ]
    for c in cands:
        try:
            if c.is_file():
                return c.resolve()
        except OSError:
            continue
    return None


def _free_mount_letter() -> str:
    """挑一个没被占用的盘符（绝不抢 M：用户可能开着别的工具）。"""
    for ch in _MOUNT_CANDIDATES:
        try:
            if not os.path.exists(f"{ch}:\\"):
                return ch
        except OSError:
            return ch
    raise HarvestFailed("没有可用盘符用于挂载 MemProcFS（已试 Z..J）")


def _sha256_file(path: Path, limit: int | None = None) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            if limit is not None and f.tell() >= limit:
                break
    return h.hexdigest()


def _resolve_workdir() -> Path:
    """
    MemProcFS 会话目录的落点（与 GUI/CLI 的工作目录策略保持一致）：
    优先 <项目>/work/mp，不可写则回退 %LOCALAPPDATA%\\MemLens\\work\\mp。

    为什么要测可写：打包后的 exe 可能被放在 Program Files 之类只读位置，
    而 MemProcFS 会话要写几百 MB 产物，路径不可写会让整个引擎失效。
    """
    env = os.environ.get("MEMLENS_WORKDIR")
    cands: list[Path] = []
    if env:
        cands.append(Path(env) / "mp")
    cands.append(_project_root() / "work" / "mp")
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    cands.append(Path(base) / "MemLens" / "work" / "mp")
    for c in cands:
        try:
            c.mkdir(parents=True, exist_ok=True)
            probe = c / ".write_test"
            probe.write_text("x", encoding="utf-8")
            probe.unlink()
            return c
        except OSError:
            continue
    return cands[0]


def _image_key(image: str) -> str:
    """镜像的稳定标识（路径 + 大小 + mtime；不哈希整个 GB 级镜像）。"""
    p = Path(image)
    try:
        st = p.stat()
        raw = f"{p.resolve()}|{st.st_size}|{int(st.st_mtime)}"
    except OSError:
        raw = str(Path(image).resolve())
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def _read_text(path: Path, limit: int = 4 << 20) -> str:
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return ""
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _parse_kv_text(text: str) -> list[dict[str, Any]]:
    """把 `Key: value` 形式的文本解析成 SCALAR 记录（保留等号/冒号两种风格）。"""
    out: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.strip().endswith(":") and "  " not in line.strip()[:-1]:
            out.append({"字段": line.strip().rstrip(":"), "值": ""})
            continue
        m = re.match(r"^\s*([^:=]{1,64}?)\s*[:=]\s*(.*)$", line)
        if m:
            out.append({"字段": m.group(1).strip(), "值": m.group(2).strip()})
        else:
            out.append({"字段": "", "值": line.strip()})
    return out


# ---------------------------------------------------------------- 会话（挂载）


@dataclasses.dataclass
class SessionInfo:
    """一次 MemProcFS 会话的结果。"""

    root: Path                    # 工作目录里的会话根（收获产物所在）
    mount: str                    # 挂载点（如 "Z:\\"）
    exe: Path
    image: str
    forensic: bool
    completed: bool
    duration_s: float
    log_path: Path
    harvested: list[str] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)
    stats: dict[str, Any] = dataclasses.field(default_factory=dict)


class _MountSession:
    """
    管理"启动 MemProcFS → 等它就绪 → 用完杀掉"的完整生命周期。

    为什么必须杀掉：MemProcFS 是常驻服务（占盘符 + 几百 MB 内存）。
    忘记清理的后果是下一次分析挂不上盘（真实踩过：M: 被占用）。
    """

    def __init__(
        self,
        exe: Path,
        image: str,
        workdir: Path,
        *,
        forensic: bool,
        timeout: float,
        log_path: Path,
        mount: str | None = None,
        extra_args: Sequence[str] = (),
        log: Callable[[str], None] | None = None,
        cancel: Callable[[], bool] | None = None,
    ) -> None:
        self.exe = exe
        self.image = str(image)
        self.workdir = workdir
        self.forensic = forensic
        self.timeout = timeout
        self.log_path = log_path
        self.mount_letter = mount or _free_mount_letter()
        self.mount = f"{self.mount_letter}:\\"
        self.extra_args = list(extra_args)
        self._log = log
        self._cancel = cancel
        self._proc: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._lines: list[str] = []
        self._lock = threading.Lock()
        self.forensic_seconds: float = 0.0
        self.steps: list[str] = []

    # -------------------------------------------------------------- 命令行
    def argv(self) -> list[str]:
        args = [
            str(self.exe),
            "-device", self.image,
            "-mount", self.mount_letter,
            "-forensic", "1" if self.forensic else "0",
            "-license-accept-elastic-license-2-0",
            "-v",
            *self.extra_args,
        ]
        return args

    # -------------------------------------------------------------- 运行
    def __enter__(self) -> "_MountSession":
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._emit(f"[MemProcFS] 启动：{' '.join(self.argv())}")
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
        try:
            self._proc = subprocess.Popen(
                self.argv(),
                cwd=str(self.workdir),          # 日志/缓存落在工作目录，绝不写安装目录
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
                shell=False,
            )
        except OSError as exc:
            raise MemProcFSUnavailable(f"无法启动 MemProcFS：{exc}") from exc

        self._wait_ready()
        return self

    def __exit__(self, *exc_info: Any) -> bool:
        self.stop()
        return False

    def _emit(self, text: str) -> None:
        with self._lock:
            self._lines.append(text)
        if self._log:
            try:
                self._log(text)
            except Exception:
                pass

    def _drain(self) -> None:
        """把剩余输出读完（进程退出后调用，保证日志完整）。"""
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            for line in proc.stdout:
                self._emit(line.rstrip("\n"))
        except Exception:
            pass

    def _wait_ready(self) -> None:
        """
        等到 forensic 完成（或轻量挂载就绪）。

        ⚠ 这里**绝不能**直接 `for line in proc.stdout` 边读边判超时：
        那是阻塞式迭代，MemProcFS 一旦安静下来（轻量挂载时很常见：打完 banner 就不再输出）
        这个循环会永远卡在 read 上，**连超时都检查不到** —— 表现就是"工具卡死"。
        （真实踩坑：本引擎第一版就是这么写的，轻量挂载挂到 7 分钟以上不返回。）

        正确做法：**单独一个读线程**把输出抽干（顺便落日志），主循环只轮询状态：
        是否完成、挂载点是否出现、进程是否退出、是否被取消、是否超时。
        """
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        started = time.time()
        done_flag = threading.Event()
        eof_flag = threading.Event()
        recent: list[str] = []

        def pump() -> None:
            try:
                for raw in proc.stdout:            # type: ignore[union-attr]
                    line = raw.rstrip("\n")
                    with self._lock:
                        self._lines.append(line)
                        recent.append(line)
                        if len(recent) > 200:
                            del recent[:100]
                    m = _FORENSIC_DONE_RE.search(line)
                    if m:
                        self.forensic_seconds = float(m.group(1))
                        done_flag.set()
                    sm = _FORENSIC_STEP_RE.search(line)
                    if sm and sm.group(1) != "FC_VIRTMEM_SCAN":
                        step = f"{sm.group(1)} {sm.group(2).strip()}".strip()
                        if step and step not in self.steps:
                            self.steps.append(step)
            except Exception:
                pass
            finally:
                eof_flag.set()

        reader = threading.Thread(target=pump, name="memprocfs-out", daemon=True)
        self._reader = reader
        reader.start()

        sys_dir = os.path.join(self.mount, "sys")
        try:
            while True:
                if self._cancel and self._cancel():
                    raise HarvestFailed("用户取消")
                if done_flag.is_set():                 # forensic 完成
                    break
                if not self.forensic and os.path.isdir(self.mount) \
                        and os.path.isdir(sys_dir):    # 轻量挂载：挂载点出现即可用
                    break
                rc = proc.poll()
                if rc is not None:
                    # 进程退出：把剩余输出读完再判定
                    reader.join(timeout=3)
                    tail = [l for l in recent[-6:] if l.strip()]
                    if done_flag.is_set() or (not self.forensic and os.path.isdir(sys_dir)):
                        break
                    raise HarvestFailed(
                        f"MemProcFS 提前退出（返回码 {rc}）：" + " | ".join(tail))
                if time.time() - started > self.timeout:
                    raise HarvestFailed(f"等待 MemProcFS 就绪超时（>{self.timeout:.0f}s）")
                time.sleep(0.5)
        finally:
            self._log_tail(list(recent))
        if not (done_flag.is_set() or os.path.isdir(sys_dir)):
            raise HarvestFailed("MemProcFS 未报告就绪（既没有 forensic 完成行，也没有挂载点）")

    def _log_tail(self, lines: Sequence[str]) -> None:
        """把本次读到的输出写进会话日志（滚动写盘，便于排错）。"""
        if not lines:
            return
        try:
            with open(self.log_path, "a", encoding="utf-8", errors="replace") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            pass

    # -------------------------------------------------------------- 停止
    def stop(self) -> None:
        """
        结束会话：杀进程 + 等读线程收尾。

        ⚠ 这里**不再自己读 stdout** —— stdout 已由 _wait_ready 里的读线程独占；
        两个地方同时 `for line in proc.stdout` 会互相抢，甚至再次阻塞住。
        """
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
        finally:
            if self._reader is not None and self._reader.is_alive():
                self._reader.join(timeout=3)
            self._proc = None


# ---------------------------------------------------------------- 引擎


class MemProcFSAdapter(EngineAdapter):
    """MemProcFS 适配器（虚拟盘取证）。"""

    name = "memprocfs"
    display = "MemProcFS（虚拟盘取证）"
    supported_containers = ("raw", "vmem", "dmp", "lime", "crash", "unknown")

    def __init__(
        self,
        *,
        workdir: str | os.PathLike | None = None,
        exe_path: str | os.PathLike | None = None,
        max_rows: int = DEFAULT_MAX_ROWS,
        harvest_timeout: float = DEFAULT_HARVEST_TIMEOUT,
    ) -> None:
        self.exe_path = str(exe_path) if exe_path else None
        #: 会话目录（不传则自动解析，见 _resolve_workdir）
        self.workdir = Path(workdir) if workdir else _resolve_workdir()
        self.max_rows = int(max_rows)
        self.harvest_timeout = float(harvest_timeout)
        self._lock = threading.Lock()
        #: 本次进程内已完成的会话（image_key → SessionInfo）
        self._sessions: dict[str, SessionInfo] = {}
        #: 初始化失败的记忆（image_key → 带降级建议的错误文本）：避免每个产物都重跑一遍
        self._failures: dict[str, str] = {}

    # ---------------------------------------------------------------- 环境
    def exe(self) -> Path | None:
        return find_executable(self.exe_path)

    @property
    def symbols_dir(self) -> Path | None:
        exe = self.exe()
        return (exe.parent / "Symbols") if exe else None

    def symbol_stats(self) -> tuple[int, float]:
        """(符号文件数, MB)：用于给用户一个"符号就绪度"的可见指标。"""
        d = self.symbols_dir
        if not d or not d.exists():
            return 0, 0.0
        n, total = 0, 0
        for p in d.rglob("*"):
            try:
                if p.is_file():
                    n += 1
                    total += p.stat().st_size
            except OSError:
                continue
        return n, total / (1 << 20)

    def available(self) -> tuple[bool, str]:
        exe = self.exe()
        if exe is None:
            return False, (
                "未找到 memprocfs.exe。请把 MemProcFS 放到 "
                "<MemLens>/tools/MemProcFS/ 下，或设置环境变量 MEMLENS_MEMPROCFS "
                "指向 memprocfs.exe。"
            )
        if not exe.is_file():
            return False, f"路径不是文件：{exe}"
        n, mb = self.symbol_stats()
        sym = f"符号文件 {n} 个（{mb:.0f} MB）" if n else "符号表尚未下载（首次取证会自动从微软符号服务器获取）"
        return True, f"{exe}；{sym}；挂载盘符自动选择（不占用 M:）"

    # ---------------------------------------------------------------- 插件
    def list_plugins(self, *, refresh: bool = False) -> list[PluginMeta]:
        """运行时枚举：目录里已收获的产物 + catalogs 里的模板。"""
        out: list[PluginMeta] = []
        for a in ARTIFACTS:
            out.append(PluginMeta(
                name=a.name, display=a.display, category=a.category,
                kind=a.kind, description=a.description, needs_params=a.needs_params,
            ))
        return out

    def build_run(self, plugin: PluginMeta, image: str, params: dict[str, Any] | None = None) -> RunSpec:
        """
        仅用于**审计与展示**：真正的执行走内置分支 analyze_file。

        这样做的好处：产物缓存键里仍然记录了"本产物由哪个 MemProcFS 命令行产生"，
        证据链可复现（argv 入 schedule 表）。
        """
        exe = self.exe() or Path(EXE_NAME)
        art = ARTIFACT_BY_NAME.get(plugin.name)
        argv = [
            str(exe), "-device", str(image), "-mount", "<auto>",
            "-forensic", "1", "-license-accept-elastic-license-2-0",
        ]
        if art is not None and art.online:
            argv = [str(exe), "-device", str(image), "-mount", "<auto>", "-live"]
        return RunSpec(plugin=plugin, argv=argv, output_kind=art.kind if art else plugin.kind,
                       env={"PYTHONIOENCODING": "utf-8"})

    def parse_records(self, spec: RunSpec, stdout: str, stderr: str) -> Iterator[dict[str, Any]]:
        """
        内置分支不走这里；保留实现是为了兼容"有人直接拿 stdout 当产物"的老调用路径。
        """
        raise NotImplementedError(
            "MemProcFS 引擎通过 analyze_file 产出记录（虚拟盘产物），不经 stdout 解析")

    # ---------------------------------------------------------------- 会话管理
    def session_dir(self, image: str) -> Path:
        return self.workdir / _image_key(image)

    def _manifest_path(self, image: str) -> Path:
        return self.session_dir(image) / "manifest.json"

    def loaded_session(self, image: str) -> SessionInfo | None:
        """返回内存中或磁盘上（已收获完成）的会话。"""
        key = _image_key(image)
        if key in self._sessions:
            return self._sessions[key]
        mf = self._manifest_path(image)
        if mf.is_file():
            try:
                data = json.loads(mf.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return None
            if data.get("complete") and int(data.get("harvest_version") or 0) == HARVEST_VERSION:
                info = SessionInfo(
                    root=self.session_dir(image), mount=data.get("mount", ""),
                    exe=Path(data.get("exe", "")), image=image, forensic=True,
                    completed=True, duration_s=float(data.get("duration_s") or 0.0),
                    log_path=self.session_dir(image) / "memprocfs.log",
                    harvested=list(data.get("harvested") or []),
                    warnings=list(data.get("warnings") or []),
                    stats=dict(data.get("stats") or {}),
                )
                self._sessions[key] = info
                return info
        return None

    def ensure_session(
        self,
        image: str,
        *,
        refresh: bool = False,
        offline: bool = False,
        progress: Callable[[int, int], None] | None = None,
        cancel: Callable[[], bool] | None = None,
        log: Callable[[str], None] | None = None,
    ) -> SessionInfo:
        """
        确保镜像已完成一次取证收集（幂等；已缓存则秒回）。

        这是本引擎的"重活"：首次运行 = 启动 MemProcFS + 等 forensic 完成 + 收获产物。
        """
        exe = self.exe()
        if exe is None:
            ok, why = self.available()
            raise MemProcFSUnavailable(why)
        key = _image_key(image)
        # ★ 失败记忆：同一个镜像初始化失败后，**不再重复启动 MemProcFS**
        #   （实测：512 MB 的部分采集 raw 上，每个产物都重跑一次 = 每个 78 s 白等）
        with self._lock:
            if key in self._failures:
                raise HarvestFailed(self._failures[key])
        with self._lock:
            if not refresh:
                cached = self.loaded_session(image)
                if cached is not None:
                    if log:
                        log(f"[MemProcFS] 复用已完成的取证会话：{cached.root}")
                    return cached
            try:
                return self._harvest(image, exe, offline=offline, progress=progress,
                                     cancel=cancel, log=log)
            except HarvestFailed as exc:
                msg = f"{exc}\n{self._fallback_hint(image, str(exc))}"
                self._failures[key] = msg
                raise HarvestFailed(msg) from exc

    def _fallback_hint(self, image: str, err: str) -> str:
        """
        初始化失败时给出**可执行的降级建议**。

        实测依据：NSSCTF 的 `file.raw`（512 MB、部分物理内存、WinXP SP3 32 位）上
        MemProcFS 报 `[CORE] Failed to initialize`（78 s 后退出），而 **vol3 同一镜像
        `windows.info` 成功出 23 行**。所以"MemProcFS 失败"不等于"这份镜像没法分析"——
        必须告诉用户换哪条路，否则用户只会看到一片失败。
        """
        low = err.lower()
        if "failed to initialize" not in low and "failed to open" not in low \
                and "无法" not in err:
            return "建议：确认镜像完整、是否缺配套 .vmsn/.vmsd 元数据；或改用 --engine vol3。"
        bits: list[str] = []
        try:
            size = os.path.getsize(image)
        except OSError:
            size = 0
        if 0 < size < 1024 * 1024 * 1024:
            bits.append(f"该镜像只有 {size / 1048576:.0f} MB，很可能只是**部分物理内存**"
                         "（整机 Windows 物理内存通常 ≥2 GB），内核页表不在采集范围内")
        bits.append("MemProcFS 需要完整物理内存才能建立内存映射")
        bits.append("**vol3 对部分镜像仍可工作**（本机实测：同一 512MB raw 上 "
                    "`windows.info` 成功出 23 行）")
        return ("降级建议：" + "；".join(bits)
                + "。改用：`--engine vol3 --plugins windows-basic`")

    # ---------------------------------------------------------------- 收集
    def _harvest(
        self,
        image: str,
        exe: Path,
        *,
        offline: bool,
        progress: Callable[[int, int], None] | None,
        cancel: Callable[[], bool] | None,
        log: Callable[[str], None] | None,
    ) -> SessionInfo:
        root = self.session_dir(image)
        root.mkdir(parents=True, exist_ok=True)
        log_path = root / "memprocfs.log"
        if offline:
            log_path.write_text("[MemLens] 离线模式：禁用微软符号服务器\n", encoding="utf-8")

        extra: list[str] = []
        if offline:
            extra.append("-disable-symbolserver")

        def _log(text: str) -> None:
            if log:
                log(text)

        try:
            size = os.path.getsize(image)
        except OSError:
            size = 0

        # 进度：以"阶段"折算成镜像字节的比例，让界面进度条真实前进
        stages = ("启动 MemProcFS", "内核符号解析/页表重建", "取证收集（forensic）",
                  "收获产物到工作目录", "完成")
        def _stage(i: int) -> None:
            if progress and size:
                progress(int(size * (i + 1) / len(stages)), size)

        started = time.time()
        _log(f"[MemProcFS] 使用解释器/可执行文件：{exe}")
        _stage(0)
        with _MountSession(
            exe, image, root, forensic=True, timeout=self.harvest_timeout,
            log_path=log_path, extra_args=extra, log=_log, cancel=cancel,
        ) as sess:
            _stage(1)
            mount = Path(sess.mount)
            if not mount.is_dir():
                raise HarvestFailed(f"MemProcFS 报告完成但挂载点不存在：{mount}")
            _stage(2)
            # CSV 是本引擎的核心产物。`-forensic 1` 虽会等取证跑完再挂载，但大镜像上
            # CSV 落盘可能比挂载点稍晚 → 有界等待，避免"收集成功但一个 CSV 都没拿到"。
            csv_dir = mount / "forensic" / "csv"
            wait_deadline = time.time() + 90
            while time.time() < wait_deadline:
                if cancel and cancel():
                    raise HarvestFailed("用户取消")
                try:
                    if csv_dir.is_dir() and any(csv_dir.glob("*.csv")):
                        break
                except OSError:
                    pass
                time.sleep(1)
            harvested, warnings = self._collect(mount, root, log=_log)
            _stage(3)

        duration = time.time() - started
        stats = {
            "forensic_seconds": round(sess.forensic_seconds, 1),
            "total_seconds": round(duration, 1),
            "artifacts": len(harvested),
            "steps": sess.steps[:40],
        }
        info = SessionInfo(
            root=root, mount=sess.mount, exe=exe, image=image, forensic=True,
            completed=True, duration_s=duration, log_path=log_path,
            harvested=harvested, warnings=warnings, stats=stats,
        )
        try:
            self._manifest_path(image).write_text(json.dumps({
                "complete": True, "harvest_version": HARVEST_VERSION,
                "image": str(Path(image).resolve()),
                "image_key": _image_key(image), "mount": sess.mount, "exe": str(exe),
                "duration_s": duration, "harvested": harvested,
                "warnings": warnings, "stats": stats,
                "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError as exc:
            info.warnings.append(f"manifest 写入失败：{exc}")
        self._sessions[_image_key(image)] = info
        _stage(4)
        _log(f"[MemProcFS] 取证完成：{len(harvested)} 项产物，耗时 {duration:.0f}s"
             f"（forensic {sess.forensic_seconds:.0f}s）")
        return info

    def _collect(
        self,
        mount: Path,
        root: Path,
        *,
        log: Callable[[str], None] | None = None,
    ) -> tuple[list[str], list[str]]:
        """把挂载点里的产物复制到工作目录（脱离挂载点后仍可离线分析）。"""
        harvested: list[str] = []
        warnings: list[str] = []

        def _cp(src: Path, dst: Path, limit_mb: int = 0) -> bool:
            try:
                if limit_mb and src.stat().st_size > limit_mb * (1 << 20):
                    warnings.append(f"跳过过大文件：{src.name}（>{limit_mb} MB）")
                    return False
                dst.parent.mkdir(parents=True, exist_ok=True)
                with open(src, "rb") as fi, open(dst, "wb") as fo:
                    while True:
                        chunk = fi.read(1 << 20)
                        if not chunk:
                            break
                        fo.write(chunk)
                return True
            except OSError as exc:
                warnings.append(f"复制失败 {src}：{exc}")
                return False

        # 1) 具名文件
        for rel in _HARVEST_FILES:
            src = mount / rel
            if src.is_file():
                if _cp(src, root / "harvest" / rel.replace("/", os.sep)):
                    harvested.append(rel)

        # 2) 目录（镜像挂载布局：harvest/<rel>/<文件名>）
        for rel, limit_mb in _HARVEST_DIRS:
            src_dir = mount / rel
            if not src_dir.is_dir():
                continue
            dst_dir = root / "harvest" / Path(rel.replace("/", os.sep))
            try:
                entries = list(src_dir.iterdir())
            except OSError as exc:
                warnings.append(f"列出 {rel} 失败：{exc}")
                continue
            for item in entries:
                if item.is_file():
                    if _cp(item, dst_dir / item.name, limit_mb):
                        harvested.append(f"{rel}/{item.name}")

        # 3) 注册表：Run 键（键=目录，值=文件）+ hive 清单 + ProductId 已在 1) 里
        self._harvest_registry_run(mount, root, harvested, warnings)
        # 3b) 代理配置键（通道配置维度 FR-02 的核心数据源）
        self._harvest_registry_proxy(mount, root, harvested, warnings)

        # 4) 每进程文本视图（不含 memory.vmem）
        pids_dir = mount / "pid"
        if pids_dir.is_dir():
            try:
                for entry in pids_dir.iterdir():
                    if not entry.is_dir():
                        continue
                    dst_dir = root / "harvest" / "pid" / entry.name
                    for fn in _PROC_VIEW_FILES:
                        f = entry / fn
                        if f.is_file():
                            if _cp(f, dst_dir / fn):
                                harvested.append(f"pid/{entry.name}/{fn}")
            except OSError as exc:
                warnings.append(f"遍历 pid 目录失败：{exc}")

        # 5) 清单类产物（eventlog / bitlocker / hive）：统一写进 harvest/_listings/
        listings = root / "harvest" / "_listings"
        self._write_listing(mount / "registry" / "hive_files", listings / "registry_hives.json")
        self._write_listing(mount / "misc" / "eventlog", listings / "eventlog.json")
        self._write_listing(mount / "misc" / "bitlocker", listings / "bitlocker.json")

        if log:
            log(f"[MemProcFS] 收获 {len(harvested)} 个产物文件"
                + (f"，{len(warnings)} 条提醒" if warnings else ""))
        return harvested, warnings

    def _write_listing(self, src_dir: Path, out_path: Path) -> None:
        rows: list[dict[str, Any]] = []
        if src_dir.is_dir():
            try:
                for item in sorted(src_dir.iterdir()):
                    if item.is_file():
                        try:
                            rows.append({"名称": item.name, "大小": item.stat().st_size})
                        except OSError:
                            continue
            except OSError:
                pass
        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
        except OSError:
            pass

    def _harvest_registry_run(
        self,
        mount: Path,
        root: Path,
        harvested: list[str],
        warnings: list[str],
    ) -> None:
        """
        抓自启动项：HKLM 与每个 HKU 用户的 Run / RunOnce。

        MemProcFS 的注册表虚拟 FS 里：**键 = 目录，值 = 文件（文件名即值名，内容即数据）**。
        目录里还有一个 `(_Key_)` 元数据文件，要排除。
        """
        targets: list[tuple[str, Path]] = []
        hklm = mount / "registry" / "HKLM"
        for sub in ("SOFTWARE/Microsoft/Windows/CurrentVersion/Run",
                    "SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce",
                    "SOFTWARE/Wow6432Node/Microsoft/Windows/CurrentVersion/Run"):
            p = hklm / Path(sub.replace("/", os.sep))
            if p.is_dir():
                targets.append((f"HKLM\\{sub.replace('/', chr(92))}", p))
        hku = mount / "registry" / "HKU"
        if hku.is_dir():
            try:
                for user in hku.iterdir():
                    if not user.is_dir():
                        continue
                    for sub in ("SOFTWARE/Microsoft/Windows/CurrentVersion/Run",
                                "SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce"):
                        p = user / Path(sub.replace("/", os.sep))
                        if p.is_dir():
                            targets.append((f"HKU\\{user.name}\\{sub.replace('/', chr(92))}", p))
            except OSError as exc:
                warnings.append(f"遍历 HKU 失败：{exc}")

        rows: list[dict[str, Any]] = []
        for key_path, key_dir in targets:
            try:
                entries = list(key_dir.iterdir())
            except OSError:
                continue
            for item in entries:
                if not item.is_file() or item.name.startswith("(_"):
                    continue
                try:
                    val = item.read_text(encoding="utf-8", errors="replace").strip()
                except OSError:
                    continue
                rows.append({"注册表键": key_path, "名称": item.name, "数据": val[:2000]})
        out = root / "harvest" / "registry_run.json"
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
            harvested.append("registry_run.json")
        except OSError as exc:
            warnings.append(f"Run 键落盘失败：{exc}")

    def _harvest_registry_proxy(
        self,
        mount: Path,
        root: Path,
        harvested: list[str],
        warnings: list[str],
    ) -> None:
        r"""
        抓取**代理配置**相关的注册表键（FR-02 通道配置的核心数据源）。

        为什么单独抓而不靠通用遍历：MemProcFS 的注册表虚拟 FS 是整棵注册表，
        全量复制可达数 GB；而通道配置维度只关心极少数键：
          · HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings
          · HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Internet Settings
        （键=目录，值=文件；文件名即值名，内容即数据）

        方案 4.2.3(2) 要求**三个配置面分别读取**（用户级/系统级/浏览器级）——
        这里覆盖前两个面；浏览器级需先 dump 浏览器 Profile 文件，取不到时明确降级。
        """
        targets: list[tuple[str, Path]] = []
        rel_suffix = "Software/Microsoft/Windows/CurrentVersion/Internet Settings"

        hklm = mount / "registry" / "HKLM"
        for sub in (rel_suffix,
                    "Software/Microsoft/Windows/CurrentVersion/Internet Settings"):
            p = hklm / Path(sub.replace("/", os.sep))
            if p.is_dir():
                targets.append((f"HKLM\\{sub.replace('/', chr(92))}", p))
                break

        hku = mount / "registry" / "HKU"
        if hku.is_dir():
            try:
                for user in hku.iterdir():
                    if not user.is_dir():
                        continue
                    p = user / Path(rel_suffix.replace("/", os.sep))
                    if p.is_dir():
                        targets.append((f"HKU\\{user.name}\\"
                                       f"{rel_suffix.replace('/', chr(92))}", p))
            except OSError as exc:
                warnings.append(f"遍历 HKU 失败（代理配置）：{exc}")

        rows: list[dict[str, Any]] = []
        for key_path, key_dir in targets:
            try:
                entries = list(key_dir.iterdir())
            except OSError:
                continue
            for item in entries:
                if not item.is_file() or item.name.startswith("(_"):
                    continue
                try:
                    val = item.read_text(encoding="utf-8", errors="replace").strip()
                except OSError:
                    continue
                if not val:
                    continue
                rows.append({"注册表键": key_path, "名称": item.name,
                             "数据": val[:2000]})

        if not rows:
            warnings.append("未取得 Internet Settings 代理配置键"
                            "（该机可能未配置代理，或键不在收集范围内）")
            return
        out = root / "harvest" / "registry_proxy.json"
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(rows, ensure_ascii=False, indent=1),
                           encoding="utf-8")
            harvested.append("registry_proxy.json")
        except OSError as exc:
            warnings.append(f"代理配置落盘失败：{exc}")

    # ---------------------------------------------------------------- 轻量挂载
    def live_read(self, image: str, reader: Callable[[Path], Any], *,
                  log: Callable[[str], None] | None = None,
                  cancel: Callable[[], bool] | None = None,
                  timeout: float = DEFAULT_LIVE_TIMEOUT) -> Any:
        """
        轻量挂载（不跑 forensic），执行 reader(挂载根)，然后立刻卸载。

        用于"按需"读取：单进程内存 dump、任意注册表键。
        代价：一次挂载约数秒到数十秒（符号已缓存时很快）。
        """
        exe = self.exe()
        if exe is None:
            raise MemProcFSUnavailable(self.available()[1])
        root = self.session_dir(image) / "live"
        root.mkdir(parents=True, exist_ok=True)
        with _MountSession(
            exe, image, root, forensic=False, timeout=timeout,
            log_path=root / "memprocfs.log", log=log, cancel=cancel,
        ) as sess:
            return reader(Path(sess.mount))

    # ---------------------------------------------------------------- 执行
    def analyze_file(
        self,
        image_path: str,
        plugin: PluginMeta,
        params: dict[str, Any] | None = None,
        *,
        progress: Callable[[int, int], None] | None = None,
        cancel: Callable[[], bool] | None = None,
        log: Callable[[str], None] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """
        产出某个产物的记录（TaskRunner 内置引擎分支入口）。

        第一次调用会触发完整的取证收集（分钟级），之后每个产物都是读本地文件（毫秒级）。
        """
        params = params or {}
        art = ARTIFACT_BY_NAME.get(plugin.name)
        if art is None:
            raise KeyError(f"未知的 MemProcFS 产物：{plugin.name}")

        def _log(text: str) -> None:
            if log:
                log(text)

        # ---- 需要挂载点在线才能做的操作 ----
        if art.online:
            yield from self._analyze_online(image_path, art, params, log=_log, cancel=cancel)
            return

        sess = self.ensure_session(
            image_path,
            refresh=bool(params.get("refresh")),
            offline=bool(params.get("offline")),
            progress=progress, cancel=cancel, log=_log,
        )
        yield from self._records_from_session(sess, art, params)

    # ---------------------------------------------------------------- 记录解析
    def _harvest_path(self, sess: SessionInfo, rel: str) -> Path:
        return sess.root / "harvest" / rel.replace("/", os.sep)

    def _records_from_session(
        self,
        sess: SessionInfo,
        art: Artifact,
        params: dict[str, Any],
    ) -> Iterator[dict[str, Any]]:
        max_rows = int(params.get("max_rows") or self.max_rows)

        if art.name == "mprocfs.harvest":
            yield {
                "项目": "取证收集", "值": f"{len(sess.harvested)} 项产物",
                "说明": f"耗时 {sess.duration_s:.0f}s（forensic {sess.stats.get('forensic_seconds', 0)}s）",
            }
            yield {"项目": "挂载点", "值": sess.mount, "说明": "收集完成即卸载"}
            yield {"项目": "可执行文件", "值": str(sess.exe), "说明": ""}
            yield {"项目": "会话目录", "值": str(sess.root), "说明": "全部产物在此，可离线复看"}
            for k in ("artifacts", "total_seconds", "forensic_seconds"):
                if k in sess.stats:
                    yield {"项目": k, "值": str(sess.stats[k]), "说明": ""}
            for w in sess.warnings:
                yield {"项目": "提醒", "值": w, "说明": ""}
            return

        if art.name in ("mprocfs.sysinfo", "mprocfs.productid"):
            path = self._harvest_path(sess, art.rel)
            if not path.is_file():
                raise HarvestFailed(f"产物不存在：{art.rel}（挂载点里没有该文件）")
            yield from _parse_kv_text(_read_text(path))
            return

        if art.name == "mprocfs.envs":
            pid_dir = sess.root / "harvest" / "pid"
            if pid_dir.is_dir():
                for item in sorted(pid_dir.iterdir(), key=lambda p: p.name):
                    env_file = item / "win-environment.txt"
                    if not env_file.is_file():
                        continue
                    name = ""
                    name_file = item / "name.txt"
                    if name_file.is_file():
                        name = _read_text(name_file).strip()
                    for line in _read_text(env_file, limit=1 << 20).splitlines():
                        line = line.strip()
                        if not line or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        yield {"PID": item.name, "进程": name,
                               "变量": k.strip(), "值": v.strip()[:2000]}
            return

        if art.name == "mprocfs.cmdlines":
            pid_dir = sess.root / "harvest" / "pid"
            fields = ("name.txt", "ppid.txt", "win-cmdline.txt", "win-path.txt",
                      "win-curdir.txt", "win-title.txt", "time-create.txt")
            if pid_dir.is_dir():
                for item in sorted(pid_dir.iterdir(), key=lambda p: p.name):
                    row: dict[str, Any] = {"PID": item.name}
                    for fn in fields:
                        f = item / fn
                        if f.is_file():
                            row[fn[:-4] if fn.endswith(".txt") else fn] = \
                                _read_text(f).strip()[:4000]
                    if len(row) > 1:
                        yield row
            return

        if art.name == "mprocfs.flag_hits":
            yield from self._scan_flag_hits(sess)
            return

        if art.name == "mprocfs.users":
            path = self._harvest_path(sess, art.rel)
            text = _read_text(path)
            for i, line in enumerate(text.splitlines()):
                if not line.strip() or line.strip().startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 3 and parts[0].isdigit():
                    yield {"序号": parts[0], "用户名": parts[1], "SID": parts[2],
                           "原始": line.strip()}
                elif len(parts) >= 2:
                    yield {"序号": "", "用户名": parts[0], "SID": parts[1],
                           "原始": line.strip()}
            return

        if art.name == "mprocfs.procinfo":
            out: list[dict[str, Any]] = []
            for rel in ("misc/procinfo/dtb.txt", "misc/procinfo/progress_percent.txt"):
                p = self._harvest_path(sess, rel)
                if p.is_file():
                    out.append({"字段": Path(rel).name, "值": _read_text(p).strip()})
            for row in out:
                yield row
            return

        if art.name == "mprocfs.registry_run":
            p = self._harvest_path(sess, "registry_run.json")
            if p.is_file():
                try:
                    rows = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    rows = []
                for r in rows:
                    yield r
            return

        if art.name == "mprocfs.registry_proxy":
            p = sess.root / "harvest" / "registry_proxy.json"
            if p.is_file():
                try:
                    for r in json.loads(p.read_text(encoding="utf-8")):
                        yield r
                except (OSError, ValueError):
                    pass
            return

        if art.name == "mprocfs.registry_hives":
            p = sess.root / "harvest" / "_listings" / "registry_hives.json"
            if p.is_file():
                try:
                    for r in json.loads(p.read_text(encoding="utf-8")):
                        name = str(r.get("名称", ""))
                        yield {"配置单元": name,
                               "大小": r.get("大小", 0),
                               "本地路径": str(sess.root / "harvest" / "registry"
                                             / "hive_files" / name)}
                except (OSError, ValueError):
                    pass
            for rel in sess.harvested:
                if rel.startswith("registry/hive_files/"):
                    yield {"配置单元": Path(rel).name, "大小": "",
                           "本地路径": str(self._harvest_path(sess, rel))}
            return

        if art.name == "mprocfs.eventlog":
            for row in self._listing_records(sess, "eventlog.json", "misc/eventlog", "事件日志"):
                yield row
            return

        if art.name == "mprocfs.bitlocker":
            for row in self._listing_records(sess, "bitlocker.json", "misc/bitlocker", "文件"):
                yield row
            return

        # ---- 通用 CSV ----
        rel = art.rel
        if rel.endswith(".csv"):
            path = self._harvest_path(sess, rel)
            if not path.is_file():
                raise HarvestFailed(f"产物不存在：{rel}（挂载点里没有该文件）")
            yield from self._iter_csv(path, max_rows=max_rows)
            return

        # ---- 其余：以目录形式收获的产物 → 直接列清单 ----
        path = self._harvest_path(sess, rel)
        if path.is_dir() or any(h.startswith(rel.rstrip("/") + "/") for h in sess.harvested):
            for row in self._listing_records(sess, "", rel, "文件"):
                yield row
            return
        if path.is_file():
            yield {"文件": Path(rel).name, "本地路径": str(path),
                   "内容": _read_text(path)[:4000]}
            return
        raise HarvestFailed(f"产物不存在：{rel}")

    def _scan_flag_hits(
        self, sess: SessionInfo, *, max_files: int = 5000,
        max_file_mb: int = 64, max_total_mb: int = 512,
    ) -> Iterator[dict[str, Any]]:
        """
        在**已收获的文本类产物**里秒级扫 flag。

        为什么要有它：MemLens 原有的 `memstrings.flag` 要**逐字节扫完整个镜像**
        （2 GiB 镜像实测几分钟），而 flag 往往就躺在 process.csv 的命令行、
        timeline 的文本列、注册表值、环境变量里 —— 这些**已经收获成文件**了，
        再扫一遍是秒级的。先扫这里，再决定要不要做全镜像扫描。
        """
        from memlens.core.flagbank import MAIN_RE

        harvest = sess.root / "harvest"
        if not harvest.is_dir():
            return
        total = 0
        scanned = 0
        for path in sorted(harvest.rglob("*")):
            try:
                if not path.is_file():
                    continue
            except OSError:
                continue
            if path.suffix.lower() not in (".txt", ".csv", ".json"):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > max_file_mb * (1 << 20):
                continue
            if total + size > max_total_mb * (1 << 20):
                break
            total += size
            scanned += 1
            if scanned > max_files:
                break
            text = _read_text(path, limit=64 << 20)
            for m in MAIN_RE.finditer(text):
                try:
                    rel = path.relative_to(sess.root).as_posix()
                except ValueError:
                    rel = path.name
                start = max(0, m.start() - 60)
                ctx = text[start:m.end() + 60].replace("\r", " ").replace("\n", " ")
                yield {"命中": m.group(0), "来源文件": rel,
                       "偏移": m.start(), "上下文": ctx[:300]}

    def _listing_records(
        self, sess: SessionInfo, listing: str, rel_dir: str, label: str = "文件",
    ) -> Iterator[dict[str, Any]]:
        """
        目录清单类产物（eventlog / bitlocker / hive / 任意目录）。

        listing 非空时优先读收集阶段写下的 `_listings/<listing>`
        （它记录了完整清单，即使某个大文件被大小上限跳过也仍然可见）。
        """
        rows: list[dict[str, Any]] = []
        if listing:
            p = sess.root / "harvest" / "_listings" / listing
            if p.is_file():
                try:
                    rows = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    rows = []
        if not rows:
            prefix = rel_dir.rstrip("/") + "/"
            for r in sess.harvested:
                if r.startswith(prefix):
                    rows.append({"名称": Path(r).name, "大小": ""})
        base = sess.root / "harvest" / Path(rel_dir.replace("/", os.sep))
        for r in rows:
            name = str(r.get("名称", ""))
            yield {label: name, "大小": r.get("大小", ""),
                   "本地路径": str(base / name)}

    @staticmethod
    def _iter_csv(path: Path, *, max_rows: int = 0) -> Iterator[dict[str, Any]]:
        """读 CSV（MemProcFS 的 CSV 是 UTF-8、标准表头；空列名跳过）。"""
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                return
            cols = [(h or f"列{i+1}").strip() for i, h in enumerate(header)]
            n = 0
            for row in reader:
                if not row:
                    continue
                rec: dict[str, Any] = {}
                for i, val in enumerate(row):
                    key = cols[i] if i < len(cols) else f"列{i+1}"
                    rec[key] = val
                yield rec
                n += 1
                if max_rows and n >= max_rows:
                    return

    # ---------------------------------------------------------------- 在线产物
    def _suspect_pids(self, image: str, *, limit: int = 3) -> list[str]:
        """
        无 `pid` 参数时自动挑"最值得看/dump 的进程"。

        取值顺序：`findevil.csv`（MemProcFS 内建异常检测，最可靠）→ 退化为
        `process.csv` 里"工具名特征 / 从用户可写目录运行"的进程。
        这样 GUI 里点一下就能 dump 到该 dump 的进程，而不是报错要用户填 PID。
        """
        sess = self.loaded_session(image)
        if sess is None:
            return []
        csv_dir = sess.root / "harvest" / "forensic" / "csv"
        pids: list[str] = []

        def _add(pid: str) -> bool:
            if pid.isdigit() and pid not in pids:
                pids.append(pid)
            return len(pids) >= limit

        found = csv_dir / "findevil.csv"
        if found.is_file():
            try:
                for row in self._iter_csv(found):
                    if _add(str(row.get("PID") or "").strip()):
                        return pids
            except OSError:
                pass

        proc = csv_dir / "process.csv"
        if proc.is_file():
            try:
                for row in self._iter_csv(proc):
                    name = str(row.get("Name") or "")
                    path = str(row.get("UserPath") or "")
                    cmd = str(row.get("CommandLine") or "")
                    if _TOOL_HINT_RE.search(name) or _TOOL_HINT_RE.search(cmd) \
                            or _SUSP_PATH_RE.search(path) or _SUSP_PATH_RE.search(cmd):
                        if _add(str(row.get("PID") or "").strip()):
                            break
            except OSError:
                pass
        return pids

    def _analyze_online(
        self,
        image_path: str,
        art: Artifact,
        params: dict[str, Any],
        *,
        log: Callable[[str], None] | None,
        cancel: Callable[[], bool] | None,
    ) -> Iterator[dict[str, Any]]:
        """
        需要挂载点在线的产物：单进程视图 / 进程内存 dump / 任意注册表键。

        实现方式：临时轻量挂载 → 读取/复制 → 立刻卸载。
        """
        if art.name == "mprocfs.proc_view":
            pid = str(params.get("pid") or "").strip()
            pids = [pid] if pid.isdigit() else self._suspect_pids(image_path, limit=5)
            if not pids:
                raise HarvestFailed(
                    "mprocfs.proc_view 需要参数 pid（数字），或先跑一次 findevil 以自动挑选可疑进程")
            def _read(root: Path) -> list[dict[str, Any]]:
                out: list[dict[str, Any]] = []
                for one in pids:
                    d = root / "pid" / one
                    if not d.is_dir():
                        out.append({"PID": one, "字段": "(挂载点里没有该进程目录)", "值": ""})
                        continue
                    for fn in _PROC_VIEW_FILES:
                        f = d / fn
                        if f.is_file():
                            out.append({"PID": one,
                                        "字段": fn[:-4] if fn.endswith(".txt") else fn,
                                        "值": _read_text(f, limit=65536).strip()})
                return out
            rows = self.live_read(image_path, _read, log=log, cancel=cancel)
            yield from rows
            return

        if art.name == "mprocfs.dump_process":
            pid = str(params.get("pid") or "").strip()
            pids = [pid] if pid.isdigit() else self._suspect_pids(image_path, limit=3)
            if not pids:
                raise HarvestFailed(
                    "mprocfs.dump_process 需要参数 pid（数字），或先跑一次 findevil 以自动挑选可疑进程")
            out_dir = Path(params.get("output_dir") or (self.session_dir(image_path) / "dump"))
            out_dir.mkdir(parents=True, exist_ok=True)

            def _dump(root: Path) -> list[dict[str, Any]]:
                meta: list[dict[str, Any]] = []
                for one in pids:
                    src = root / "pid" / one / "memory.vmem"
                    dst = out_dir / f"pid{one}.vmem"
                    if not src.is_file():
                        meta.append({"PID": one, "错误": "挂载点里没有该进程的 memory.vmem"})
                        continue
                    size = src.stat().st_size
                    # ⚠ **稀疏文件陷阱（实测撑爆磁盘）**：crash dump 里的 memory.vmem 是
                    #   **稀疏文件**（逻辑 30+ GB、实际只有几十 MB 有数据）。
                    #   普通 copy 会把空洞**展开成真实字节** → 一次复制写满 D:（实测 31.34 GB）。
                    #   ⇒ 按 4 MB 分块复制，**全零块只 seek 不写**（NTFS 自动成洞），
                    #   并设实际写入硬上限兜底。
                    written = 0
                    holes = 0
                    try:
                        with open(src, "rb") as fi, open(dst, "wb") as fo:
                            chunk = 4 << 20
                            while True:
                                buf = fi.read(chunk)
                                if not buf:
                                    break
                                if not any(buf):
                                    holes += 1
                                    fo.seek(len(buf), 1)      # 留洞，不落盘
                                else:
                                    fo.write(buf)
                                    written += len(buf)
                                if written > _DUMP_HARD_LIMIT:
                                    break
                    except OSError as exc:
                        meta.append({"PID": one, "错误": f"复制失败：{exc}"})
                        continue
                    meta.append({"PID": one, "落盘文件": str(dst),
                                 "逻辑大小": size, "实际写入": written, "空洞块": holes})
                return meta

            metas = self.live_read(image_path, _dump, log=log, cancel=cancel)
            for meta in metas:
                if meta.get("错误"):
                    yield meta
                    continue
                dst = Path(str(meta.get("落盘文件", "")))
                meta["SHA-256"] = _sha256_file(dst) if dst.is_file() else ""
                meta["提示"] = ("用「镜像字节扫描」或 strings 在该 dump 里找 flag/凭据；"
                                "也可当作静态样本分析；不要在本机直接运行 dump 出来的东西")
                yield meta
            return

        if art.name == "mprocfs.registry_key":
            key = str(params.get("key") or "").strip()
            if not key:
                raise ValueError("mprocfs.registry_key 需要参数 key，"
                                 "例如 key=HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
            rel = key.replace("\\", "/").strip("/")

            def _read_key(root: Path) -> list[dict[str, Any]]:
                d = root / "registry" / Path(rel)
                if not d.is_dir():
                    raise HarvestFailed(f"注册表键不存在或不可读：{key}")
                out: list[dict[str, Any]] = []
                for item in sorted(d.iterdir()):
                    if not item.is_file() or item.name.startswith("(_"):
                        continue
                    out.append({"键": key, "名称": item.name,
                                "数据": _read_text(item, limit=65536).strip()[:4000]})
                return out

            rows = self.live_read(image_path, _read_key, log=log, cancel=cancel)
            yield from rows
            return

        raise KeyError(f"未实现的在线产物：{art.name}")


# 注册（导入即注册；registry._bootstrap 也会显式注册一次）
from memlens.engines import registry as _registry  # noqa: E402

_registry.register(MemProcFSAdapter)
