"""
MemLens · Volatility 3 引擎适配器

要点（与"把命令写死"的做法不同）：
  * **插件清单运行时枚举**：首选用 `--help` 输出解析，结果缓存到磁盘；可 `refresh=True` 重枚举。
  * **不依赖 Scripts\\vol.py 的具体文件名**：用自带的薄入口脚本 `_vol3_entry.py` 调 `volatility3.cli:main`，
    这样无论 pip 生成的是 `vol.py` 还是 `vol.py.exe` 都能跑。
  * **输出用 jsonl**：逐行 JSON，解析容错强（引擎的日志/警告混进 stdout 也不会毁掉整批结果）。
  * **常用插件带中文名与分组**：查表命中就用中文，未命中自动回退（绝不因为上游新增插件就崩）。
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

from memlens.core.vol3_env import Vol3Env, interpret_line, key_errors
from memlens.engines.base import (
    EngineAdapter,
    OutputKind,
    PluginMeta,
    RunSpec,
)

# 薄入口脚本：避免依赖 pip 生成的 "vol.py.exe" 这一具体文件名
ENTRY_SCRIPT = Path(__file__).with_name("_vol3_entry.py")

# 打包（PyInstaller）后由 exe 自身充当 vol3 入口的开关。
# **必须**与 main.py 里的 VOL3_ENTRY_FLAG 保持一致。
VOL3_ENTRY_FLAG = "--vol3-entry"

# frozen 判定：PyInstaller 会注入 sys.frozen
FROZEN = bool(getattr(sys, "frozen", False))

# 常用插件的中文名与分组（未列出的插件会自动回退为英文名 + 推断分组）
KNOWN: dict[str, tuple[str, str, OutputKind]] = {
    # ---- 系统信息 ----
    "banners": ("系统类型探测（banners）", "系统", OutputKind.SCALAR),
    "windows.info": ("Windows 版本信息", "系统", OutputKind.SCALAR),
    "windows.info.Info": ("Windows 版本信息", "系统", OutputKind.SCALAR),
    "windows.statistics": ("内存统计信息", "系统", OutputKind.TABLE),
    "windows.verinfo": ("PE 版本信息", "系统", OutputKind.TABLE),
    "windows.modules": ("内核模块列表", "系统", OutputKind.TABLE),
    "windows.modscan": ("内核模块扫描", "系统", OutputKind.TABLE),
    "windows.driverscan": ("驱动扫描", "系统", OutputKind.TABLE),
    "windows.driverirp": ("驱动 IRP 钩子", "系统", OutputKind.TABLE),
    "windows.devicetree": ("设备对象树", "系统", OutputKind.TABLE),
    "windows.ssdt": ("SSDT 表", "系统", OutputKind.TABLE),
    "windows.callbacks": ("系统回调函数", "系统", OutputKind.TABLE),
    "windows.unloadedmodules": ("已卸载模块", "系统", OutputKind.TABLE),
    # ---- 进程 ----
    "windows.pslist": ("进程列表（活动链）", "进程", OutputKind.TABLE),
    "windows.psscan": ("进程扫描（池扫描）", "进程", OutputKind.TABLE),
    "windows.pstree": ("进程树", "进程", OutputKind.TABLE),
    "windows.cmdline": ("进程命令行", "进程", OutputKind.TABLE),
    "windows.dlllist": ("进程加载的 DLL", "进程", OutputKind.TABLE),
    "windows.handles": ("进程句柄", "进程", OutputKind.TABLE),
    "windows.ldrmodules": ("进程模块加载链", "进程", OutputKind.TABLE),
    "windows.getsids": ("进程/线程 SID", "进程", OutputKind.TABLE),
    "windows.privileges": ("进程权限", "进程", OutputKind.TABLE),
    "windows.envars": ("进程环境变量", "进程", OutputKind.TABLE),
    "windows.threads": ("线程信息", "进程", OutputKind.TABLE),
    "windows.vadinfo": ("进程 VAD 信息", "进程", OutputKind.TABLE),
    "windows.vadwalk": ("进程 VAD 树遍历", "进程", OutputKind.TABLE),
    "windows.memmap": ("进程内存映射（可导出）", "进程", OutputKind.FILE_SET),
    "windows.dumpfiles": ("内存中的文件对象（可导出）", "进程", OutputKind.FILE_SET),
    "windows.procdump": ("进程转储（可导出）", "进程", OutputKind.FILE_SET),
    # ---- 网络 ----
    "windows.netscan": ("网络连接扫描", "网络", OutputKind.TABLE),
    "windows.netstat": ("网络连接状态", "网络", OutputKind.TABLE),
    # ---- 恶意代码 / 注入 ----
    "windows.malfind": ("内存注入检测（Malfind）", "恶意代码", OutputKind.TABLE),
    "windows.hollowprocesses": ("空心进程检测", "恶意代码", OutputKind.TABLE),
    "windows.processghosting": ("进程幽灵化检测", "恶意代码", OutputKind.TABLE),
    "windows.psxview": ("隐藏进程多源比对（psxview）", "恶意代码", OutputKind.TABLE),
    "windows.suspicious_threads": ("可疑线程检测", "恶意代码", OutputKind.TABLE),
    "windows.suspended_threads": ("挂起线程检测", "恶意代码", OutputKind.TABLE),
    "windows.vadregexscan": ("VAD 正则扫描", "恶意代码", OutputKind.TABLE),
    "windows.yarascan": ("YARA 扫描", "恶意代码", OutputKind.TABLE),
    # ---- 注册表 ----
    "windows.registry.hivelist": ("注册表 Hive 列表", "注册表", OutputKind.TABLE),
    "windows.registry.hivescan": ("注册表 Hive 扫描", "注册表", OutputKind.TABLE),
    "windows.registry.printkey": ("注册表键值查看", "注册表", OutputKind.TABLE),
    "windows.registry.userassist": ("用户行为记录（UserAssist）", "注册表", OutputKind.TABLE),
    "windows.registry.certificates": ("注册表证书", "注册表", OutputKind.TABLE),
    "windows.registry.getcellroutine": ("注册表单元格获取", "注册表", OutputKind.TABLE),
    # ---- 凭据（仅做存在性提示，不导出明文）----
    "windows.hashdump": ("SAM 哈希（存在性提示）", "凭据", OutputKind.TEXT),
    "windows.lsadump": ("LSA 密钥（存在性提示）", "凭据", OutputKind.TEXT),
    "windows.cachedump": ("域缓存凭据（存在性提示）", "凭据", OutputKind.TEXT),
    # ---- 其他 ----
    "windows.filescan": ("文件对象扫描", "文件", OutputKind.TABLE),
    "windows.mutantscan": ("互斥体扫描", "文件", OutputKind.TABLE),
    "windows.svcscan": ("服务扫描", "服务", OutputKind.TABLE),
    "windows.svclist": ("服务列表", "服务", OutputKind.TABLE),
    "windows.svcdiff": ("服务差异分析", "服务", OutputKind.TABLE),
    "windows.crashinfo": ("崩溃信息", "其他", OutputKind.TEXT),
    "windows.strings": ("内存字符串提取", "其他", OutputKind.TABLE),
    "windows.consoles": ("控制台历史", "其他", OutputKind.TABLE),
    "windows.clipboard": ("剪贴板内容", "其他", OutputKind.TABLE),
}

# 分组推断：按插件名里的关键词
CATEGORY_HINTS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("pslist", "psscan", "pstree", "cmdline", "dlllist", "handles", "threads", "vad", "process", "getsids", "privileges", "envars"), "进程"),
    (("net", "socket", "tcp", "udp", "conn"), "网络"),
    (("malfind", "inject", "hollow", "ghost", "suspicious", "yara", "rootkit"), "恶意代码"),
    (("registry", "hive", "userassist", "shimcache", "amcache"), "注册表"),
    (("hashdump", "lsadump", "cachedump", "credential"), "凭据"),
    (("dump", "memmap", "procdump", "filescan", "file"), "文件"),
    (("service", "svc"), "服务"),
    (("info", "banners", "module", "driver", "ssdt", "callback", "device"), "系统"),
)

# 插件名提取。
# 注意 vol3 的 `--help` 有两种排版（实测 2.28.2）：
#   ① 名字与描述同行：  "    banners.Banners     Attempts to identify potential linux banners in an"
#   ② 名字独占一行，描述在下一行（长名字时）
# 所以这里**不能**用 `\s*$` 锚定行尾，必须捕获名字后面可能存在的描述。
PLUGIN_LINE_RE = re.compile(
    r"^\s{2,}((?:windows|linux|mac|banners|yarascan|timeliner|isfinfo|layerwriter|"
    r"configwriter|volshell|frameworkinfo|version|mockstacker|pdbconv)[\w.]*)[ \t]*(.*)$"
)


def _infer_category(name: str) -> str:
    """
    分类推断，分两层：
      1. 先按平台前缀（windows./linux./mac.）分开 —— 跨平台插件混在一起会让人无从下手；
      2. Windows 插件再按用途关键词细分。
    """
    low = name.lower()

    # ---- Linux ----
    if low.startswith("linux."):
        if any(k in low for k in ("pslist", "psscan", "pstree", "psaux", "proc", "bash",
                                  "users", "envars", "capabilities", "ptrace", "elfs",
                                  "kthreads", "pidhashtable")):
            return "Linux-进程与用户"
        if any(k in low for k in ("net", "sock", "arp", "route", "ip_", "ifconfig", "netfilter")):
            return "Linux-网络"
        if any(k in low for k in ("check", "hidden", "malware", "module", "lsmod", "ebpf",
                                  "ftrace", "tracepoint", "perf", "iomem", "vmcoreinfo")):
            return "Linux-内核与安全"
        if any(k in low for k in ("pagecache", "mount", "fs_", "lsof", "getcwd", "library")):
            return "Linux-文件系统"
        return "Linux-其他"

    # ---- macOS ----
    if low.startswith("mac."):
        return "macOS"

    # ---- Windows / 通用：按用途细分 ----
    for keywords, cat in CATEGORY_HINTS:
        if any(k in low for k in keywords):
            return cat
    return "其他"


# 分类展示顺序（GUI/CLI 共用）
CATEGORY_ORDER: tuple[str, ...] = (
    "系统", "进程", "网络", "恶意代码", "注册表", "凭据", "文件", "服务",
    "Linux-进程与用户", "Linux-网络", "Linux-内核与安全", "Linux-文件系统", "Linux-其他",
    "macOS", "其他",
)


def _short_name(full: str) -> str:
    """
    取"用户惯用名"：
      `windows.pslist.PsList` → `windows.pslist`
      `banners.Banners`       → `banners`        （注意：两段式也要能砍）
      `windows.pslist`        → 原样返回（末段小写说明本就没有类名后缀）
    """
    parts = full.split(".")
    if len(parts) >= 2 and parts[-1][:1].isupper():
        return ".".join(parts[:-1])
    return full


# ------------------------------------------------------------------ 失败诊断

#: 失败原因 → (简短标题, 可执行的处置建议, 是否值得降 parallelism 重试)
_FAILURES: tuple[tuple[str, str, str, bool], ...] = (
    (
        "only supports Windows 10",
        "该插件不支持这个系统版本",
        "vol3 的这条插件对镜像版本有硬性要求（例如 windows.svclist 只支持 Windows 10 15063+）。\n"
        "**这不是符号表问题**，同一镜像里的 pslist / netscan 等通用插件仍然正常工作；\n"
        "换用该功能的通用替代插件（如 windows.services / windows.svcscan）即可。",
        False,
    ),
    (
        "layer_name",
        "未定位到 Windows 内核符号层",
        "vol3 没能把镜像映射到某个 Windows 内核版本，插件因此无法运行。常见原因：\n"
        "  ① 首次运行需联网下载 ISF 符号表（几十 MB），请检查网络或稍后重试；\n"
        "  ② 镜像对应的 Windows 版本没有现成 ISF —— 可手动放符号包后用 -s 指定；\n"
        "  ③ 裸 .vmem 缺 .vmss/.vmsn 元数据，物理页布局不确定；\n"
        "  ④ 并行模式可能打断定位（已自动降级重试一次，若仍失败请看上面三条）",
        True,
    ),
    (
        "symbol_table_name",
        "未定位到内核符号表",
        "同上：符号表缺失或版本不匹配。首次运行需要联网下载 ISF 符号表。",
        True,
    ),
    (
        "No metadata file found alongside VMEM",
        "VMEM 缺少配套的 .vmss/.vmsn 元数据文件",
        "这条**只是提示，不是失败**：没有 .vmsn/.vmss 时 vol3 会退回把 .vmem 当裸物理内存处理，\n"
        "对绝大多数 CTF 镜像（含 vol_easy.vmem）完全够用，无需理会。\n"
        "真失败请看后面几行（Unsuitable symbol tables / symbol table requirement）。",
        False,
    ),
    (
        "symbol table requirement was not fulfilled",
        "内核符号表没拿到（本插件因此 0 行）",
        "vol3 认出了内核，但**没有可用的 ISF 符号表**，于是所有 windows.* 插件都会空手而归。\n"
        "两种可能：\n"
        "  ① 首次运行正在下载（ntkrnlmp.pdb 约 10 MB + 转 ISF，1-3 分钟），网络慢会更久；\n"
        "  ② 下载被拦截/无网络。\n"
        "MemLens 已把缓存固定在工作目录，成功一次之后同一镜像**秒开**；\n"
        "界面「环境自检」里可以直接看符号表是否已就绪。",
        True,
    ),
    (
        "attempt to write a readonly database",
        "缓存目录不可写（vmem 单文件 + 只读安装目录的经典症状）",
        "vol3 想把标识符索引写回缓存，但目标不可写。\n"
        "MemLens 已默认把 --cache-path 指到工作目录下的 vol3/cache；\n"
        "若仍出现，请检查该目录权限或磁盘空间。",
        False,
    ),
    (
        "unable to open database file",
        "缓存目录不存在（--cache-path 指向的目录没建）",
        "vol3 不会自己创建 --cache-path 目录。MemLens 会自动建；手工跑命令行时请先 mkdir。",
        False,
    ),
    (
        "Unsuitable symbol tables",
        "ISF 符号表与镜像不匹配",
        "已下载到符号包但没有一份能套用该镜像的内核构建。请确认镜像确实是 Windows 内核转储。",
        False,
    ),
    (
        "PDB GUID",
        "PDB 下载失败或未匹配",
        "vol3 会尝试用 PDB GUID 反查内核版本，这一步需要网络。离线环境请预置符号表。",
        True,
    ),
    (
        "URLopen error",
        "下载符号表时网络出错",
        "ISF 符号表需要联网下载。可检查代理/网络，或改用离线环境预置的符号目录。",
        True,
    ),
    (
        "SSDExt: Invalid signature",
        "文件格式识别失败",
        "该文件不是有效的内存转储（可能是磁盘镜像或被截断/加密的文件）。",
        False,
    ),
    (
        "Permission denied",
        "文件被占用或无读权限",
        "请关闭正在占用该文件的程序（虚拟机、取证工具等）后重试。",
        False,
    ),
)


def diagnose_failure(stderr: str) -> tuple[str, str, bool] | None:
    """
    把 vol3 的原始报错翻译成「发生了什么 + 该怎么办」。

    为什么要做：vol3 失败时只会刷一屏 `Progress: ... Updating caches`，
    真正的结论（`Unable to validate ... layer_name`）被埋在末尾，
    而那屏进度还会让人以为"还在慢慢跑"而不是"已经失败了"。
    """
    text = stderr or ""
    for marker, title, advice, retry in _FAILURES:
        if marker.lower() in text.lower():
            return title, advice, retry
    return None


def collapse_progress(lines: Sequence[str]) -> tuple[list[str], int]:
    """
    压缩 vol3 的进度刷屏。

    vol3 会把 `Progress: 12.34  Updating caches for 110 files...` 打上上百行，
    在 GUI 日志里把真正的结论完全淹掉。这里只保留**第一行 + 最后一行**，
    并返回被折叠的行数，让调用方如实告知用户"折叠了 N 行"。
    """
    out: list[str] = []
    prog_idx: list[int] = []
    for i, ln in enumerate(lines):
        (prog_idx if ln.lstrip().startswith("Progress:") else out).append(i)
    if not prog_idx:
        return list(lines), 0
    folded = len(prog_idx) - 2
    if folded <= 0:
        return list(lines), 0
    head = lines[prog_idx[0]].rstrip()
    tail = lines[prog_idx[-1]].rstrip()
    insert_at = sum(1 for i in prog_idx if i < prog_idx[0])
    out.insert(insert_at, f"{head}")
    out.insert(insert_at + 1, f"    …（已折叠 {folded} 行 vol3 进度输出）…")
    out.insert(insert_at + 2, f"{tail}")
    return out, folded


# ------------------------------------------------------------------ 预检结果


@dataclasses.dataclass
class WarmupResult:
    """一次符号预检（windows.info）的结论。"""

    ok: bool
    duration_ms: int
    kernel: str = ""                       # 如 7601.17514.amd64fre.win7sp1_rtm.
    symbol_path: str = ""                  # 实际命中的 ISF 路径（file:// 形式）
    layer: str = ""                        # 如 "0 WindowsIntel32e"
    records: dict[str, Any] = dataclasses.field(default_factory=dict)
    error: str | None = None               # 失败短标题
    advise: str = ""                       # 可执行的下一步建议
    key_lines: list[str] = dataclasses.field(default_factory=list)

    def summary(self) -> str:
        if self.ok:
            bits = [f"内核已定位（{self.kernel or '版本未知'}）"]
            if self.symbol_path:
                name = self.symbol_path.rsplit("/", 1)[-1]
                bits.append(f"符号表 {name}")
            bits.append(f"{self.duration_ms / 1000:.1f}s")
            return "；".join(bits)
        return f"未就绪：{self.error or '未知原因'}"


class Volatility3Adapter(EngineAdapter):
    """Volatility 3 适配器。"""
    name = "vol3"
    display = "Volatility 3"
    supported_containers = ("raw", "lime", "windmp", "vmem", "elfcore")

    def __init__(
        self,
        *,
        python_exe: str | None = None,
        vol_py: str | Path | None = None,
        cache_dir: str | Path | None = None,
        symbols_dir: str | Path | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> None:
        self.python_exe = python_exe or sys.executable
        self.vol_py = Path(vol_py) if vol_py else None
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".memlens" / "cache"
        self.symbols_dir = Path(symbols_dir) if symbols_dir else None
        self.extra_env = dict(extra_env or {})
        self._plugin_cache: list[PluginMeta] | None = None

    # ------------------------------------------------------------------ 内部
    def diagnose_failure(self, stderr: str) -> tuple[str, str, bool] | None:
        """
        把 vol3 的原始报错翻译成「发生了什么 + 该怎么办」。

        ★ 暴露成**适配器方法**（而不是只有模块级函数），
          这样上层的 TaskRunner 可以对任何引擎用同一套调用约定做失败归一化——
          归一化后同一个根因才会合并成一条缺口，而不是每个插件各报一串不同的 stderr。
        """
        return diagnose_failure(stderr)

    def _command_prefix(self) -> list[str]:
        """
        构造调用 vol3 的命令前缀（按运行形态自适应）。

        顺序很重要：
          1. 用户显式指定了 vol.py → 用它；
          2. **frozen（打包成 exe）** → 用 exe 自身的 `--vol3-entry` 子进程模式。
             因为此时 sys.executable 指向 exe 而不是 python 解释器，
             `exe _vol3_entry.py` 这形式根本不成立；
          3. 源码运行 → 用内置薄入口脚本（不依赖 pip 生成的 vol.py.exe 文件名）；
          4. 兜底 → 找 PATH 里的 vol.py / vol。
        """
        if self.vol_py and Path(self.vol_py).exists():
            return [self.python_exe, str(self.vol_py)]
        if FROZEN:
            return [sys.executable, VOL3_ENTRY_FLAG]
        if ENTRY_SCRIPT.exists():
            return [self.python_exe, str(ENTRY_SCRIPT)]
        # 兜底：尝试 pip 生成的入口
        exe = shutil.which("vol.py") or shutil.which("vol")
        if exe:
            return [exe]
        raise RuntimeError("未找到 Volatility 3 入口（既没有 vol.py 也没有内置入口脚本）")

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.setdefault("PYTHONIOENCODING", "utf-8")
        env.setdefault("PYTHONUTF8", "1")
        if self.symbols_dir:
            # 让 vol3 使用我们指定的符号表目录（离线/共享符号表场景）
            env["VOLATILITY_SYMBOL_DIRS"] = str(self.symbols_dir)
        env.update(self.extra_env)
        return env

    def _run(self, argv: Sequence[str], timeout: float | None = 120.0) -> tuple[int, str, str]:
        kwargs: dict[str, Any] = {}
        if os.name == "nt":
            # --windowed 打包的 GUI 每起一次子进程都会闪一个控制台黑窗。
            # 这里是**每次调用 vol3 插件**的热路径，不抑制的话界面会不停闪。
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        proc = subprocess.run(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
            env=self._env(),
            timeout=timeout,
            shell=False,          # 关键：永不使用 shell
            **kwargs,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""

    # ------------------------------------------------------------------ 环境
    def available(self) -> tuple[bool, str]:
        try:
            prefix = self._command_prefix()
        except RuntimeError as exc:
            return False, str(exc)
        try:
            rc, out, err = self._run([*prefix, "--help"], timeout=60)
        except subprocess.TimeoutExpired:
            return False, "调用 vol.py --help 超时（60s）"
        except Exception as exc:  # pragma: no cover
            return False, f"调用失败：{exc}"
        blob = f"{out}\n{err}"
        m = re.search(r"Volatility 3 Framework ([\d.]+)", blob)
        if rc == 0 and m:
            return True, f"可用，版本 {m.group(1)}（解释器：{self.python_exe}）"
        if m:
            return True, f"可用，版本 {m.group(1)}（--help 返回码 {rc}，可能缺少部分可选依赖）"
        return False, (err.strip().splitlines() or ["未知错误"])[0][:200]

    # ------------------------------------------------------------------ 插件
    def _cache_file(self) -> Path:
        return self.cache_dir / f"plugins_{self.name}.json"

    def list_plugins(self, *, refresh: bool = False) -> list[PluginMeta]:
        if self._plugin_cache is not None and not refresh:
            return self._plugin_cache

        cache = self._cache_file()
        if cache.exists() and not refresh:
            try:
                raw = json.loads(cache.read_text(encoding="utf-8"))
                plugins = [
                    PluginMeta(
                        name=item["name"],
                        display=item["display"],
                        category=item["category"],
                        kind=OutputKind(item.get("kind", "table")),
                        description=item.get("description", ""),
                    )
                    for item in raw
                ]
                if plugins:
                    self._plugin_cache = plugins
                    return plugins
            except Exception:
                pass  # 缓存坏了就重新枚举

        plugins = self._enumerate_plugins()
        self._plugin_cache = plugins
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(
                json.dumps(
                    [
                        {
                            "name": p.name,
                            "display": p.display,
                            "category": p.category,
                            "kind": p.kind.value,
                            "description": p.description,
                        }
                        for p in plugins
                    ],
                    ensure_ascii=False,
                    indent=1,
                ),
                encoding="utf-8",
            )
        except Exception:
            pass
        return plugins

    def _enumerate_plugins(self) -> list[PluginMeta]:
        """跑一次 `--help`，解析出插件清单（并挑出 Volatility3 自己的渲染器名）。"""
        prefix = self._command_prefix()
        rc, out, err = self._run([*prefix, "--help"], timeout=60)
        blob = f"{out}\n{err}"

        found: dict[str, PluginMeta] = {}
        for line in blob.splitlines():
            m = PLUGIN_LINE_RE.match(line)
            if not m:
                continue
            full = m.group(1)
            desc = (m.group(2) or "").strip()
            short = _short_name(full)
            if full in KNOWN:
                display, category, kind = KNOWN[full]
            elif short in KNOWN:
                display, category, kind = KNOWN[short]
            else:
                display, category, kind = full, _infer_category(full), OutputKind.TABLE
            found[full] = PluginMeta(name=full, display=display, category=category,
                                     kind=kind, description=desc)

        if not found:
            raise RuntimeError(
                "无法从 `vol.py --help` 输出中解析出插件清单。原始输出片段：\n"
                + "\n".join(blob.splitlines()[:25])
            )
        # 常用分组优先排序，便于 UI 展示
        order = list(CATEGORY_ORDER)
        return sorted(found.values(), key=lambda p: (order.index(p.category) if p.category in order else 99, p.name))

    # ------------------------------------------------------------------ 执行
    def build_run(self, plugin: PluginMeta, image: str, params: dict[str, Any] | None = None) -> RunSpec:
        """
        组装 vol3 命令行。

        ⚠ **不要在这里无条件加 `--parallelism threads`**（这条坑踩过，代价很大）：

        并行 stacking 会**静默打断裸 VMEM 的 Windows 内核定位**。实测同一张
        `vol_easy.vmem`（Win7 SP1 x64，无 .vmss/.vmsn 元数据）：

            --parallelism threads    → 0 行，Unable to validate ... layer_name
            --parallelism processes  → 0 行，同样失败
            --parallelism off        → 35 行，pslist 正常
            不传（vol3 默认）         → 35 行，pslist 正常

        表现是**全部插件失败、检测器 0 条发现项**，而日志里只有一屏
        `Progress: ... Updating caches for 110 files` 刷屏，看不出真实原因。
        因此默认交给 vol3 自己决定（等价于 off），需要并行时由调用方显式传。
        """
        params = dict(params or {})
        argv = [*self._command_prefix()]
        # ---- 缓存与符号目录：固定到工作目录（见 core/vol3_env.py 的坑说明）----
        # 不放进 params 的语义位（避免影响产物缓存键），但允许 params 覆盖。
        cache_dir = params.get("cache_dir") or (str(self.cache_dir) if self.cache_dir else None)
        symbols_dir = params.get("symbols_dir") or (str(self.symbols_dir) if self.symbols_dir else None)
        # 符号目录可以是**多个**（vol3 的 -s 接受分号分隔列表）：
        # 第一位永远是 MemLens 自己的可写目录（新 ISF 落这里），后面挂接本机已有的
        # 只读符号源（例如比赛工具包里自带的 volatility3\symbols）。
        # 这样"离线、零下载、秒级出结果"成为可能，也顺手解决"符号拿不到→全是日志"。
        sym_dirs: list[str] = [symbols_dir] if symbols_dir else []
        try:
            from memlens.core.symbols import indexable_extra_sources

            wd = None
            if symbols_dir:
                p = Path(symbols_dir)
                if p.name == "symbols" and p.parent.name == "vol3":
                    wd = p.parent.parent          # <workdir>/vol3/symbols → <workdir>
            # 只挂"小"符号源：几千个 ISF 的大库会让 vol3 首次运行建全量索引（实测 CPU
            # 上千秒仍未完成）。大库请用 `memlens symbols --import-kernel` 精确取内核符号表。
            for extra in indexable_extra_sources(wd):
                if str(extra) not in sym_dirs:
                    sym_dirs.append(str(extra))
        except Exception:
            pass                                   # 符号源探测失败不影响主流程
        for d in ([cache_dir] if cache_dir else []) + sym_dirs[:1]:
            if d:
                try:
                    Path(d).mkdir(parents=True, exist_ok=True)
                except OSError:
                    pass          # 交给 vol3 自己报错，信息更准确
        if cache_dir:
            argv += ["--cache-path", str(cache_dir)]
        if sym_dirs:
            # -s 会把第一个目录**前置**到符号搜索路径：下载来的 ISF 也落在这里（可写、可移植）
            argv += ["-s", ";".join(sym_dirs)]
        # 只有调用方**显式要求**并行时才加；不传即用 vol3 默认（实测可用的那条路）
        par = params.get("parallelism")
        if par:
            argv += ["--parallelism", str(par)]
        if params.get("offline"):
            argv.append("--offline")
        argv += ["-f", os.path.abspath(image)]
        if params.get("output_dir"):
            argv += ["-o", str(params["output_dir"])]
        # 渲染器：默认 jsonl（容错强），可被参数覆盖
        renderer = params.get("renderer") or "jsonl"
        argv += ["-r", renderer]
        argv.append(plugin.name)
        # 附加参数：如 --pid=1234 / --dump
        for extra in params.get("extra", []) or []:
            argv.append(str(extra))
        return RunSpec(
            plugin=plugin,
            argv=argv,
            env=None,
            timeout=params.get("timeout"),
            output_kind=plugin.kind,
        )

    # ------------------------------------------------------------------ 预检
    def warmup(
        self,
        image: str,
        *,
        timeout: float = 1800.0,
        on_line: Callable[[str], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> "WarmupResult":
        """
        "预检"：只跑最轻的 `windows.info`，目的是**把内核符号表准备好**。

        为什么值得单独跑一步：首次分析时 vol3 要建符号索引、扫页映射、按 PDB 特征找内核、
        必要时从微软符号服务器下载 PDB 并转成 ISF（1-3 分钟）。这期间任何插件都只有
        一屏 `Progress:` 刷屏，用户会以为程序死了。先单独跑这一步，界面就能明确显示
        "正在下载符号表"，并且**内核拿不到时立刻停**，不再白跑 27 个插件。

        Returns:
            WarmupResult（ok=False 不代表镜像坏，只代表 Windows 符号没就绪）
        """
        started = time.time()
        plugin = PluginMeta(name="windows.info", display="Windows 版本信息",
                            category="系统", kind=OutputKind.SCALAR)
        spec = self.build_run(plugin, image, {"renderer": "jsonl"})
        kwargs: dict[str, Any] = {}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            proc = subprocess.Popen(
                spec.argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                encoding="utf-8", errors="replace", bufsize=1,
                env=self._env(), shell=False, **kwargs,
            )
        except Exception as exc:  # pragma: no cover
            return WarmupResult(ok=False, duration_ms=0, error=f"启动 vol3 失败：{exc}")

        out_lines: list[str] = []
        err_lines: list[str] = []

        def pump(pipe, sink, emit: bool) -> None:
            for line in pipe:                       # type: ignore[union-attr]
                sink.append(line)
                if emit and on_line:
                    try:
                        on_line(line.rstrip("\n"))
                    except Exception:
                        pass

        t_out = threading.Thread(target=pump, args=(proc.stdout, out_lines, False), daemon=True)
        t_err = threading.Thread(target=pump, args=(proc.stderr, err_lines, True), daemon=True)
        t_out.start()
        t_err.start()

        deadline = time.time() + timeout if timeout else None
        killed = False
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                proc.kill()
                killed = True
                break
            if deadline and time.time() > deadline:
                proc.kill()
                killed = True
                break
            time.sleep(0.1)
        t_out.join(timeout=5)
        t_err.join(timeout=5)

        duration_ms = int((time.time() - started) * 1000)
        stderr = "".join(err_lines)
        rc = proc.returncode if proc.returncode is not None else -1
        info: dict[str, Any] = {}
        try:
            for rec in self.parse_records(spec, "".join(out_lines), stderr):
                key = rec.get("Variable") or rec.get("variable")
                if key:
                    info[str(key)] = rec.get("Value", rec.get("value"))
        except Exception:
            pass

        if killed:
            return WarmupResult(ok=False, duration_ms=duration_ms,
                                error="预检被取消或超时", key_lines=key_errors(stderr))

        symbol = str(info.get("Symbols") or "")
        ok = bool(info) and rc == 0
        result = WarmupResult(
            ok=ok,
            duration_ms=duration_ms,
            kernel=str(info.get("NTBuildLab") or info.get("BuildLab") or ""),
            symbol_path=symbol,
            layer=str(info.get("layer_name") or ""),
            records=info,
            key_lines=key_errors(stderr),
        )
        if not ok:
            diag = diagnose_failure(stderr)
            if diag:
                result.error, result.advise = diag[0], diag[1]
            elif result.key_lines:
                result.error = result.key_lines[0]
            else:
                result.error = "windows.info 未返回系统信息（镜像可能不是 Windows 内存，或符号未就绪）"
        return result

    def parse_records(self, spec: RunSpec, stdout: str, stderr: str) -> Iterator[dict[str, Any]]:
        """
        解析 jsonl 输出。

        容错策略：逐行尝试 JSON；跳过引擎自身的日志/空行/进度行；
        如果一行都解析不出来但确实有内容（例如渲染器实际是 `json` 数组），
        则退化为整体 JSON 解析；仍然失败就抛异常（不静默返回空）。
        """
        text = (stdout or "").strip()
        if not text:
            return

        # 先试 jsonl
        parsed_any = False
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line[0] not in "[{":
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            parsed_any = True
            if isinstance(obj, dict):
                yield obj
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, dict):
                        yield item

        if parsed_any:
            return

        # 再试整体 JSON（数组或对象）
        start = min((i for i in (text.find("["), text.find("{")) if i >= 0), default=-1)
        if start >= 0:
            try:
                obj = json.loads(text[start:])
            except json.JSONDecodeError:
                obj = None
            if isinstance(obj, list):
                for item in obj:
                    if isinstance(item, dict):
                        yield item
                return
            if isinstance(obj, dict):
                yield obj
                return

        raise ValueError(
            "无法解析引擎输出为结构化记录（既不是 jsonl 也不是 json）。"
            f"stdout 前 200 字符：{text[:200]!r}"
        )
