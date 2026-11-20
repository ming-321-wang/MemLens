"""
MemLens · Volatility 3 运行环境（缓存/符号目录）与"进度语义化"

## 为什么需要这个模块

这条经验是踩出来的（2026-10，vol_easy.vmem 一题）：

  * vol3 默认把**符号索引缓存**写到 `%APPDATA%\\volatility3`、把**下载的 ISF 符号表**
    写到 `volatility3/symbols/...`（即安装目录）；打包成 exe 后那是 `_internal` 内部，
    既可能只读、也和案件数据脱节。写不进去时 vol3 只在 stderr 里丢一行
    `PermissionError: [WinError 5]`，插件最后以 "symbol table requirement was not fulfilled"
    收场 —— 用户看到的就是"跑了半天，什么都没分析出来"。
  * vol3 的进度输出（`Progress: 75.45  Updating caches for 110 files...`）会刷上百行，
    把真正的结论淹没；而这些进度行其实**语义明确**：先建索引、再扫页表、再按 PDB 特征
    找内核。把它们翻译成人话，界面才能告诉用户"现在在干什么、还要多久"。

因此：缓存与符号目录一律放到 **工作目录下**（跟着案件走、必然可写、exe 与源码共用），
并把 vol3 的原始进度翻译成 (阶段, 百分比, 人话)。
"""

from __future__ import annotations

import dataclasses
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterator

# 工作目录下的子目录名（与案件数据同级，便于整体拷贝/归档）
VOL3_SUBDIR = "vol3"
CACHE_SUBDIR = "cache"
SYMBOLS_SUBDIR = "symbols"
#: vol3 的标识符索引文件名（默认在 CACHE_PATH 下）
IDENTIFIER_DB = "identifier.cache"
#: 已下载的 PDB 原始文件缓存（`data_<hash>.cache`）
PDB_CACHE_GLOB = "data_*.cache"


# --------------------------------------------------------------------- 进度语义

#: (正则, 阶段标识, 人话模板)。模板里可用 {n} 引用第一个捕获组。
_PHASE_RULES: tuple[tuple[str, str, str], ...] = (
    (r"Updating caches for (\d+) files",
     "index", "建立符号索引：正在登记 {n} 个 ISF 文件（仅首次需要，之后走缓存）"),
    (r"Reading remote ISF list", "index_remote", "读取在线符号清单（用于自动获取内核符号表）"),
    (r"Downloading|Retreiving|retreive_pdb", "download", "正在从微软符号服务器下载 PDB"),
    (r"Converting|PdbReader|get_json", "convert", "正在把 PDB 转换成 ISF 符号表（首次约 1-3 分钟）"),
    (r"Scanning .* using PageMapScanner", "pagemap", "扫描物理内存页映射（确定内存布局）"),
    (r"Stacking attempts finished", "stacked", "内存层已就绪"),
    (r"Scanning .* using BytesScanner", "bytescan", "按特征字节定位内核"),
    (r"Scanning .* using PdbSignatureScanner", "pdbscan", "按 PDB 特征定位内核（确定 Windows 版本）"),
    (r"PDB scanning finished", "kernel_found", "内核已定位，符号表就绪"),
    (r"Running automagic:\s*([A-Za-z]+)", "automagic", "自动配置：{n}"),
    (r"Kernel Module", "kernel_module", "解析内核模块列表"),
)

_PROGRESS_RE = re.compile(r"Progress:\s*([\d.]+)\s+(.*?)\s*$")
_PHASE_COMPILED = tuple((re.compile(p), key, tpl) for p, key, tpl in _PHASE_RULES)

#: 人话阶段名（界面直接用）
PHASE_LABEL = {
    "index": "符号索引",
    "index_remote": "在线符号清单",
    "download": "下载符号",
    "convert": "生成符号表",
    "pagemap": "页映射扫描",
    "stacked": "内存层就绪",
    "bytescan": "内核特征扫描",
    "pdbscan": "内核定位",
    "kernel_found": "符号表就绪",
    "automagic": "自动配置",
    "kernel_module": "内核模块",
    "run": "插件执行",
}


@dataclasses.dataclass
class ProgressStep:
    """一条 vol3 进度输出的语义化结果。"""

    percent: float | None      # 0-100，取不到就是 None
    phase: str                 # 稳定标识（见 PHASE_LABEL）
    text: str                  # 给人看的一句话

    @property
    def label(self) -> str:
        return PHASE_LABEL.get(self.phase, self.phase)


def interpret_line(line: str) -> ProgressStep | None:
    """
    把一行 vol3 输出翻译成 (阶段, 百分比, 人话)。

    返回 None 表示这行不含可用的进度/阶段信息（调用方照旧记日志即可）。
    """
    if not line:
        return None
    percent: float | None = None
    body = line
    m = _PROGRESS_RE.search(line)
    if m:
        try:
            percent = float(m.group(1))
        except ValueError:
            percent = None
        body = m.group(2)

    for rx, phase, tpl in _PHASE_COMPILED:
        mm = rx.search(body)
        if mm:
            text = tpl
            if "{n}" in tpl:
                text = tpl.replace("{n}", mm.group(1) if mm.groups() else "")
            return ProgressStep(percent=percent, phase=phase, text=text)
    if percent is not None:
        return ProgressStep(percent=percent, phase="run", text=body.strip()[:120])
    return None


#: stderr 里这些行属于噪音，展示"关键错误"时要滤掉
_NOISE_RE = re.compile(
    r"^\s*(Progress:|$)|^\s*(WARNING|INFO)\s+volatility3\.(framework\.plugins|automagic|schemas)"
)
#: 这些关键词所在行才是真正需要用户看到的
_KEY_ERROR_RE = re.compile(
    r"Unsuitable symbol tables|Unable to validate|symbol table requirement|"
    r"Unable to satisfy|PermissionError|OperationalError|MemoryError|"
    r"No such file|not a valid|Cannot|Failed|Error|Traceback|"
    r"does not exist|unsupported|Unable to|Requirement",
    re.IGNORECASE,
)


def key_errors(stderr: str, limit: int = 8) -> list[str]:
    """
    从 vol3 的 stderr 里挑出"真正说明问题"的行。

    为什么不用 diagnose_failure 的固定特征：那套只能覆盖已知的几种；
    这里给的是**通用兜底**——保证界面上永远有一行可读的失败原因，
    而不是把一屏 Progress 刷给用户。
    """
    out: list[str] = []
    for raw in (stderr or "").splitlines():
        line = raw.strip()
        if not line or _NOISE_RE.search(raw):
            continue
        if _KEY_ERROR_RE.search(line):
            if line not in out:
                out.append(line[:300])
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------- 环境

@dataclasses.dataclass
class Vol3Status:
    """符号/缓存环境现状（给界面做"已就绪/需下载"判断）。"""

    root: Path
    cache_dir: Path
    symbols_dir: Path
    identifier_db: Path | None = None
    indexed_local: int = 0
    indexed_remote: int = 0
    isf_files: int = 0
    pdb_cache_mb: float = 0.0
    note: str = ""

    @property
    def warm(self) -> bool:
        """是否已经有可用的符号缓存（不必联网）。"""
        return self.isf_files > 0

    def summary(self) -> str:
        if self.identifier_db is None and not self.isf_files:
            return "符号环境未初始化（首次分析会自动建立）"
        parts = [f"本地 ISF 索引 {self.indexed_local} 项",
                 f"在线清单 {self.indexed_remote} 项",
                 f"已下载符号表 {self.isf_files} 个"]
        if self.pdb_cache_mb:
            parts.append(f"PDB 缓存 {self.pdb_cache_mb:.1f} MB")
        if self.note:
            parts.append(self.note)
        return "；".join(parts)


class Vol3Env:
    """把 vol3 的缓存与符号目录固定到工作目录下。"""

    def __init__(self, workdir: str | os.PathLike) -> None:
        self.workdir = Path(workdir)
        self.root = self.workdir / VOL3_SUBDIR
        self.cache_dir = self.root / CACHE_SUBDIR
        self.symbols_dir = self.root / SYMBOLS_SUBDIR

    # ------------------------------------------------------------------ 准备
    def ensure(self) -> "Vol3Env":
        """
        建目录。

        ⚠ 必须由我们建：vol3 的 `--cache-path` **不会**自己创建目录，
        目录不存在时它直接抛
        `sqlite3.OperationalError: unable to open database file`（已实测）。
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.symbols_dir.mkdir(parents=True, exist_ok=True)
        return self

    def apply(self, adapter: Any) -> "Vol3Env":
        """把缓存/符号目录注入引擎实例（不放进 params，避免污染产物缓存键）。"""
        self.ensure()
        try:
            adapter.cache_dir = self.cache_dir
            adapter.symbols_dir = self.symbols_dir
        except Exception:
            pass
        return self

    # ------------------------------------------------------------------ 查询
    def status(self) -> Vol3Status:
        st = Vol3Status(root=self.root, cache_dir=self.cache_dir, symbols_dir=self.symbols_dir)
        db = self.cache_dir / IDENTIFIER_DB
        if db.exists():
            st.identifier_db = db
            try:
                uri = db.resolve().as_uri() + "?mode=ro"
                con = sqlite3.connect(uri, uri=True, timeout=1.0)
                try:
                    st.indexed_local = con.execute(
                        "SELECT COUNT(*) FROM cache WHERE local = 1").fetchone()[0]
                    st.indexed_remote = con.execute(
                        "SELECT COUNT(*) FROM cache WHERE local = 0").fetchone()[0]
                finally:
                    con.close()
            except Exception as exc:      # 被别的进程锁住 / 半成品文件
                st.note = f"索引库暂不可读（{type(exc).__name__}）"
        try:
            st.isf_files = sum(1 for _ in self.symbols_dir.rglob("*.json.xz"))
        except OSError:
            st.isf_files = 0
        if self.cache_dir.exists():
            total = 0
            for p in self.cache_dir.glob(PDB_CACHE_GLOB):
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
            st.pdb_cache_mb = total / (1 << 20)
        return st

    def kernel_isf(self) -> list[Path]:
        """列出已下载的 Windows 内核 ISF（判定"下次能不能离线跑"）。"""
        out: list[Path] = []
        win = self.symbols_dir / "windows"
        if win.exists():
            out.extend(p for p in win.rglob("*.json.xz"))
        return out

    def iter_progress(self, lines: Iterator[str]) -> Iterator[ProgressStep]:
        """便利方法：从一行行 stderr 里筛出进度步。"""
        for line in lines:
            step = interpret_line(line)
            if step is not None:
                yield step
