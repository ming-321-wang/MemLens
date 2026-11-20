r"""
MemLens · Volatility3 符号表（ISF）管理

## 为什么单独一个模块

vol3 的插件能不能跑，**唯一前提**是"内核 ISF 符号表就绪"。而 ISF 的获取路径很脆弱：

  * 默认要从微软符号服务器下载 PDB（`ntkrnlmp.pdb` 约 40 MB）再转成 ISF（1-3 分钟）；
  * 下载/转换要写盘，写不进去（打包 exe 落在只读目录、企业策略、无网络）时，
    vol3 只在 stderr 丢一行，最后以 `symbol table requirement was not fulfilled` 收场；
  * 用户看到的现象就是**所有插件全失败、界面只剩日志** —— 这正是 MemLens 被抱怨的
    "只会输出日志"的典型成因之一。

因此这里提供三条腿：
  1. **只读引用**：把本机已有的 ISF 目录（例如比赛工具包里自带的 `symbols`）作为
     额外搜索路径传给 vol3（`-s a;b`），零拷贝、离线可用、秒级生效；
  2. **本地导入**：把别人的 ISF 复制进 MemLens 自己的工作目录，做成便携、可归档的符号库；
  3. **现状可见**：随时能查"我现在到底有没有符号、覆盖哪些系统"，而不是靠猜。

⚠ 只读引用他人目录时**只读不写**：vol3 的 `-s` 参数是"搜索路径"，新 ISF 只会写进
MemLens 自己可写的工作目录（放在 `-s` 列表第一位）。
"""

from __future__ import annotations

import os
import shutil
import sys
import json
import lzma
import urllib.request
from pathlib import Path
from typing import Callable, Iterable, Sequence

#: 额外符号源的注册文件（每行一个目录，允许相对项目根）
SOURCES_FILE = "vol3_sources.txt"
#: 环境变量（分号分隔）也可以追加符号源
ENV_SOURCES = "MEMLENS_VOL3_SYMBOLS"
_KINDS = ("windows", "linux", "mac")


def project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def work_symbols_dir(workdir: str | os.PathLike) -> Path:
    """MemLens 自己的工作符号目录（必然可写、跟案件走）。"""
    return Path(workdir) / "vol3" / "symbols"


def _sources_file(workdir: Path) -> Path:
    return Path(workdir) / SOURCES_FILE


def extra_sources(workdir: str | os.PathLike | None = None) -> list[Path]:
    """
    列出"只读引用"的额外符号目录（去重、必须真实存在）。

    来源优先级：环境变量 > 注册文件 > 项目内约定目录。
    """
    wd = Path(workdir) if workdir else (project_root() / "work")
    out: list[Path] = []

    env = os.environ.get(ENV_SOURCES) or ""
    for part in env.split(";"):
        part = part.strip()
        if part:
            out.append(Path(part))

    reg = _sources_file(wd)
    if reg.is_file():
        try:
            for line in reg.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    p = Path(line)
                    out.append(p if p.is_absolute() else (project_root() / p))
        except OSError:
            pass

    root = project_root()
    out += [root / "tools" / "vol3_symbols", root / "tools" / "symbols"]

    seen: set[str] = set()
    alive: list[Path] = []
    for p in out:
        try:
            key = str(p.resolve()).lower()
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)
        if p.is_dir():
            alive.append(p)
    return alive


def add_source(dir_path: str | os.PathLike, workdir: str | os.PathLike | None = None) -> Path:
    """把某个目录登记为常驻只读符号源（写入注册文件，不复制任何文件）。"""
    wd = Path(workdir) if workdir else (project_root() / "work")
    p = Path(dir_path)
    if not p.is_dir():
        raise FileNotFoundError(f"目录不存在：{p}")
    reg = _sources_file(wd)
    reg.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if reg.is_file():
        lines = [ln for ln in reg.read_text(encoding="utf-8").splitlines() if ln.strip()]
    entry = str(p.resolve())
    if entry not in lines:
        lines.append(entry)
        reg.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return reg


def symbol_dirs(workdir: str | os.PathLike, *, extra: Iterable[Path] = ()) -> list[Path]:
    """
    传给 vol3 `-s` 的完整符号目录列表。

    **自己的可写目录必须排第一**：vol3 会把新下载/转换的 ISF 写进第一个可写目录，
    排在后面就会试图写进别人的只读目录（实测会以权限错误告终）。
    """
    out: list[Path] = [work_symbols_dir(workdir)]
    for p in list(extra) or extra_sources(workdir):
        try:
            if p.is_dir() and p.resolve() != out[0].resolve():
                out.append(p)
        except OSError:
            continue
    return out


def join_for_cli(dirs: Iterable[Path]) -> str:
    return ";".join(str(d) for d in dirs)


def indexable_extra_sources(workdir: str | os.PathLike) -> list[Path]:
    """
    筛出"可以安全挂进 vol3 `-s`"的额外符号源。

    判据是**条目数量**：小源（≤ MAX_INDEXABLE_ISF）挂上去几乎零成本；
    大源（几千个 ISF）会让 vol3 首次运行就为它重建标识符索引 —— 实测 3000+ 条目
    时 CPU 上千秒仍未结束。遇到大源就跳过并提示改用按内核精确导入。
    """
    out: list[Path] = []
    for src in extra_sources(workdir):
        if sum(scan(src).values()) <= MAX_INDEXABLE_ISF:
            out.append(src)
    return out


# ------------------------------------------------------- 按内核精确取符号表


def kernel_pdb_from_modules_csv(csv_path: str | os.PathLike) -> tuple[str, str, str] | None:
    """
    从 MemProcFS 的 `modules.csv` 里读内核模块的 PDB 身份。

    Returns:
        (pdb 文件名, GUID, age)，例如 ("ntkrnlmp.pdb", "3844DBB920174967BE7AA4A2C20430FA", "2")

    为什么从这里读：MemProcFS 的 modules.csv 每行都带 `PdbPath/PdbAge/PdbHexGUID`，
    而且这份 CSV 在 MemLens 自己的会话目录里（无需再解析镜像），拿它当"镜像内核指纹"
    最省事也最可靠。
    """
    import csv

    p = Path(csv_path)
    if p.is_dir():
        p = p / "harvest" / "forensic" / "csv" / "modules.csv"
    if not p.is_file():
        return None
    try:
        with open(p, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            for row in csv.DictReader(f):
                pdb = (row.get("PdbPath") or "").strip().replace("\\", "/").rsplit("/", 1)[-1]
                guid = (row.get("PdbHexGUID") or "").strip()
                age = (row.get("PdbAge") or "").strip()
                if pdb.lower().startswith("nt") and guid and age:
                    return pdb, guid.upper(), age
    except OSError:
        return None
    return None


def import_kernel(
    workdir: str | os.PathLike,
    *,
    session_dir: str | os.PathLike | None = None,
    src: str | os.PathLike | None = None,
) -> list[Path]:
    """
    只把**目标镜像内核需要的那个 ISF** 复制进 MemLens 符号目录。

    这是"大符号库"的正确用法：
      * 先按内核 GUID+age 精确定位（来自 MemProcFS 会话的 modules.csv）；
      * 只拷一个文件（约 10-40 MB），vol3 立刻可用、离线可用、无需建全量索引；
      * 定位不到身份时退化为"复制 nt* 内核系列 ISF"，仍然远小于全量。
    """
    wd = Path(workdir)
    dst_root = work_symbols_dir(wd) / "windows"
    dst_root.mkdir(parents=True, exist_ok=True)

    ident = kernel_pdb_from_modules_csv(session_dir) if session_dir else None
    sources = [Path(src)] if src else (extra_sources(wd) + [work_symbols_dir(wd)])
    copied: list[Path] = []

    for s in sources:
        win = s / "windows" if (s / "windows").is_dir() else s
        if not win.is_dir():
            continue
        cands: list[Path] = []
        if ident:
            pdb, guid, age = ident
            cands += [f for f in win.glob(f"{pdb}/*.json.xz")
                      if f.name.lower().startswith(f"{guid.lower()}-")]
        if not cands:
            cands = [f for f in win.rglob("*.json.xz")
                     if f.parent.name.lower().startswith(("ntkrnlmp", "ntoskrnl",
                                                          "ntkrnlpa", "ntkrpamp"))]
        for f in cands:
            dst = dst_root / f.parent.name / f.name
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dst)
                copied.append(dst)
            except OSError:
                continue
    return copied


# --------------------------------------------------------------------- 现状


def scan(root: str | os.PathLike) -> dict[str, int]:
    """统计某个符号目录下的 ISF 数量（按 windows/linux/mac 分类）。"""
    base = Path(root)
    out: dict[str, int] = {k: 0 for k in _KINDS}
    out["其他"] = 0
    if not base.is_dir():
        return out
    try:
        for p in base.rglob("*.json.xz"):
            kind = next((k for k in _KINDS if k in p.parts), "其他")
            out[kind] = out.get(kind, 0) + 1
    except OSError:
        pass
    return out


def describe(workdir: str | os.PathLike) -> str:
    """一句话说明当前符号环境（GUI/CLI 都直接用）。"""
    wd = Path(workdir)
    own = scan(work_symbols_dir(wd))
    own_total = sum(own.values())
    lines = [f"自有符号目录：{work_symbols_dir(wd)}（ISF {own_total} 个："
             f"windows {own['windows']} / linux {own['linux']} / mac {own['mac']}）"]
    for src in extra_sources(wd):
        s = scan(src)
        n = sum(s.values())
        lines.append(f"只读引用：{src}（ISF {n} 个："
                     f"windows {s['windows']} / linux {s['linux']} / mac {s['mac']}）"
                     + (f"  ⚠ 条目过多（>{MAX_INDEXABLE_ISF}），"
                        "vol3 会为它建索引而显著拖慢首次运行；"
                        "建议改用 `symbols --import-kernel --image <镜像>` 只取需要的内核符号表"
                        if n > MAX_INDEXABLE_ISF else ""))
    if len(lines) == 1:
        lines.append("提示：可以用 `memlens symbols --add-dir <已有 symbols 目录>` 只读挂接"
                     "本机已有的符号表（例如比赛工具包里自带的 volatility3\\symbols），"
                     "即可离线秒出结果，无需联网下载。")
    return "\n".join(lines)


#: 可以直接挂进 vol3 `-s` 的 ISF 条目上限。
#: 超过这个数量，vol3 首次运行要为整个源建标识符索引（实测 3000+ 条目时 CPU 上千秒），
#: 反而把"离线可用"变成"等半小时" —— 这种情况应该**只取需要的那一个内核符号表**。
MAX_INDEXABLE_ISF = 400


# --------------------------------------------------------------------- 导入


def import_from(
    src: str | os.PathLike,
    workdir: str | os.PathLike,
    *,
    progress: Callable[[int, int], None] | None = None,
    overwrite: bool = False,
) -> tuple[int, int, int]:
    """
    把某个来源的 ISF 复制进 MemLens 自己的符号目录（做便携、离线符号库）。

    src 允许是三种形态：vol3 的 `symbols` 目录本身、它的父目录、或比赛工具包里的
    `Tools/volatility3/symbols`。

    Returns:
        (复制数量, 跳过数量, 复制字节数)
    """
    base = Path(src)
    if not base.is_dir():
        raise FileNotFoundError(f"目录不存在：{base}")
    # 允许传父目录：自动下探一层找 symbols/
    if not any((base / k).is_dir() for k in _KINDS):
        cand = base / "symbols"
        if any((cand / k).is_dir() for k in _KINDS):
            base = cand
    files = [p for p in base.rglob("*.json.xz") if p.is_file()]
    dst_root = work_symbols_dir(workdir)
    dst_root.mkdir(parents=True, exist_ok=True)

    copied = skipped = 0
    total_bytes = 0
    total = max(1, len(files))
    for i, f in enumerate(files, 1):
        rel = f.relative_to(base)
        dst = dst_root / rel
        try:
            if dst.exists() and not overwrite and dst.stat().st_size == f.stat().st_size:
                skipped += 1
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dst)
                copied += 1
                total_bytes += f.stat().st_size
        except OSError:
            skipped += 1
        if progress and (i % 50 == 0 or i == total):
            progress(i, total)
    return copied, skipped, total_bytes
# =====================================================================
# PDB → ISF 按需转换（vol3 离线符号）
# ---------------------------------------------------------------------
# 背景：用户给的 "最新 MemProcFS 符号表" 是 **PDB 布局**
#   （Symbols/<pdb名>/<GUID+age>/<pdb名>.pdb），MemProcFS 直接可用；
#   但 vol3 需要 **ISF（.json.xz）**，PDB 不直接吃。
#   单个 PDB → ISF 实测约 38.5s（5.2MB），1076 个全转约 11.5h → 不可行。
#   所以做"按需转换 + 缓存"：镜像内核 GUID 命中本地 PDB 时才转这一个。
# =====================================================================


def pdb_to_isf(
    pdb_path: str | os.PathLike,
    out_dir: str | os.PathLike,
    progress: Callable[[int, int], None] | None = None,
) -> Path:
    """
    把**本地 PDB** 转成 vol3 ISF（.json.xz），缓存到 `out_dir/windows/<pdb名>/<GUID>-<age>.json.xz`。

    用 vol3 自带的 PdbReader（PDB → JSON 符号格式），单个约 20-60s。
    已转换的同 GUID 直接复用（返回既有文件，不重复转）。
    """
    pdb_path = Path(pdb_path)
    if not pdb_path.is_file():
        raise FileNotFoundError(f"PDB 不存在：{pdb_path}")
    from volatility3.framework import contexts
    from volatility3.framework.symbols.windows.pdbconv import PdbReader

    dst_root = Path(out_dir) / "windows" / pdb_path.name
    dst_root.mkdir(parents=True, exist_ok=True)

    ctx = contexts.Context()
    location = "file:" + urllib.request.pathname2url(os.path.abspath(pdb_path))
    conv = PdbReader(ctx, location, database_name=pdb_path.name)
    js = conv.get_json()
    meta = js.get("metadata", {}).get("windows", {}).get("pdb", {})
    guid = str(meta.get("GUID") or "")
    age = str(meta.get("age") or "")
    if not guid:
        raise ValueError(f"PDB 无 GUID：{pdb_path.name}")
    out = dst_root / f"{guid}-{age}.json.xz"
    if out.exists():
        return out
    with lzma.open(out, "wb") as f:
        f.write(bytes(json.dumps(js, indent=2, sort_keys=True), "latin-1"))
    if progress:
        progress(100, 100)
    return out


def find_local_pdb(
    guid: str,
    age: str,
    pdb_name: str,
    pdb_dirs: Sequence[str | os.PathLike],
) -> Path | None:
    """按 GUID+age 在本地 PDB 符号源里找对应 PDB（布局 `<src>/<pdb名>/<GUID+age>/<pdb名>.pdb`）。"""
    key = guid + age
    for d in pdb_dirs:
        cand = Path(d) / pdb_name / key / pdb_name
        if cand.is_file():
            return cand
        # 兜底：大小写/后缀变体
        cand2 = Path(d) / pdb_name / key / (pdb_name[:-1] + "_")
        if cand2.is_file():
            return cand2
    return None


def convert_for_image(
    workdir: str | os.PathLike,
    image: str | os.PathLike,
    *,
    session_dir: str | os.PathLike | None = None,
    pdb_dirs: Sequence[str | os.PathLike] | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> list[Path]:
    """
    按需转换：**镜像内核 GUID → 本地 PDB → ISF**，缓存到 MemLens 符号目录。

    用于 vol3 离线：分析前对目标镜像跑一次，vol3 就有对应 ISF（无需联网）。

    流程：
      1. 从 MemProcFS 会话（modules.csv）拿内核 PDB 身份 (pdb, guid, age)；
      2. 在本地 PDB 源（默认 MemProcFS 的 Symbols 目录）按 GUID 找 PDB；
      3. PdbReader 转 ISF → `workdir/vol3/symbols/windows/<pdb>/<guid>-<age>.json.xz`。

    Returns:
        成功转换/复用的 ISF 路径列表（没命中则空列表）。
    """
    wd = Path(workdir)
    if not session_dir:
        try:
            from memlens.engines.memprocfs import MemProcFSAdapter
            ad = MemProcFSAdapter()
            sess = ad.loaded_session(str(image))
            session_dir = sess.root if sess else ad.session_dir(str(image))
        except Exception:
            session_dir = None
    ident = kernel_pdb_from_modules_csv(session_dir) if session_dir else None
    if not ident:
        return []
    pdb_name, guid, age = ident

    if not pdb_dirs:
        from memlens.engines.memprocfs import MemProcFSAdapter
        ad = MemProcFSAdapter()
        pdb_dirs = [str(ad.symbols_dir)] if ad.symbols_dir else []
    pdb_path = find_local_pdb(guid, age, pdb_name, pdb_dirs)
    if not pdb_path:
        return []
    out = pdb_to_isf(pdb_path, work_symbols_dir(wd), progress=progress)
    return [out]
