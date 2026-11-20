"""
MemLens · 后台任务（GUI 与核心之间的桥）

原则：**所有耗时的引擎调用都在工作线程里**，UI 线程只做信号回填。
这样即使跑几分钟的插件，界面也不会卡死（这是桌面取证工具的底线体验）。

v0.9 起，"一键分析"被拆成**有先后的三段**——这是从"跑了半天什么都没出来"里学到的：

    ① 字节快扫（秒级~分钟级）
       memstrings.flag / ioc 直接在原始字节上找 flag 与 IOC。**不依赖任何符号表**，
       所以哪怕内核符号还没就绪，用户也立刻有东西看。夺旗题常常在这一步就出答案。
    ② 符号预检（首次 1-3 分钟，之后 3 秒）
       只跑 windows.info，把内核与 ISF 符号表准备好。期间把 vol3 的进度翻译成人话
       （建索引/扫页表/找内核/下载符号），并如实上报；失败则给出可执行建议。
    ③ 插件循环
       逐个执行所选插件；每个插件都回传状态、行数、耗时、真实失败原因。
       ②失败时 windows.* 插件直接标记为"跳过"并说明原因，不再白跑二十分钟。
"""

from __future__ import annotations

import threading
import time
import traceback
from pathlib import Path
from typing import Any, Sequence

from PySide6.QtCore import QThread, Signal

from memlens.core import flagbank
from memlens.core.image_probe import can_analyze, describe, probe_image
from memlens.core.vol3_env import Vol3Env, interpret_line
from memlens.detectors.base import DetectionContext, run_all
from memlens.engines import registry
from memlens.engines.base import PluginMeta
from memlens.engines.vol3 import Volatility3Adapter, diagnose_failure
from memlens.storage.db import DataStore
from memlens.tasks.runner import TaskRunner

#: 字节快扫阶段使用的插件（顺序即优先级）。
#: 只放 flag 扫描：IOC 提取在真实镜像上会产出十几万条记录（实测 158,728 条/2GiB），
#: 既拖时间又灌爆结果表；需要时用「字节扫描·全量」预设或情报页单跑。
PRESCAN_PLUGINS = ("memstrings.flag",)


class ProbeWorker(QThread):
    """镜像探测（读文件、算指纹，可能几秒到几十秒）。"""

    done = Signal(object)      # ProbeResult
    failed = Signal(str)

    def __init__(self, image_path: str, *, deep: bool = True) -> None:
        super().__init__()
        self.image_path = image_path
        self.deep = deep

    def run(self) -> None:  # noqa: D102
        try:
            result = probe_image(self.image_path, deep=self.deep)
            self.done.emit(result)
        except Exception as exc:
            self.failed.emit(f"{exc}\n{traceback.format_exc()}")


class AnalyzeWorker(QThread):
    """
    一键分析：探测 → 建案 → 字节快扫 → 符号预检 → 逐个执行插件 → 检测器 → 汇总。

    通过 `event` 信号回传的事件（kind）：
      stage   → {"text": str}                          当前阶段（状态栏/日志）
      line    → {"plugin": str, "line": str}           引擎原始输出
      phase   → {"plugin", "phase", "label", "text", "percent", "elapsed_ms"}
                                                       翻译后的进度（界面画进度条/阶段）
      progress→ {"plugin", "done", "total", "percent"}  内置引擎（字节扫描）的字节进度
      result  → {"plugin", "display", "status", "rows", "duration_ms", "error", "reason", "advise"}
      symbol  → {"ok", "summary", "error", "advise", "kernel", "symbol_path", "duration_ms"}
      flags   → {"items": [...], "best": {...} | None}  flag 候选汇总
      case    → {"case_id", "name"}
      probe   → {...}
      done    → {"case_id", "stats", "findings": [...]}
    """

    event = Signal(str, dict)
    failed = Signal(str)

    def __init__(
        self,
        *,
        image_path: str,
        plugins: Sequence[PluginMeta],
        db_path: str | Path,
        workdir: str | Path,
        case_name: str = "",
        engine_name: str = "vol3",
        renderer: str = "jsonl",
        timeout: float | None = 1800.0,
        cache: bool = True,
        fast_probe: bool = False,
        fast_hash: bool = True,
        case_id: str | None = None,
        pre_scan: bool = True,
        warmup: bool = True,
        loose_flags: bool = False,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.image_path = image_path
        self.plugins = list(plugins)
        self.db_path = Path(db_path)
        self.workdir = Path(workdir)
        self.case_name = case_name or Path(image_path).stem
        self.engine_name = engine_name
        self.renderer = renderer
        self.timeout = timeout
        self.cache = cache
        self.fast_probe = fast_probe
        self.fast_hash = fast_hash
        self.case_id = case_id          # 复用已有案件（例如"再扫一遍 flag"）
        self.pre_scan = pre_scan
        self.warmup = warmup
        self.loose_flags = loose_flags
        self._cancel = threading.Event()
        self._started_at = time.time()

    # ------------------------------------------------------------------ 控制
    def cancel(self) -> None:
        """请求取消（协作式：当前插件会被 terminate，后续插件不再启动）。"""
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    # ------------------------------------------------------------------ 辅助
    def _emit_result(self, plugin: PluginMeta, res, *, status: str | None = None,
                     reason: str | None = None, advise: str = "") -> None:
        status = status or res.status
        rows = getattr(res, "rows", 0)
        duration_ms = getattr(res, "duration_ms", 0)
        error = getattr(res, "error", None)
        tail = getattr(res, "stderr_tail", "") or ""
        if reason is None and status in ("failed", "partial", "skipped"):
            diag = diagnose_failure(tail)
            if diag:
                reason, advise = diag[0], diag[1]
            else:
                from memlens.core.vol3_env import key_errors
                lines = key_errors(tail)
                reason = lines[0] if lines else error
        self.event.emit("result", {
            "plugin": plugin.name, "display": plugin.display,
            "status": status, "rows": rows, "duration_ms": duration_ms,
            "error": error, "reason": reason, "advise": advise,
            "artifact_id": getattr(res, "artifact_id", None),
        })

    # ------------------------------------------------------------------ 主流程
    def run(self) -> None:  # noqa: C901
        try:
            self.event.emit("stage", {"text": f"探测镜像：{self.image_path}"})
            probe = probe_image(self.image_path, deep=not self.fast_probe,
                               for_engine=self.engine_name)
            self.event.emit("stage", {"text": "探测完成：" + probe.summary()})
            self.event.emit("probe", {
                "summary": probe.summary(),
                "container": probe.container.value,
                "os_type": probe.os_type.value,
                "os_confidence": probe.os_confidence,
                "analysable": probe.analysable,
                "warnings": list(probe.warnings),
                "describe": describe(probe),
            })

            # 统一可分析性判断（与按钮状态、CLI 共用同一份逻辑，避免再次漂移）
            ok_analyze, why_not = can_analyze(probe, self.engine_name)
            if not ok_analyze:
                self.event.emit("stage", {
                    "text": f"⚠ 容器 {probe.container.value} 需要先解包，已停止自动分析"
                })
                self.failed.emit(why_not)
                return

            engine = registry.get(self.engine_name)
            ok, why = engine.available()
            if not ok:
                self.failed.emit(f"引擎不可用：{why}")
                return

            store = DataStore(self.db_path)
            try:
                if self.case_id:
                    self.event.emit("case", {"case_id": self.case_id, "name": self.case_name})
                else:
                    self.event.emit("stage", {"text": "建立案件并计算镜像哈希…"})
                    self.case_id = store.create_case(
                        self.case_name, self.image_path,
                        container=probe.container.value,
                        os_type=probe.os_type.value,
                        os_confidence=probe.os_confidence,
                        hash_limit=64 << 20 if self.fast_hash else None,
                    )
                    self.event.emit("case", {"case_id": self.case_id, "name": self.case_name})

                # ---------------- 阶段①：字节快扫（不依赖符号表）----------------
                if self.pre_scan and self.engine_name in ("vol3", "memstrings") \
                        and not self._cancel.is_set():
                    self._run_pre_scan(store, self.case_id)

                # ---------------- 阶段②：符号预检 ----------------
                kernel_ok = True
                if self.warmup and isinstance(engine, Volatility3Adapter) \
                        and not self._cancel.is_set():
                    kernel_ok = self._run_warmup(engine)

                # ---------------- 阶段③：插件循环 ----------------
                if not self._cancel.is_set():
                    self._run_plugins(store, engine, kernel_ok)

                # ---------------- 检测器 + flag 汇总 ----------------
                if not self._cancel.is_set():
                    self.event.emit("stage", {"text": "运行检测器（多源交叉验证）…"})
                    # 先把"检测器实际看到的证据集"打出来：曾出现过检测器取不到
                    # psscan 记录而把几十个正常进程误报成异常的坑，留一行可核对的数字最省事
                    for like in ("%pslist%", "%psscan%", "%malfind%", "%static.profile%"):
                        try:
                            n = len(store.records_of_plugin(self.case_id, like, limit=200_001))
                        except Exception:
                            n = -1
                        self.event.emit("line", {
                            "plugin": "detectors",
                            "line": f"证据集 {like} → {n} 条" + ("（空，相关检测器会跳过）" if n == 0 else ""),
                        })
                    ctx = DetectionContext(store, self.case_id)
                    findings, notes = run_all(ctx)
                    store.clear_findings(self.case_id)
                    for d in findings:
                        store.add_finding(
                            self.case_id, title=d.title, detector=d.detector, rule_id=d.rule_id,
                            description=d.description, severity=d.severity,
                            confidence=d.confidence, sources=d.sources, evidence=d.evidence,
                        )
                    for n in notes:
                        self.event.emit("line", {"plugin": "detectors", "line": n})

                self._emit_flags(store)

                stats = store.stats(self.case_id)
                self.event.emit("done", {
                    "case_id": self.case_id,
                    "stats": stats,
                    "elapsed_ms": int((time.time() - self._started_at) * 1000),
                })
            finally:
                store.close()
        except Exception as exc:
            self.failed.emit(f"{exc}\n{traceback.format_exc()}")

    # ------------------------------------------------------------- 阶段实现
    def _run_pre_scan(self, store: DataStore, case_id: str) -> None:
        """字节级快扫：任何容器都能跑，夺旗题的第一把钥匙。"""
        ms_engine = registry.get("memstrings")
        pool = {p.name: p for p in ms_engine.list_plugins()}
        plugins = [pool[n] for n in PRESCAN_PLUGINS if n in pool]
        if not plugins:
            return
        self.event.emit("stage", {
            "text": "步骤 1/3 · 字节级快扫（flag / IOC，不依赖符号表，大镜像约 1-3 分钟）"
        })
        runner = TaskRunner(store, ms_engine, workdir=self.workdir / "artifacts")
        for idx, plugin in enumerate(plugins, 1):
            if self._cancel.is_set():
                return
            self.event.emit("stage", {
                "text": f"步骤 1/3 · 字节快扫 {idx}/{len(plugins)}：{plugin.display}"
            })
            res = runner.run_plugin(
                case_id, plugin, {"loose": self.loose_flags},
                cancel_event=self._cancel, timeout=self.timeout, cache=self.cache,
                on_progress=lambda done, total, _p=plugin: self.event.emit(
                    "progress", {"plugin": _p.name, "done": done, "total": total,
                                 "percent": (done / total * 100.0) if total else None}),
            )
            self._emit_result(plugin, res)

    def _run_warmup(self, engine: Volatility3Adapter) -> bool:
        """符号预检：把"看不见的三分钟"变成看得见的阶段。"""
        env = Vol3Env(self.workdir).ensure()
        env.apply(engine)
        st = env.status()
        self.event.emit("stage", {
            "text": "步骤 2/3 · 定位内核与符号表：" + st.summary()
        })
        t0 = time.time()

        def on_line(line: str) -> None:
            step = interpret_line(line)
            if step is not None:
                self.event.emit("phase", {
                    "plugin": "windows.info", "phase": step.phase, "label": step.label,
                    "text": step.text, "percent": step.percent,
                    "elapsed_ms": int((time.time() - t0) * 1000),
                })
            elif line.strip():
                self.event.emit("line", {"plugin": "vol3", "line": line})

        res = engine.warmup(self.image_path, timeout=self.timeout or 1800.0,
                            on_line=on_line, cancel_event=self._cancel)
        self.event.emit("symbol", {
            "ok": res.ok, "summary": res.summary(), "error": res.error,
            "advise": res.advise, "kernel": res.kernel, "symbol_path": res.symbol_path,
            "duration_ms": res.duration_ms, "layer": res.layer,
            "key_lines": res.key_lines, "status": env.status().summary(),
        })
        return bool(res.ok)

    def _run_plugins(self, store: DataStore, engine: Any, kernel_ok: bool) -> None:
        runner = TaskRunner(store, engine, workdir=self.workdir / "artifacts")
        total = len(self.plugins)
        runnable: list[PluginMeta] = []
        for p in self.plugins:
            needs_kernel = p.name.startswith("windows.")
            if not kernel_ok and needs_kernel:
                self._emit_result(
                    p, _Skipped(), status="skipped",
                    reason="内核符号表未就绪：该插件必须解析 Windows 内核结构，"
                           "先解决符号表问题再跑（见上方「符号预检」的结论）",
                    advise="① 确认能访问 msdl.microsoft.com（下载 PDB 需要）；"
                           "② 或把已有的 windows.zip 符号包解压到工作目录的 vol3/symbols 下。")
            else:
                runnable.append(p)

        for idx, plugin in enumerate(runnable, 1):
            if self._cancel.is_set():
                self.event.emit("stage", {"text": "已取消"})
                break
            self.event.emit("stage", {
                "text": f"步骤 3/3 · 插件 {idx}/{len(runnable)}：{plugin.display} [{plugin.name}]"
            })
            t0 = time.time()

            def on_line(line: str, _p=plugin, _t0=t0) -> None:
                step = interpret_line(line)
                if step is not None:
                    self.event.emit("phase", {
                        "plugin": _p.name, "phase": step.phase, "label": step.label,
                        "text": step.text, "percent": step.percent,
                        "elapsed_ms": int((time.time() - _t0) * 1000),
                    })
                elif line.strip():
                    self.event.emit("line", {"plugin": _p.name, "line": line})

            res = runner.run_plugin(
                self.case_id, plugin, {"renderer": self.renderer},
                cancel_event=self._cancel, timeout=self.timeout, cache=self.cache,
                on_line=on_line,
            )
            self._emit_result(plugin, res)

    def _emit_flags(self, store: DataStore) -> None:
        try:
            items = flagbank.collect(store, self.case_id, limit=300,
                                     include_loose=self.loose_flags)
        except Exception as exc:
            self.event.emit("line", {"plugin": "flagbank", "line": f"旗标汇总失败：{exc}"})
            return
        best = next((i for i in items if i["kind"] == "明文"), None)
        self.event.emit("flags", {"items": items, "best": best, "count": len(items)})


class _Skipped:
    """给"跳过"的插件造一个与 ExecutionResult 同形的占位（保持回填逻辑统一）。"""

    status = "skipped"
    rows = 0
    duration_ms = 0
    error = None
    stderr_tail = ""
    artifact_id = None
    output_path = None


class DetectWorker(QThread):
    """只跑检测器（不改镜像、不跑插件）——用于"我改了规则想重算一遍"的场景。"""

    done = Signal(list, list)      # findings, notes
    failed = Signal(str)

    def __init__(self, db_path: str | Path, case_id: str) -> None:
        super().__init__()
        self.db_path = Path(db_path)
        self.case_id = case_id

    def run(self) -> None:
        try:
            store = DataStore(self.db_path)
            try:
                ctx = DetectionContext(store, self.case_id)
                findings, notes = run_all(ctx)
                store.clear_findings(self.case_id)
                for d in findings:
                    store.add_finding(
                        self.case_id, title=d.title, detector=d.detector, rule_id=d.rule_id,
                        description=d.description, severity=d.severity,
                        confidence=d.confidence, sources=d.sources, evidence=d.evidence,
                    )
            finally:
                store.close()
            self.done.emit(findings, notes)
        except Exception as exc:
            self.failed.emit(f"{exc}\n{traceback.format_exc()}")
