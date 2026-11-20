"""
MemLens · 一键深度分析编排器（Deep Analyzer）

## 这是本工具的"主流程"

用户的原话：**"我不要快速、深度分析这些选项，我要这个工具打开附件就是深度分析全部内容。"**

所以本模块**没有"快速/深度"开关** —— 只有一条路径：
`打开附件 → 探测 → 生成计划 → 全量执行 → 检测 → 情报 → 时间线 → 旗标 → 系统画像 → 报告`

用户能干预的不是"分析多少"，而是"中途要不要停"（取消），以及"要不要重跑某个产物"。

## 分阶段与进度

| 阶段 | 权重 | 产出 |
|---|---|---|
| ① 探测 | 3% | 容器格式、操作系统、指纹证据 |
| ② 计划 | 2% | 将要跑什么（可解释） |
| ③ 引擎执行 | 55% | 全部产物（MemProcFS / vol3 / 字节扫描 / 静态） |
| ④ 检测器 | 12% | 发现项（异常内存、可疑进程、注入…） |
| ⑤ 情报 | 10% | IOC + 词典命中 |
| ⑥ 时间线 | 6% | 统一时间线 |
| ⑦ 旗标 | 4% | flag 候选 |
| ⑧ 系统画像 | 5% | **系统信息/版本/内存大小**（用户最想要的） |
| ⑨ 报告 | 3% | Markdown + HTML |

## 失败要说真话

任何阶段失败都**记进 summary 的 failed 列表**（阶段、插件、原因），
并在前端"运行状态"里显示。绝不"静默跳过"——那是 LovelyMem 的老毛病：
`os.path.exists` 一判就跳过，用户根本不知道为什么没有系统信息。
"""

from __future__ import annotations

import dataclasses
import os
import re
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Sequence

from memlens.core import image_probe
from memlens.core.image_probe import OSType, ProbeResult
from memlens.engines.base import EngineAdapter
from memlens.pipeline import plan as plan_mod
from memlens.pipeline import sysprofile as sp_mod
from memlens.storage.db import DataStore
from memlens.tasks.runner import ExecutionResult, TaskRunner

#: 阶段定义（名称, 权重, 说明）
PHASES: tuple[tuple[str, int, str], ...] = (
    ("probe", 3, "探测文件格式与操作系统"),
    ("plan", 2, "生成分析计划"),
    ("engine", 55, "执行全部取证引擎与插件"),
    ("detect", 12, "运行检测器（异常内存/隐藏进程/注入/可疑样本）"),
    ("intel", 10, "情报提取（IOC + 词典匹配）"),
    ("timeline", 6, "构建统一时间线"),
    ("flags", 4, "全量旗标扫描"),
    ("profile", 5, "合成系统画像（版本 / 内存大小 / CPU / 开机时间）"),
    ("report", 3, "生成报告"),
)


@dataclasses.dataclass
class DeepResult:
    """一次深度分析的结论。"""

    case_id: str = ""
    run_id: str = ""
    status: str = "ok"            # ok / failed / cancelled
    duration_ms: int = 0
    phases: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    artifacts: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    failed: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    skipped: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    findings: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    profile: dict[str, Any] = dataclasses.field(default_factory=dict)
    flags: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    stats: dict[str, Any] = dataclasses.field(default_factory=dict)
    plan: dict[str, Any] = dataclasses.field(default_factory=dict)
    errors: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class DeepAnalyzer:
    """把一个证据文件跑成一份完整报告。"""

    def __init__(
        self,
        store: DataStore,
        workdir: str | os.PathLike,
        *,
        engines: dict[str, EngineAdapter] | None = None,
        cancel_event: threading.Event | None = None,
        on_event: Callable[[str, Any], None] | None = None,
        run_id: str = "",
    ) -> None:
        self.store = store
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.cancel_event = cancel_event
        self.on_event = on_event or (lambda _k, _v: None)
        self.run_id = run_id
        self.engines: dict[str, EngineAdapter] = dict(engines or {})

    # ------------------------------------------------------------ 事件
    def _emit(self, kind: str, payload: Any) -> None:
        try:
            self.on_event(kind, payload)
        except Exception:
            pass

    def _log(self, text: str) -> None:
        self._emit("log", {"text": str(text)})

    def _cancelled(self) -> bool:
        return bool(self.cancel_event and self.cancel_event.is_set())

    # ------------------------------------------------------------ 进度
    def _make_progress(self) -> Callable[[str, float, str], None]:
        total = sum(w for _n, w, _d in PHASES)
        done = 0.0
        state = {"done": 0.0}

        def progress(phase: str, frac: float, message: str = "") -> None:
            state["done"] = done + max(0.0, min(1.0, frac)) * _weight(phase)
            self._emit("progress", {
                "phase": phase,
                "phase_message": message,
                "percent": round(100.0 * state["done"] / max(total, 1), 1),
            })

        # 让闭包能推进阶段
        def advance(phase: str, message: str = "") -> None:
            nonlocal done
            done += _weight(phase)
            progress(phase, 0.0, message)

        progress.advance = advance  # type: ignore[attr-defined]
        return progress  # type: ignore[return-value]

    # ------------------------------------------------------------ 主流程
    def analyze(
        self,
        image_path: str,
        *,
        case_id: str | None = None,
        name: str | None = None,
        reuse_case: bool = False,
    ) -> DeepResult:
        started = time.time()
        res = DeepResult(run_id=self.run_id)
        progress = self._make_progress()
        image_path = os.path.abspath(image_path)
        # ★ v1.3：分析动作属重点操作，**CLI 与 Web 都留痕**（方案 5.4）
        #   注意：必须等案件建好再写（此前 case_id 还没生成，落库会是空串，
        #   按案件查审计时反而查不到——实测踩过）。

        if not os.path.isfile(image_path):
            res.status = "failed"
            res.errors.append(f"文件不存在：{image_path}")
            return res

        try:
            # ---------------- ① 探测 ----------------
            # ★ 先发一个"立即"事件：深度探测要扫 192 MiB 指纹窗口（实测 2.1 s），
            #   如果探测完才发第一个进度，界面会有 **近 2 秒完全没动静** ——
            #   用户感受就是"点了没反应"。先动一下再慢慢干活。
            self._emit("progress", {"phase": "probe", "phase_message": "正在探测文件格式与操作系统…",
                                    "percent": 0.5})
            self._log(f"探测 {image_path}")
            probe = image_probe.probe_image(image_path, deep=True)
            self._emit("probe", _probe_payload(probe))
            res.plan["probe"] = _probe_payload(probe)

            # 案件
            if case_id and reuse_case:
                pass
            elif case_id:
                self.store.update_case(case_id, container=probe.container.value,
                                       os_type=probe.os_type.value,
                                       os_confidence=probe.os_confidence, state="analyzing")
            else:
                case_id = self.store.create_case(
                    name or Path(image_path).name,
                    image_path,
                    container=probe.container.value,
                    os_type=probe.os_type.value,
                    os_confidence=probe.os_confidence,
                )
            res.case_id = case_id
            self.store.update_case(case_id, state="analyzing")
            try:
                self.store.add_audit(actor="operator", action="analyze",
                                     target=image_path, case_id=case_id,
                                     critical=True,
                                     detail=f"启动深度分析 run={self.run_id}")
            except Exception:
                pass
            progress.advance("probe", f"容器={probe.container.value} 系统={probe.os_type.value}")

            # ---------------- ② 计划 ----------------
            plan = plan_mod.build_plan(probe, self.engines)
            res.plan["plan"] = plan.summary()
            res.skipped = plan.skipped
            self._emit("plan", plan.summary())
            for note in plan.notes:
                self._log(f"计划：{note}")
            progress.advance("plan", f"共 {len(plan.items)} 个执行项")

            # ---------------- ③ 引擎执行 ----------------
            # ★ v1.8：识别"疑似合成/占位样本"（MemLens 自带 synthetic_* 测试样本）——
            #   这类样本无真实内核，MemProcFS/vol3 必然失败，给用户明确中文提示而非"数据源不可用"。
            syn = image_probe.looks_synthetic(image_path)
            _syn_sug = ""
            if syn and syn.get("synthetic"):
                self._log(f"⚠ 疑似合成/占位样本：{syn['detail']}")
                res.stats["synthetic"] = syn
                _syn_sug = ("该检材疑似合成/占位样本（零字节 {z}%、无内核特征），不是真实内存镜像，"
                            "MemProcFS/vol3 不适用。请用真实 Windows 内存镜像（几百 MB~GB），"
                            "或改用 memstrings/static 引擎（无符号依赖，合成样本也能出字符串/进程名）。"
                            ).format(z=syn["zero_pct"])
            else:
                syn = None
            gap_rows: list[dict[str, Any]] = []
            self._run_engines(case_id, plan, res, progress, gap_rows, image_path=image_path)
            # 合成样本：把"数据源不可用"类缺口的建议改写为明确提示
            if _syn_sug:
                for g in gap_rows:
                    if str(g.get("suggestion", "")).startswith("该数据源在本环境不可用"):
                        g["suggestion"] = _syn_sug
                gap_rows.append({
                    "scope": "synthetic", "source": "synthetic",
                    "dimension": "数据源", "impact": "none",
                    "reason": (f"该检材疑似合成/占位样本（零字节 {syn['zero_pct']}%，无内核特征）"),
                    "suggestion": _syn_sug,
                })

            # ---------------- ④ 检测器 ----------------
            if not self._cancelled():
                self._run_detectors(case_id, res)
            progress.advance("detect")

            # ★ v1.3：把计划阶段的"跳过项"也变成结构化缺口
            for sk in plan.skipped:
                gap_rows.append({
                    "scope": "dimension",
                    "dimension": sk.get("plugin") or sk.get("engine") or "",
                    "source": sk.get("plugin") or sk.get("engine") or "",
                    "reason": sk.get("reason") or "按计划跳过",
                    "impact": "downgrade",
                    "level_cap": "",
                    "suggestion": (_syn_sug if _syn_sug else
                                  "该数据源在本环境不可用；结论相应维度按降级处理。"),
                })

            # ---------------- ⑤ 情报 ----------------
            if not self._cancelled():
                self._phase(res, "intel", lambda: self._run_intel(case_id, res))
            progress.advance("intel")

            # ---------------- ⑥ 时间线 ----------------
            if not self._cancelled():
                self._phase(res, "timeline", lambda: self._run_timeline(case_id, res))
            progress.advance("timeline")

            # ---------------- ⑦ 旗标 ----------------
            if not self._cancelled():
                self._phase(res, "flags", lambda: self._run_flags(case_id, res))
            progress.advance("flags")

            # ---------------- ⑧ 系统画像 ----------------
            if not self._cancelled():
                self._phase(res, "profile", lambda: self._run_profile(case_id, probe, res))
            progress.advance("profile")

            # ---------------- ⑨ 报告 ----------------
            if not self._cancelled():
                self._phase(res, "report", lambda: self._run_report(case_id, res))
            progress.advance("report")

            # ★ v1.3：缺口清单入库（方案表 9：缺口是独立实体，须结构化存储）
            try:
                self.store.clear_gaps(case_id)
                if gap_rows:
                    for g in gap_rows:
                        n_aff = int(g.pop("affected", 1) or 1)
                        if n_aff > 1:
                            g["reason"] = f"{g.get('reason','')}（{n_aff} 个产物受同一根因影响）"
                    n = self.store.add_gaps(case_id, gap_rows)
                    self._log(f"缺口清单：{n} 项（缺什么 / 为什么 / 怎么补）")
            except Exception as exc:
                res.errors.append(f"缺口清单入库失败：{exc}")

            res.artifacts = self.store.list_artifacts(case_id)
            res.findings = self.store.list_findings(case_id)
            res.stats = self.store.stats(case_id)
            res.status = "cancelled" if self._cancelled() else "ok"

        except Exception as exc:                       # pragma: no cover
            res.status = "failed"
            res.errors.append(f"{type(exc).__name__}: {exc}")
            self._log("异常：\n" + traceback.format_exc())

        res.duration_ms = int((time.time() - started) * 1000)
        try:
            self.store.add_audit(actor="operator", action="analyze_done",
                                 target=image_path, case_id=case_id or "",
                                 detail=(f"深度分析结束：状态={res.status}，"
                                         f"产物={len(res.artifacts)}，"
                                         f"发现项={len(res.findings)}"))
        except Exception:
            pass
        if case_id:
            try:
                self.store.update_case(case_id, state="done" if res.status == "ok" else "failed")
            except Exception:
                pass
            if self.run_id:
                try:
                    self.store.upsert_run(
                        self.run_id, case_id, state=res.status, finished_at=_now(),
                        summary_json={"stats": res.stats, "errors": res.errors,
                                      "failed": res.failed, "duration_ms": res.duration_ms},
                    )
                except Exception as exc:
                    # 记录批次失败**绝不能**把一次已经跑完的分析顶成崩溃
                    res.errors.append(f"分析批次登记失败：{exc}")
        return res

    def _phase(self, res: DeepResult, name: str, fn) -> None:
        """
        执行一个阶段；该阶段异常只记录，**不影响后续阶段**。

        为什么需要：以前时间线阶段抛一次 NameError，
        就会把后面 旗标 / 系统画像 / 报告 三个阶段全跳过 ——
        用户看到的是"跑完了、产物有一堆、但什么都没有"。
        """
        try:
            fn()
        except Exception as exc:
            res.errors.append(f"阶段「{name}」失败：{exc}")
            self._log(f"⚠ 阶段「{name}」失败：{exc}")

    # ------------------------------------------------------------ ③ 引擎
    def _run_engines(self, case_id: str, plan: plan_mod.AnalysisPlan,
                     res: DeepResult, progress,
                     gap_rows: list[dict[str, Any]] | None = None, image_path: str = "") -> None:
        gap_rows = gap_rows if gap_rows is not None else []
        by_engine: dict[str, list[plan_mod.PlanItem]] = {}
        for item in plan.items:
            by_engine.setdefault(item.engine, []).append(item)

        total_items = len(plan.items) or 1
        done_items = 0

        # 引擎顺序：MemProcFS 优先（一次挂载拿全量），再 vol3，再字节扫描，最后静态
        order = ["memprocfs", "vol3", "memstrings", "static"]
        ordered = [e for e in order if e in by_engine] + \
                  [e for e in by_engine if e not in order]

        for engine_name in ordered:
            if self._cancelled():
                break
            engine = self.engines.get(engine_name)
            items = by_engine[engine_name]
            if engine is None:
                for it in items:
                    res.failed.append({"engine": engine_name, "plugin": it.plugin,
                                       "reason": "引擎未注册"})
                continue
            ok, why = engine.available()
            if not ok:
                self._log(f"引擎 {engine_name} 不可用：{why}")
                for it in items:
                    res.failed.append({"engine": engine_name, "plugin": it.plugin,
                                       "reason": why})
                done_items += len(items)
                continue

            # ★ 符号表预检：vol3 引擎跑插件前先准备内核 ISF（对齐 GUI 三段式）。
            #   真镜像会自动联网下载 PDB→ISF（首次 1-3 分钟，之后缓存）；
            #   无有效内核的镜像（合成/占位样本）会明确失败并记缺口，不再白跑。
            if engine_name == "vol3" and image_path and hasattr(engine, "warmup"):
                self._log("符号表预检：准备内核 ISF（首次需联网下载 1-3 分钟）…")
                self._emit("progress", {"phase": "symbols", "phase_message": "正在准备内核符号表…",
                                        "percent": 0.0})
                try:
                    wr = engine.warmup(image_path, timeout=1800.0,
                                       on_line=lambda ln: self._log("[vol3] " + ln.strip()[:200]),
                                       cancel_event=self.cancel_event)
                    if not wr.ok:
                        reason = str(wr.error or "未知原因").replace("\n", " ")[:200]
                        self._log(f"符号预检未通过：{reason}")
                        gap_rows = gap_rows if gap_rows is not None else []
                        _add_gap(gap_rows, {"reason": f"符号预检失败：{reason}",
                                            "scope": "vol3", "dimension": "符号表"})
                        skipped_items = [it for it in items if it.plugin.startswith("windows.")]
                        for it in skipped_items:
                            res.skipped.append({"engine": engine_name, "plugin": it.plugin,
                                                "reason": f"符号预检失败：{reason}"})
                        items = [it for it in items if not it.plugin.startswith("windows.")]
                        done_items += len(skipped_items)
                        if not items:
                            self._log("vol3 所有插件因符号表未就绪而跳过")
                            continue
                    else:
                        self._log("符号预检通过：内核 ISF 就绪")
                except Exception as exc:
                    self._log(f"符号预检异常：{exc}")

            self._log(f"── 引擎 {engine.display}：{len(items)} 个插件 ──")
            # 引擎内部按插件顺序串行（vol3 并行会打断内核定位，实测）
            runner = TaskRunner(self.store, engine, workdir=self.workdir / "artifacts")
            plugin_by_name = {p.name: p for p in engine.list_plugins()}
            for idx, it in enumerate(items, 1):
                if self._cancelled():
                    break
                meta = plugin_by_name.get(it.plugin)
                if meta is None:
                    res.failed.append({"engine": engine_name, "plugin": it.plugin,
                                       "reason": "插件不在引擎清单中（可能被上游改名）"})
                    continue
                self._emit("plugin_start", {
                    "engine": engine_name, "plugin": it.plugin,
                    "display": it.display, "index": idx, "total": len(items),
                })
                r = runner.run_plugin(
                    case_id, meta, it.params or None,
                    on_line=lambda line, _n=it.plugin: self._log(f"[{_n}] {line}"),
                    cancel_event=self.cancel_event,
                    timeout=_timeout_for(it),
                )
                self._emit("plugin_done", {
                    "engine": engine_name, "plugin": it.plugin,
                    "status": r.status, "rows": r.rows,
                    "duration_ms": r.duration_ms, "error": r.error,
                })
                if r.status == "failed":
                    res.failed.append({"engine": engine_name, "plugin": it.plugin,
                                       "reason": r.error or "未知原因"})
                    # ★ v1.3：失败必须变成**结构化缺口**（方案表 9），
                    #   不能只躺在日志里——报告要能写"缺了什么、为什么缺、怎么补"。
                    _add_gap(gap_rows, {
                        "scope": "source",
                        "dimension": it.plugin,
                        "source": f"{engine_name}:{it.plugin}",
                        "reason": r.error or "未知原因",
                        "impact": "blocked" if it.required else "downgrade",
                        "level_cap": "",
                        "suggestion": _suggest_for(r.error or ""),
                    })
                elif r.status == "partial":
                    _add_gap(gap_rows, {
                        "scope": "source",
                        "dimension": it.plugin,
                        "source": f"{engine_name}:{it.plugin}",
                        "reason": r.error or "执行成功但未解析出任何记录",
                        "impact": "downgrade",
                        "level_cap": "",
                        "suggestion": _suggest_for(r.error or ""),
                    })
                done_items += 1
                progress("engine", done_items / total_items,
                         f"{engine_name} · {it.display}")

    # ------------------------------------------------------------ ④ 检测器
    def _run_detectors(self, case_id: str, res: DeepResult) -> None:
        try:
            from memlens.detectors import base as det_base
        except Exception as exc:
            res.errors.append(f"检测器模块不可用：{exc}")
            return
        ctx = det_base.DetectionContext(self.store, case_id)
        self.store.clear_findings(case_id)
        try:
            detections, skipped = det_base.run_all(ctx)
        except Exception as exc:
            res.errors.append(f"检测器执行失败：{exc}")
            return
        for det in detections:
            try:
                self.store.add_finding(
                    case_id, title=det.title, detector=det.detector,
                    description=det.description, severity=det.severity,
                    confidence=det.confidence, sources=det.sources, evidence=det.evidence,
                )
            except Exception:
                continue
        for s in skipped:
            res.skipped.append({"detector": s, "reason": "依赖的产物缺失"})
        self._log(f"检测器完成：{len(detections)} 条发现项，{len(skipped)} 个检测器因缺产物跳过")

    # ------------------------------------------------------------ ⑤ 情报
    def _run_intel(self, case_id: str, res: DeepResult) -> None:
        try:
            from memlens.intel import scan as intel_scan
        except Exception as exc:
            res.errors.append(f"情报模块不可用：{exc}")
            return
        self._log("情报扫描中（IOC + 词典）…")
        try:
            report = intel_scan.scan_case(
                self.store, case_id,
                on_progress=lambda msg: self._log(f"情报：{msg}"),
                cancel=(lambda: self._cancelled()),
            )
        except Exception as exc:
            res.errors.append(f"情报扫描失败：{exc}")
            return
        for note in report.notes:
            self._log(f"情报：{note}")
        # 情报结果也进专表（便于前端按类型筛选）
        try:
            ioc_rows = self.store.records_of_plugin(case_id, "intel.ioc", limit=5000)
            self.store.add_iocs(case_id, [
                {"kind": str(r.get("ioc_type") or "other"), "value": str(r.get("value") or ""),
                 "context": r.get("context"), "severity": str(r.get("severity") or "info"),
                 "score": float(r.get("score") or 0.0), "source": str(r.get("source") or ""),
                 "hits": int(r.get("count") or 1)}
                for r in ioc_rows if isinstance(r, dict) and r.get("value")
            ])
        except Exception:
            pass
        self._log(f"情报完成：{report.summary()}")

    # ------------------------------------------------------------ ⑥ 时间线
    def _run_timeline(self, case_id: str, res: DeepResult) -> None:
        try:
            from memlens import timeline as tl
        except Exception as exc:
            res.errors.append(f"时间线模块不可用：{exc}")
            return
        try:
            rows = self.store.records_with_source(case_id, limit=600_000,
                                                   skip_plugins=("intel.", "memlens."))
            events = tl.build_timeline(rows, limit=50_000)
        except Exception as exc:
            # ⚠ 这一步以前会把整次分析顶掉：它在 try 块之外抛异常时，
            #   后面 旗标/画像/报告 三个阶段全被跳过 → 用户看到"跑完了但什么都没有"。
            #   现在每个阶段自己兜住自己的异常。
            res.errors.append(f"时间线构建失败：{exc}")
            self._log(f"⚠ 时间线构建失败：{exc}")
            return
        payload = []
        for e in events:
            rec = e.to_record()
            payload.append({
                # ★ v1.3：统一 UTC 入库 + 保留原始时区与偏移量（方案 5.3）
                "ts": rec.get("ts_utc") or rec.get("time") or rec.get("raw_time"),
                "ts_utc": rec.get("ts_utc"),
                "ts_local": rec.get("ts_local"),
                "ts_raw": rec.get("ts_raw"),
                "tz_offset": rec.get("tz_offset"),
                "tz_name": rec.get("tz_name"),
                "tz_assumption": rec.get("tz_assumption"),
                "ts_epoch": _to_epoch(rec.get("ts_utc")),
                "source": e.source_plugin,
                "category": _category_of(e.source_plugin),
                "title": e.title,
                "detail": e.detail,
                "ref_plugin": e.source_plugin,
            })
        try:
            self.store.clear_timeline(case_id)
            self.store.add_timeline_events(case_id, payload)
        except Exception as exc:
            res.errors.append(f"时间线入库失败：{exc}")
        self._log(f"时间线：{len(payload)} 个事件")

    # ------------------------------------------------------------ ⑦ 旗标
    def _run_flags(self, case_id: str, res: DeepResult) -> None:
        try:
            from memlens.core import flagbank
        except Exception as exc:
            res.errors.append(f"旗标模块不可用：{exc}")
            return
        try:
            hits = flagbank.collect(self.store, case_id, limit=500)
        except Exception as exc:
            res.errors.append(f"旗标扫描失败：{exc}")
            return
        res.flags = hits
        try:
            self.store.add_flags(case_id, [
                {"value": h.get("value"), "kind": h.get("kind"),
                 "offset": h.get("offset"), "context": h.get("ctx"),
                 "source": ", ".join(h.get("sources") or []),
                 "confidence": 0.95 if h.get("kind") == "明文" else 0.5}
                for h in hits
            ])
        except Exception:
            pass
        if hits:
            self._log(f"旗标候选 {len(hits)} 条，最高置信：{hits[0].get('value')}")

    # ------------------------------------------------------------ ⑧ 系统画像
    def _run_profile(self, case_id: str, probe: ProbeResult, res: DeepResult) -> None:
        sysinfo_text = ""
        users_text = ""
        product_id = ""
        vol3_records: dict[str, list[dict[str, Any]]] = {}

        # MemProcFS 的 sysinfo / users / productid 产物。
        # ⚠ 它们的记录是**本地化键名**的字典：
        #     sysinfo  → {"字段": "Physical Memory", "值": "2 GB"}
        #     users    → {"序号": "0000", "用户名": "Administrator", "SID": "S-1-5-21-…"}
        #     productid→ {"字段": "ProductId", "值": "…"}
        #   之前这里只取 `r.get("value")`（英文键）→ 全部取空 →
        #   系统画像只剩 2 个字段，"内存大小取不到"的锅其实在这里。
        for artifact in self.store.list_artifacts(case_id):
            plugin = artifact.get("plugin") or ""
            if plugin not in ("mprocfs.sysinfo", "mprocfs.users", "mprocfs.productid"):
                continue
            rows = self.store.records_of_plugin(case_id, plugin, limit=5000)
            if not rows:
                path = artifact.get("output_path")
                if path and os.path.isfile(path):
                    try:
                        raw = Path(path).read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        raw = ""
                    if plugin == "mprocfs.sysinfo":
                        sysinfo_text = raw
                    elif plugin == "mprocfs.users":
                        users_text = raw
                    else:
                        product_id = raw.strip()[:256]
                continue
            if plugin == "mprocfs.sysinfo":
                sysinfo_text = _kv_rows_to_text(rows)
            elif plugin == "mprocfs.users":
                users_text = _user_rows_to_text(rows)
            else:
                product_id = _product_id_from_rows(rows)

        # vol3 记录（用于交叉验证）
        for artifact in self.store.list_artifacts(case_id):
            plugin = artifact.get("plugin") or ""
            if not plugin.startswith("vol3."):
                continue
            low = plugin.lower()
            if not any(k in low for k in ("statistics", "banners", "vmcoreinfo", "boottime",
                                          "check_sysctl", "verinfo", "info")):
                continue
            rows = self.store.records_of_plugin(case_id, plugin, limit=5000)
            if rows:
                vol3_records[plugin] = rows

        case = self.store.get_case(case_id) or {}
        profile = sp_mod.build_profile(
            probe_os=probe.os_type.value,
            sysinfo_text=sysinfo_text or None,
            users_text=users_text or None,
            vol3_records=vol3_records,
            image_path=case.get("image_path"),
            image_size=case.get("image_size"),
            image_sha256=case.get("image_sha256"),
            container=probe.container.value,
            extra={"product_id": product_id} if product_id else None,
        )
        data = profile.to_dict()
        res.profile = data
        # ★ 扁平字段写进列（可直接 SQL 查询），完整画像写进 profile_json
        fields = data.get("fields", {}) or {}
        flat = {k: v.get("value") for k, v in fields.items()}
        sources = {k: v.get("source") for k, v in fields.items()}
        try:
            self.store.set_system_profile(case_id, flat, sources, data)
        except Exception as exc:
            res.errors.append(f"系统画像入库失败：{exc}")
        filled = len([f for f in fields.values()])
        self._log(f"系统画像：合成 {filled} 个字段"
                  + (f"，用户 {len(profile.users)} 个" if profile.users else ""))
        for w in profile.warnings:
            self._log(f"⚠ {w}")

    # ------------------------------------------------------------ ⑨ 报告
    def _run_report(self, case_id: str, res: DeepResult) -> None:
        try:
            from memlens import report as report_mod
        except Exception as exc:
            res.errors.append(f"报告模块不可用：{exc}")
            return
        out_dir = self.workdir / case_id / "report"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            md = report_mod.build_markdown(self.store, case_id)
            (out_dir / "report.md").write_text(md, encoding="utf-8")
            html = report_mod.build_html(self.store, case_id)
            (out_dir / "report.html").write_text(html, encoding="utf-8")
            self._log(f"报告已生成：{out_dir}")
        except Exception as exc:
            res.errors.append(f"报告生成失败：{exc}")


# ------------------------------------------------------------------ 辅助

#: 常见失败原因 → 建议补证方式（方案表 12「建议补证」的通用映射）
_SUGGESTIONS: tuple[tuple[str, str], ...] = (
    ("failed opening file", "该文件不是 MemProcFS 可打开的内存镜像；改用 vol3 / memstrings 通道，"
                             "或确认镜像路径与格式（见「探测」结论）"),
    ("device open", "该文件不是 MemProcFS 可打开的内存镜像；改用 vol3 / memstrings 通道"),
    ("symbol", "预置该内核版本的 ISF 符号表（memlens symbols --import-kernel），或联网补齐后再跑"),
    ("符号", "预置该内核版本的 ISF 符号表（memlens symbols --import-kernel），或联网补齐后再跑"),
    ("layer_name", "确认镜像完整性（是否缺 .vmsn/.vmsd 元数据）；必要时改用 memprocfs 引擎"),
    ("readonly database", "检查 work/vol3/cache 是否可写；缓存目录不可写会导致 vol3 全量失败"),
    ("unable to open database", "确认 work/vol3/cache 目录已创建（vol3 不会自建）"),
    ("unsuitable symbol tables", "镜像对应的内核构建没有现成 ISF；从符号包补齐后重跑"),
    ("pdb", "PDB 下载失败；离线环境请预置符号表或改用 memstrings / memprocfs 通道"),
    ("permission", "关闭占用该文件的程序（虚拟机、其它取证工具）后重试"),
    ("failed to initialize", "镜像可能只是部分物理内存；改用 --engine vol3 或补全整机镜像"),
    ("timeout", "该插件在当前镜像上超时；可单独调大超时或跳过（结论相应降级）"),
    ("超时", "该插件在当前镜像上超时；可单独调大超时或跳过（结论相应降级）"),
    ("not supported", "该插件对镜像版本有硬性要求；换用同功能的通用替代插件"),
)


def _add_gap(gap_rows: list[dict[str, Any]], gap: dict[str, Any]) -> None:
    """
    追加一条缺口；**同一根因自动合并**。

    为什么合并：一次镜像格式不匹配会让 MemProcFS 的 **30+ 个产物全部报同一条错误**，
    逐条列进缺口清单会把清单冲垮（实测 131 条里 103 条是同一个根因）。
    合并后写成一条「N 个产物受影响」，缺口清单才读得懂、也才可能被真正处理。
    """
    reason = str(gap.get("reason") or "")
    # ★ 归一化后再比对：vol3 的 stderr 带 "Progress: 23.33" 这类实时进度，
    #   每个插件的尾巴都不一样 → 不归一化的话同一根因会散成几十条。
    key = _gap_key(reason)
    for g in gap_rows:
        if g.get("_key") == key and g.get("scope") == gap.get("scope"):
            g["affected"] = int(g.get("affected") or 1) + 1
            dims = str(g.get("dimension") or "")
            if dims and dims not in str(g.get("affected_plugins") or ""):
                g["affected_plugins"] = (str(g.get("affected_plugins") or "") + "," + dims).strip(",")
            return
    gap["affected"] = 1
    gap["affected_plugins"] = str(gap.get("dimension") or "")
    gap["_key"] = key
    gap_rows.append(gap)


def _gap_key(reason: str) -> str:
    """
    缺口的"根因键"：把易变的噪音剥掉，只留下真正的失败原因。

    剥掉的东西：vol3 的 `Progress: 23.33` 实时进度、空白差异、截断差异。
    """
    text = str(reason or "")
    text = re.sub(r"Progress:[^\n]*", "Progress: …", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:160]


def _suggest_for(reason: str) -> str:
    """把失败原因翻译成"建议怎么补"。"""
    low = (reason or "").lower()
    for key, advice in _SUGGESTIONS:
        if key.lower() in low:
            return advice
    if not reason:
        return "查看该产物在「产物」页的「详情」，确认是数据缺失还是引擎未就绪。"
    return "查看该产物在「产物」页的「详情」；必要时换用其它引擎或补齐数据源后重跑。"


# ------------------------------------------------------------------ 辅助

#: MemProcFS 产物的记录是**本地化键名**的字典，这里做键名兼容
_KV_KEY_NAMES = ("字段", "键", "key", "Key", "name", "Name", "项目", "名称", "条目")
_KV_VAL_NAMES = ("值", "value", "Value", "内容", "文本", "结果", "说明", "数据")
_USER_NAME_NAMES = ("用户名", "用户", "username", "user", "name", "Name", "名称", "路径", "path")
_USER_SID_NAMES = ("SID", "sid", "Sid", "用户SID", "SecurityId")
#: 行内含 SID 的形态：`Administrator  (S-1-5-21-…)` / `C:\Users\X  (S-1-…)`
_SID_IN_LINE_RE = re.compile(r"\(\s*S-1-[0-9\-]+\s*\)")


def _pick(record: dict[str, Any], names: Sequence[str]) -> str:
    """按候选键名顺序取值（本地化优先，其次英文）。"""
    for n in names:
        v = record.get(n)
        if v not in (None, ""):
            return str(v)
    # 再按"归一化后包含"兜底
    norm = {("".join(ch for ch in str(k).lower() if ch.isalnum())): v
            for k, v in record.items()}
    for n in names:
        key = "".join(ch for ch in str(n).lower() if ch.isalnum())
        for k, v in norm.items():
            if key and key in k and v not in (None, ""):
                return str(v)
    return ""


def _kv_rows_to_text(rows: Sequence[dict[str, Any]]) -> str:
    """
    把 MemProcFS 的 {"字段": k, "值": v} 记录还原成 sysinfo.txt 风格文本。

    段标题（值��空）还原成 "标题:" 行，正好能被 `parse_memprocfs_sysinfo`
    的 `_SECTION_RE` 识别成分段；分隔线（全是 -）直接丢掉。
    """
    out: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        k = _pick(r, _KV_KEY_NAMES)
        v = _pick(r, _KV_VAL_NAMES)
        if set(k) <= set("-= _") and k:
            continue
        # ⚠ MemProcFS 的 `_parse_kv_text` 按**第一个冒号**切分，
        #   于是 Windows 路径行 `C:\Users\Administrator  (S-1-…)` 被切成
        #   key="C" / value="\Users\Administrator  (S-1-…)"；
        #   而没有冒号的 `Administrator  (S-1-…)` 则变成 key="" / value=整行。
        #   实测后果：**第一个用户整行丢失、第二个用户路径被拆坏**，
        #   画像里只剩一个半截路径的用户。
        if _SID_IN_LINE_RE.search(v or ""):
            out.append(f"{k}:{v}" if k else v)     # 路径型：拼回 "C:\Users\…"
            continue
        if not k:
            continue
        if v:
            out.append(f"{k}: {v}")
        else:
            out.append(f"{k}:")
    return "\n".join(out)


def _user_rows_to_text(rows: Sequence[dict[str, Any]]) -> str:
    """把 MemProcFS 的 users 记录还原成 "名称 (SID)" 行。"""
    out: list[str] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        name = _pick(r, _USER_NAME_NAMES)
        sid = _pick(r, _USER_SID_NAMES)
        if not name:
            continue
        out.append(f"{name} ({sid})" if sid else name)
    return "\n".join(out)


def _product_id_from_rows(rows: Sequence[dict[str, Any]]) -> str:
    for r in rows:
        if not isinstance(r, dict):
            continue
        k = _pick(r, _KV_KEY_NAMES)
        v = _pick(r, _KV_VAL_NAMES)
        if k and "product" in k.lower() and v:
            return v[:256]
        if v and len(v) >= 32 and "-" in v:
            return v[:256]
    return ""


def _weight(phase: str) -> int:
    for name, w, _d in PHASES:
        if name == phase:
            return w
    return 1


def _now() -> str:
    import datetime as dt
    return dt.datetime.now().isoformat(timespec="seconds")


def _to_epoch(value: Any) -> float | None:
    """任意时间表示 → Unix 秒（用于排序与区间过滤）。"""
    import datetime as dt
    if not value:
        return None
    # 先走统一时间基准（能处理 Z 后缀与偏移）
    from memlens.core import timebase
    tv = timebase.normalize(value)
    if tv.ok and tv.utc is not None:
        return tv.utc.timestamp()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return dt.datetime.strptime(str(value)[:26], fmt).timestamp()
        except ValueError:
            continue
    return None


def _category_of(plugin: str) -> str:
    p = (plugin or "").lower()
    if "process" in p or "pslist" in p or "psscan" in p or "thread" in p:
        return "进程"
    if "net" in p or "sock" in p or "tcp" in p:
        return "网络"
    if "registry" in p or "hive" in p:
        return "注册表"
    if "file" in p or "ntfs" in p:
        return "文件"
    if "service" in p or "svc" in p:
        return "服务"
    if "module" in p or "driver" in p:
        return "模块"
    if "mal" in p or "inject" in p or "evil" in p or "yara" in p:
        return "恶意代码"
    return "其它"


def _probe_payload(probe: ProbeResult) -> dict[str, Any]:
    return {
        "path": probe.path,
        "size": probe.size,
        "container": probe.container.value,
        "container_confidence": probe.container_confidence,
        "os_type": probe.os_type.value,
        "os_confidence": probe.os_confidence,
        "zero_ratio": probe.zero_ratio,
        "evidence": [{"source": e.source, "detail": e.detail, "weight": e.weight}
                     for e in probe.evidence],
        "warnings": list(probe.warnings),
        "summary": probe.summary(),
    }


def _timeout_for(item: plan_mod.PlanItem) -> float:
    """慢插件给更长的超时（否则大镜像上会被误杀成"失败"）。"""
    if item.heavy:
        return 1800.0
    return 900.0
