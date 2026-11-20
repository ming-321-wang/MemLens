"""
MemLens · 检测器框架

一个"检测器"= 一段可复用的取证推理逻辑：读若干插件产物 → 得出"发现项"（带证据与置信度）。

与"硬编码几个 if"的区别：
  * 检测器声明自己**需要哪些插件产物**（needs），缺哪个就明确跳过并说明原因；
  * 产出统一为 Detection（标题/描述/严重度/置信度/证据源/证据体）；
  * 置信度由**多源交叉验证**加权得出，单一来源不轻易下结论（控误报）；
  * 检测器不碰 UI、不碰命令行，纯数据进→数据出，可单测。
"""

from __future__ import annotations

import dataclasses
import json
from abc import ABC, abstractmethod
from typing import Any, Iterable, Sequence

from memlens.storage.db import DataStore


@dataclasses.dataclass
class Detection:
    """一条发现项。"""

    title: str
    description: str = ""
    severity: str = "medium"        # info / low / medium / high / critical
    confidence: float = 0.5         # 0~1
    sources: list[str] = dataclasses.field(default_factory=list)   # 参与判定的证据源（插件名）
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    rule_id: str = ""
    detector: str = ""

    def severity_from_confidence(self, *, high: float = 0.8, medium: float = 0.55) -> str:
        if self.confidence >= high:
            return "high"
        if self.confidence >= medium:
            return "medium"
        return "low"


class DetectionContext:
    """检测上下文：给检测器提供"按插件取记录"的能力（不暴露 SQL）。"""

    def __init__(self, store: DataStore, case_id: str) -> None:
        self.store = store
        self.case_id = case_id
        # ⚠ 缓存键**必须包含 limit**，否则会出现"毒化视图"（真实踩过的坑）：
        #   `has_plugin()` 为了省事用 `records(like, limit=1)` 探测"产物是否存在"，
        #   而它会在检测器真正取数之前被 `guard()` 调用 —— 如果缓存只按 pattern 做键，
        #   检测器随后拿到的就是**那条 limit=1 的结果**（实测 scanned_rows=1）。
        #   后果极其隐蔽：hidden_process 只看到 1 条 psscan 记录，于是把 34 个正常
        #   系统进程全判成"链表异常"（34 条假 HIGH），同时**漏掉真正的隐藏进程**。
        self._cache: dict[tuple[str, int], list[dict[str, Any]]] = {}

    def records(self, plugin_like: str, *, limit: int = 200_000) -> list[dict[str, Any]]:
        """
        取某个（或某类）插件产物里的全部记录。

        plugin_like 支持 SQL LIKE 通配，例如 `windows.ps%` 或 `%pslist%`。
        """
        key = (plugin_like, limit)
        if key not in self._cache:
            self._cache[key] = self.store.records_of_plugin(
                self.case_id, plugin_like, limit=limit)
        return self._cache[key]

    def has_plugin(self, plugin_like: str) -> bool:
        """产物是否存在（独立缓存，绝不与 records() 共用键）。"""
        key = ("__exists__", plugin_like)          # type: ignore[assignment]
        if key not in self._cache:                 # type: ignore[operator]
            self._cache[key] = self.store.records_of_plugin(   # type: ignore[index]
                self.case_id, plugin_like, limit=1)
        return len(self._cache[key]) > 0           # type: ignore[index]

    def artifacts(self) -> list[dict[str, Any]]:
        return self.store.list_artifacts(self.case_id)


class Detector(ABC):
    """检测器基类。"""

    name: str = "detector"
    display: str = "检测器"
    #: 依赖的插件产物（SQL LIKE 模式）；任一缺失则跳过并给出提示
    needs: tuple[str, ...] = ()
    #: 该检测器覆盖的严重度上限（供规则层参考）
    default_severity: str = "medium"

    @abstractmethod
    def run(self, ctx: DetectionContext) -> list[Detection]:
        raise NotImplementedError

    # ------------------------------------------------------------ 便利方法
    def missing_needs(self, ctx: DetectionContext) -> list[str]:
        return [n for n in self.needs if not ctx.has_plugin(n)]

    def guard(self, ctx: DetectionContext) -> str | None:
        """返回 None 表示可以运行；否则返回"为何跳过"的说明。"""
        missing = self.missing_needs(ctx)
        if missing:
            return f"缺少依赖产物：{', '.join(missing)}"
        return None


# ------------------------------------------------------------------ 通用工具

# 系统进程白名单（大小写不敏感）。注意：白名单只用于"降低置信度"，绝不用来"直接排除"——
# 攻击者恰恰会伪装成这些名字，所以命中白名单仍会报告，只是分数低一些。
#
# ★ v1.3：**白名单外置到规则包**（方案 FR-21：白名单由业务侧维护，不在代码里固化）。
#   这里的常量只作为"内置基线"，实际生效的是 `rulepack.current().whitelist_list("system_process")`。
SYSTEM_PROCESS_WHITELIST: frozenset[str] = frozenset(
    n.lower()
    for n in (
        "System", "Idle", "Registry", "Memory Compression", "Secure System",
        "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
        "winlogon.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe",
        "explorer.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe",
        "spoolsv.exe", "audiodg.exe", "conhost.exe", "dllhost.exe",
        "RuntimeBroker.exe", "SearchIndexer.exe", "WmiPrvSE.exe",
        "MsMpEng.exe", "SecurityHealthService.exe", "SystemSettings.exe",
        "StartMenuExperienceHost.exe", "TextInputHost.exe", "ShellExperienceHost.exe",
    )
)


def system_whitelist() -> frozenset[str]:
    """
    当前生效的系统进程白名单（**取自规则包**，缺失时回退内置基线）。

    每次调用都取一次规则包——规则包可在分析中途被业务侧换掉，
    这样"换规则包后重跑得到不同结论"是自然行为，不需要重启进程。
    """
    try:
        from memlens.core import rulepack
        items = rulepack.whitelist_list("system_process")
        if items:
            return frozenset(items)
    except Exception:
        pass
    return SYSTEM_PROCESS_WHITELIST


def is_whitelisted(name: str | None) -> bool:
    if not name:
        return False
    return str(name).strip().lower() in system_whitelist()


def get_field(rec: dict[str, Any], *candidates: str, default: Any = None) -> Any:
    """按候选键名（忽略大小写与非字母数字字符）取字段值。"""
    norm = {"".join(ch for ch in str(k).lower() if ch.isalnum()): v for k, v in rec.items()}
    for cand in candidates:
        key = "".join(ch for ch in cand.lower() if ch.isalnum())
        if key in norm and norm[key] not in (None, ""):
            return norm[key]
    return default


def to_int(value: Any) -> int | None:
    try:
        return int(str(value).split(".")[0])
    except (TypeError, ValueError):
        return None


def truncate(text: Any, n: int = 200) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= n else s[: n - 1] + "…"


# ------------------------------------------------------------------ 注册表
_REGISTRY: dict[str, type[Detector]] = {}


def register(cls: type[Detector]) -> type[Detector]:
    _REGISTRY[cls.name] = cls
    return cls


def all_detectors() -> list[Detector]:
    from memlens.detectors import (  # noqa: F401  触发注册
        hidden_process,
        injection,
        memprocfs_triage,
        static_pe,
    )

    return [cls() for cls in _REGISTRY.values()]


def get_detector(name: str) -> Detector:
    all_detectors()
    if name not in _REGISTRY:
        raise KeyError(f"未注册的检测器：{name}（已注册：{sorted(_REGISTRY)}）")
    return _REGISTRY[name]()


def run_all(ctx: DetectionContext, *, only: Sequence[str] | None = None) -> tuple[list[Detection], list[str]]:
    """
    跑全部（或指定）检测器。

    Returns:
        (发现项列表, 跳过说明列表)
    """
    findings: list[Detection] = []
    notes: list[str] = []
    for det in all_detectors():
        if only and det.name not in only:
            continue
        reason = det.guard(ctx)
        if reason:
            notes.append(f"[{det.name}] 跳过：{reason}")
            continue
        try:
            out = det.run(ctx)
        except Exception as exc:  # 单个检测器失败不影响其它
            notes.append(f"[{det.name}] 执行出错：{exc}")
            continue
        # 正面反馈：跑了但没命中也要说一声，否则用户会怀疑"检测器根本没动"
        if out:
            notes.append(f"[{det.name}] 已执行：{len(out)} 条发现项")
        else:
            notes.append(f"[{det.name}] 已执行：未产生发现项（当前证据集不满足触发阈值）")
        for d in out:
            d.detector = det.name
            if not d.rule_id:
                d.rule_id = det.name
        findings.extend(out)
    findings.sort(key=lambda d: (-d.confidence, d.title))
    return findings, notes
