r"""
MemLens · 五维判定引擎（违规跨境访问检测模块）

## 对应方案

《计算机系统数字取证工作台开发方案》4.2 节：违规跨境访问检测模块。

五个维度按**"工具存在—通道配置—实际执行—数据外联—访问方向"**排列，
前一个是后一个的**必要条件**（方案 4.2.1）：

    没有工具 → 谈不上通道 → 谈不上执行

但"前一维不成立"**不等于停止判定**：外联证据若独立成立，可以反推前维，
此时前维记为"**痕迹已被清理**"而不是"不存在"（方案 4.2.1 原文——
这个区分在复核时经常成为争点：有人认为工具痕迹没找到就是没用过，
实际上**清理痕迹本身也是行为证据**）。

## 三条硬约定（方案 3.3 插件接口的五条约定之落地）

1. **输出必须携带依据证据项编号** —— 找不到证据编号的结论视为无效；
2. **必须声明依赖的数据源**，运行时缺源即走**降级分支**而非报错退出；
3. **必须声明所用阈值与规则包版本** —— 结论可复现的前提。

## 降级是常态，不是异常

方案 1.2 断点二说得很直白：

> Windows 默认审计策略只记录部分登录事件，安全日志的实际留存常见为七到十四天
> ……因此方法不能假设日志齐全，必须是多源交叉，并预先写死源缺失时的降级路径。

所以本引擎**不假设数据齐全**：
每个维度声明自己的数据源清单，缺源时按方案表 12 的降级路径给出
「仍可证明什么 / 结论上限 / 建议补证」，并把降级写进 `gaps` 表。

## 两套结论体系（方案 1.5 / 4.2.5）

- **检查用法**：已确认 / 存在风险 / 记录备查，用"发现""存在""疑似"表述；
- **取证用法**：A / B / C 级，用"证实""可采信"表述。

同一批数据，两种用法的结论强度不同，**词表不得混用**。
`usage` 参数决定用哪一套。
"""

from __future__ import annotations

import dataclasses
from typing import Any

from memlens.core import rulepack
from memlens.detectors.base import DetectionContext

#: 五个维度的标识（与方案 FR-01~FR-05 对应）
DIMENSIONS: tuple[str, ...] = (
    "tool_presence",       # FR-01 工具存在性
    "channel_config",      # FR-02 通道配置
    "execution_trace",     # FR-03 运行痕迹
    "data_egress",         # FR-04 数据外联
    "access_direction",    # FR-05 访问方向
)

#: 维度 → 方案功能编号
DIMENSION_FR: dict[str, str] = {
    "tool_presence": "FR-01",
    "channel_config": "FR-02",
    "execution_trace": "FR-03",
    "data_egress": "FR-04",
    "access_direction": "FR-05",
}

#: 维度中文名
DIMENSION_LABEL: dict[str, str] = {
    "tool_presence": "工具存在",
    "channel_config": "通道配置",
    "execution_trace": "实际执行",
    "data_egress": "数据外联",
    "access_direction": "访问方向",
}


# ------------------------------------------------------------------ 结论体系

#: 检查用法三档（方案表 14）
CHECK_TIERS: dict[str, str] = {
    "confirmed": "已确认",
    "risk": "存在风险",
    "record": "记录备查",
}

#: 取证用法三级（方案表 14）
FORENSIC_LEVELS: dict[str, str] = {
    "A": "A 级（两个以上独立来源互证）",
    "B": "B 级（单一来源内部多点一致）",
    "C": "C 级（单点痕迹）",
}

#: 检查用法的表述词（方案 4.2.5：不得使用"认定""证实""可采信"）
CHECK_WORDS: tuple[str, ...] = ("发现", "存在", "疑似")

#: 取证用法的表述词
FORENSIC_WORDS: tuple[str, ...] = ("证实", "可采信", "表明", "支持")


@dataclasses.dataclass
class DimensionResult:
    """
    一个维度的判定结果。

    Attributes:
        dimension: 维度标识
        score: 该维得分 0~1
        state: 三态语义
            - `established` 已成立
            - `cleared`   痕迹已被清理（外联反推，方案 4.2.1 的关键区分）
            - `not_found` 未发现
            - `degraded`  数据源缺失，只能降级判定
        level_cap: 该维的**结论等级上限**（A/B/C；单机采集通常封顶 B）
        evidence_refs: 依据证据项编号集合（方案 3.3：无法回溯的结论视为无效）
        sources_used: 实际用到的数据源
        sources_missing: 缺失的数据源
        findings: 人类可读的判定要点
        gaps: 降级说明（缺失维度 / 原因 / 建议补证）
        independent_sources: 独立来源数（定 A/B/C 用）
    """

    dimension: str
    score: float = 0.0
    state: str = "not_found"
    level_cap: str = "C"
    evidence_refs: list[str] = dataclasses.field(default_factory=list)
    sources_used: list[str] = dataclasses.field(default_factory=list)
    sources_missing: list[str] = dataclasses.field(default_factory=list)
    findings: list[str] = dataclasses.field(default_factory=list)
    gaps: list[dict[str, str]] = dataclasses.field(default_factory=list)
    independent_sources: int = 0
    #: 是否已完成与**网络侧设备记录**的三处交叉（时间/域名/进程·使用人）
    #: —— 方案 4.2.4：只有接入外部记录并完成三处交叉，方可评为 A 级。
    #: ★ 与"本维度内部有多少来源"**无关**：主机侧来源再多也只是主机侧。
    external_cross_ok: bool = False

    @property
    def label(self) -> str:
        return DIMENSION_LABEL.get(self.dimension, self.dimension)

    @property
    def fr(self) -> str:
        return DIMENSION_FR.get(self.dimension, "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "label": self.label,
            "fr": self.fr,
            "score": round(float(self.score), 4),
            "state": self.state,
            "level_cap": self.level_cap,
            "evidence_refs": list(self.evidence_refs),
            "sources_used": list(self.sources_used),
            "sources_missing": list(self.sources_missing),
            "findings": list(self.findings),
            "gaps": list(self.gaps),
            "independent_sources": self.independent_sources,
            "external_cross_ok": bool(self.external_cross_ok),
        }


@dataclasses.dataclass
class Verdict:
    """
    五维综合结论（FR-06 打分与分级 + FR-07 结论输出）。
    """

    usage: str = "check"            # check（检查用法）/ forensic（取证用法）
    tier: str = "record"            # 检查三档
    level: str = "C"                # 取证三级
    total: float = 0.0
    dimensions: list[DimensionResult] = dataclasses.field(default_factory=list)
    level_cap: str = "C"            # 整体等级上限
    rulepack_version: str = ""
    rulepack_sha256: str = ""
    notes: list[str] = dataclasses.field(default_factory=list)
    gaps: list[dict[str, str]] = dataclasses.field(default_factory=list)

    def dim(self, name: str) -> DimensionResult | None:
        for d in self.dimensions:
            if d.dimension == name:
                return d
        return None

    @property
    def tier_label(self) -> str:
        return CHECK_TIERS.get(self.tier, self.tier)

    @property
    def level_label(self) -> str:
        return FORENSIC_LEVELS.get(self.level, self.level)

    def to_dict(self) -> dict[str, Any]:
        return {
            "usage": self.usage,
            "tier": self.tier,
            "tier_label": self.tier_label,
            "level": self.level,
            "level_label": self.level_label,
            "total": round(float(self.total), 4),
            "level_cap": self.level_cap,
            "rulepack_version": self.rulepack_version,
            "rulepack_sha256": self.rulepack_sha256,
            "dimensions": [d.to_dict() for d in self.dimensions],
            "notes": list(self.notes),
            "gaps": list(self.gaps),
        }


# ------------------------------------------------------------------ 引擎基类


class Dimension:
    """
    维度插件基类。

    子类必须声明：
      * `dimension` —— 维度标识
      * `sources`   —— 依赖的数据源（SQL LIKE 模式，与检测器一致）
      * `level_cap` —— 单机采集下的结论等级上限
    """

    dimension: str = ""
    #: 依赖的数据源（SQL LIKE 模式）
    sources: tuple[str, ...] = ()
    #: 单机采集下的等级上限（方案表 12：多数维度单机可到 A，外联维只能 B）
    level_cap: str = "A"

    def available_sources(self, ctx: DetectionContext) -> tuple[list[str], list[str]]:
        """返回 (可用源, 缺失源)。"""
        used: list[str] = []
        missing: list[str] = []
        for s in self.sources:
            (used if ctx.has_plugin(s) else missing).append(s)
        return used, missing

    def run(self, ctx: DetectionContext, pack: Any) -> DimensionResult:  # pragma: no cover
        raise NotImplementedError

    # ---------------------------------------------------------------- 工具
    @staticmethod
    def threshold(pack: Any, key: str, default: float) -> float:
        """从规则包取阈值（缺项回退内置基线）。"""
        try:
            return float(pack.threshold(key, default))
        except Exception:
            return float(default)

    @staticmethod
    def gap(source: str, reason: str, impact: str = "downgrade",
            level_cap: str = "", suggestion: str = "") -> dict[str, str]:
        """构造一条降级说明（与 gaps 表字段对齐）。"""
        return {
            "scope": "dimension",
            "dimension": source,
            "source": source,
            "reason": reason,
            "impact": impact,
            "level_cap": level_cap,
            "suggestion": suggestion or f"补齐「{source}」相关证据后重跑该维度。",
        }


# ------------------------------------------------------------------ 汇总


def evaluate(ctx: DetectionContext, *, usage: str = "check",
             pack: Any = None, allow_direction: bool = False) -> Verdict:
    """
    跑全部五维并汇总成结论（FR-06）。

    Args:
        ctx: 检测上下文（提供按插件取记录的能力）
        usage: `check`（检查用法三档）/ `forensic`（取证用法三级）
        pack: 规则包；不传则取当前生效的
        allow_direction: 是否启用**访问方向维度**（FR-05）。
            ★ 方案 4.2.3(5) 要求该维度"权限必须单列，默认关闭，需单独授权开启"，
              关闭时该维**不出结论**且不影响其余四维。默认 False。

    Returns:
        Verdict：含各维结果、总分、等级、上限与降级说明
    """
    from memlens.dimensions import (            # 延迟导入避免循环
        access_direction,
        channel_config,
        data_egress,
        execution_trace,
        tool_presence,
    )

    pack = pack or rulepack.current()
    modules = {
        "tool_presence": tool_presence.ToolPresenceDimension(),
        "channel_config": channel_config.ChannelConfigDimension(),
        "execution_trace": execution_trace.ExecutionTraceDimension(),
        "data_egress": data_egress.DataEgressDimension(),
        "access_direction": access_direction.AccessDirectionDimension(
            enabled=allow_direction),
    }

    dims: list[DimensionResult] = []
    for name in DIMENSIONS:
        dim = modules[name]
        try:
            res = dim.run(ctx, pack)
        except Exception as exc:
            res = DimensionResult(
                dimension=name, state="degraded", level_cap="C",
                findings=[f"维度执行出错：{type(exc).__name__}: {exc}"],
                gaps=[dim.gap(name, f"维度执行出错：{exc}", "blocked", "C",
                             "该维度需人工复核；查看日志中该维度的异常栈。")],
            )
        dims.append(res)

    v = _score(dims, pack, usage=usage)
    v.rulepack_version = getattr(pack, "version", "")
    v.rulepack_sha256 = getattr(pack, "sha256", "")
    return v


def _score(dims: list[DimensionResult], pack: Any, *, usage: str) -> Verdict:
    """
    加权求和 + 定档（方案 4.2.4）。

    定档规则（方案原文）：
      * 加权总分 ≥ 0.75 **且** 外联维 ≥ 0.5 → 已确认
      * 总分 0.40 ~ 0.75 → 存在风险
      * < 0.40 → 记录备查
    外联维单独设下限，是为了防止"**四维痕迹齐全但从未传输**"被误定为已确认
    ——装而未用属于风险，不属于事实，两者的处置后果不同。

    取证用法的 A/B/C：**按独立来源数**定，而不是按总分
    （方案表 14：两个以上独立来源在同一时间窗内互证 → A 级）。
    """
    t_confirmed = float(pack.threshold("scoring.confirmed_total", 0.75))
    t_risk = float(pack.threshold("scoring.risk_total", 0.40))
    t_floor = float(pack.threshold("scoring.egress_floor", 0.50))
    a_src = int(pack.threshold("scoring.level_a_sources", 2))
    b_src = int(pack.threshold("scoring.level_b_sources", 1))

    total = 0.0
    for d in dims:
        if d.state == "disabled":
            # 该维未启用 → **不出结论、不参与总分**（方案 4.2.3(5)）
            continue
        w = pack.dimension_weight(d.dimension)
        total += float(d.score) * w

    egress = next((d for d in dims if d.dimension == "data_egress"), None)
    egress_score = egress.score if egress else 0.0

    # ---- 检查用法三档 ----
    if total >= t_confirmed and egress_score >= t_floor:
        tier = "confirmed"
    elif total >= t_risk:
        tier = "risk"
    else:
        tier = "record"

    # ---- 取证用法三级：按独立来源数 ----
    max_sources = max((d.independent_sources for d in dims), default=0)
    if max_sources >= a_src:
        level = "A"
    elif max_sources >= b_src:
        level = "B"
    else:
        level = "C"

    # ---- 等级上限：方案表 12「单机采集且未接入外部记录时，外联维上限 B，
    #      总分不得判为 A 级」----
    level_cap = "A"
    notes: list[str] = []
    # ★ 上限判定的依据是"**是否接入网络侧设备记录并完成三处交叉**"，
    #   而不是"外联维内部有多少个来源"——主机侧来源再多也只是主机侧，
    #   按方案 4.2.4 仍然封顶 B（实测踩过：用 independent_sources 判定会误放行 A 级）。
    external = any(d.external_cross_ok for d in dims)
    if not external:
        level_cap = "B"
        notes.append("单机采集且未接入外部网络侧记录：外联维封顶 B 级，总分不得判为 A 级。")
        if level == "A":
            level = "B"
            notes.append("因未接入外部记录，原 A 级判定下调为 B 级。")

    # ---- 汇总缺口 ----
    gaps: list[dict[str, str]] = []
    for d in dims:
        gaps.extend(d.gaps)

    v = Verdict(usage=usage, tier=tier, level=level, total=total,
                dimensions=dims, level_cap=level_cap, notes=notes, gaps=gaps)
    return v
