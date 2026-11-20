"""
MemLens · 五维判定引擎（违规跨境访问检测模块）

对应方案《计算机系统数字取证工作台开发方案》4.2 节。

    tool_presence    FR-01 工具存在性判定
    channel_config   FR-02 通道配置核查
    execution_trace  FR-03 运行痕迹核验
    data_egress      FR-04 数据外联证实
    access_direction FR-05 访问方向界定（权限默认关闭）
    base             框架 + 打分分级（FR-06）+ 结论输出（FR-07）
"""

from memlens.dimensions.base import (
    CHECK_TIERS,
    DIMENSION_FR,
    DIMENSION_LABEL,
    DIMENSIONS,
    FORENSIC_LEVELS,
    Dimension,
    DimensionResult,
    Verdict,
    evaluate,
)

__all__ = [
    "DIMENSIONS", "DIMENSION_FR", "DIMENSION_LABEL",
    "CHECK_TIERS", "FORENSIC_LEVELS",
    "Dimension", "DimensionResult", "Verdict", "evaluate",
]
