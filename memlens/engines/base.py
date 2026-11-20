"""
MemLens · 引擎适配层（抽象）

设计目标：把"异构的外部取证引擎"统一成同一套接口，使上层（任务调度 / 证据入库 / UI）
完全不需要知道底下跑的是 Volatility3、dissect 还是别的什么。

四个不可动摇的约定（这些是从同类工具的工程教训里总结出来的）：
  1. **插件清单必须运行时枚举**，不许在代码里硬编码几十个插件名（上游一升级就全废）；
  2. **命令必须参数化**（列表形式、shell=False），绝不拼接字符串交给 shell；
  3. **结果必须结构化**（JSON/JSONL），不允许靠解析人类可读的表格来取数；
  4. **执行必须可取消、有超时、有进度**，且失败信息要向上抛，不许静默返回空。
"""

from __future__ import annotations

import dataclasses
import enum
from abc import ABC, abstractmethod
from typing import Any, Iterator, Sequence


class OutputKind(str, enum.Enum):
    """插件产出的形态，决定上层如何入库与展示。"""

    TABLE = "table"          # 多行多列（进程/网络/句柄…）→ 入 records 表
    TEXT = "text"            # 纯文本（info/banners/字符串）→ 存产物文件
    FILE_SET = "file_set"    # 落盘的二进制产物（dump/memmap）→ 只登记产物
    SCALAR = "scalar"        # 键值对（系统信息）→ 入 records（key/value 两列）

    @property
    def is_tabular(self) -> bool:
        return self in (OutputKind.TABLE, OutputKind.SCALAR)


@dataclasses.dataclass(frozen=True)
class PluginMeta:
    """一个可执行插件的元信息（由引擎在运行时枚举得到）。"""

    name: str                       # 引擎内部标识，如 "windows.pslist.PsList"
    display: str                    # 展示名（中文优先）
    category: str                   # 分组，如 "进程" / "网络" / "恶意代码"
    kind: OutputKind = OutputKind.TABLE
    description: str = ""
    needs_params: tuple[str, ...] = ()   # 需要用户额外填的参数（如 pid）

    @property
    def key(self) -> str:
        """稳定键：用于缓存、去重、与规则绑定。"""
        return self.name


@dataclasses.dataclass
class RunSpec:
    """一次执行的完整描述（由适配器产出，交给任务执行器）。"""

    plugin: PluginMeta
    argv: list[str]                  # 已参数化的命令行（不含 shell 解释）
    cwd: str | None = None
    env: dict[str, str] | None = None
    timeout: float | None = None     # 秒；None 表示不限制
    output_kind: OutputKind = OutputKind.TABLE

    def pretty(self) -> str:
        return " ".join(f'"{a}"' if " " in a else a for a in self.argv)


@dataclasses.dataclass
class RunOutcome:
    """一次执行的结果。"""

    spec: RunSpec
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    cancelled: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.cancelled and self.error is None


class EngineUnavailable(RuntimeError):
    """引擎不可用（未安装 / 环境不满足）。"""


class EngineAdapter(ABC):
    """
    引擎适配器基类。

    子类至少要实现：available / list_plugins / build_run / parse_records。
    """

    #: 引擎标识（小写，用于数据库与配置）
    name: str = "engine"
    #: 展示名
    display: str = "Engine"
    #: 支持的容器/系统适用范围说明（供 UI 提示）
    supported_containers: tuple[str, ...] = ()

    # ---------------------------------------------------------------- 环境
    @abstractmethod
    def available(self) -> tuple[bool, str]:
        """
        自检：这个引擎现在能用吗？

        Returns:
            (是否可用, 说明)。不可用时说明里给出原因与修复建议。
        """
        raise NotImplementedError

    # ---------------------------------------------------------------- 插件
    @abstractmethod
    def list_plugins(self, *, refresh: bool = False) -> list[PluginMeta]:
        """
        运行时枚举插件清单。

        Args:
            refresh: 忽略本地缓存，强制重新枚举。
        """
        raise NotImplementedError

    # ---------------------------------------------------------------- 执行
    @abstractmethod
    def build_run(self, plugin: PluginMeta, image: str, params: dict[str, Any] | None = None) -> RunSpec:
        """把插件 + 镜像 + 参数组装成可执行描述。"""
        raise NotImplementedError

    @abstractmethod
    def parse_records(self, spec: RunSpec, stdout: str, stderr: str) -> Iterator[dict[str, Any]]:
        """
        把引擎输出解析成"记录"（每行一个 dict）。

        约定：解析失败要抛异常，**不要**返回空迭代器来假装"没有结果"。
        """
        raise NotImplementedError

    # ---------------------------------------------------------------- 辅助
    def search_plugins(self, keyword: str, plugins: Sequence[PluginMeta] | None = None) -> list[PluginMeta]:
        """按关键词过滤插件（名称 / 展示名 / 分组，忽略大小写，空格分隔为 AND）。"""
        pool = list(plugins) if plugins is not None else self.list_plugins()
        terms = [t for t in keyword.lower().split() if t]
        if not terms:
            return pool
        out = []
        for p in pool:
            hay = f"{p.name} {p.display} {p.category} {p.description}".lower()
            if all(t in hay for t in terms):
                out.append(p)
        return out


def describe_engine(engine: EngineAdapter) -> str:
    """引擎自检结果的可读渲染。"""
    ok, why = engine.available()
    mark = "✅" if ok else "❌"
    return f"{mark} {engine.display}（{engine.name}）：{why}"
