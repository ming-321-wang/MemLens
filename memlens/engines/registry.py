"""
MemLens · 引擎注册表

把"有哪些引擎可用"变成数据而不是 if-else。新增一个取证域（事件日志 / 注册表 / 流量包…）
只需实现一个 EngineAdapter 并注册进来，UI 与调度层零改动。
"""

from __future__ import annotations

from typing import Callable, Iterator

from memlens.engines.base import EngineAdapter

# (引擎类, 是否默认启用)
_REGISTRY: dict[str, type[EngineAdapter]] = {}
_INSTANCES: dict[str, EngineAdapter] = {}


def register(cls: type[EngineAdapter]) -> type[EngineAdapter]:
    """类装饰器：注册一个引擎适配器。"""
    _REGISTRY[cls.name] = cls
    return cls


def get(name: str, **kwargs) -> EngineAdapter:
    """按名字取引擎实例（首次调用时按需构造并缓存）。"""
    if name in _INSTANCES:
        return _INSTANCES[name]
    if name not in _REGISTRY:
        raise KeyError(f"未注册的引擎：{name}（已注册：{sorted(_REGISTRY)}）")
    inst = _REGISTRY[name](**kwargs)
    _INSTANCES[name] = inst
    return inst


def installed() -> list[str]:
    """已注册的引擎名。"""
    return sorted(_REGISTRY)


def iter_available() -> Iterator[tuple[EngineAdapter, bool, str]]:
    """逐个引擎做自检，产出 (实例, 可用?, 说明)。"""
    for name in installed():
        try:
            engine = get(name)
            ok, why = engine.available()
        except Exception as exc:  # 自检本身出错也不能让程序崩
            engine, ok, why = None, False, f"自检异常：{exc}"
        yield engine, ok, why


def _bootstrap() -> None:
    """导入内置引擎模块以触发注册（延迟导入，避免可选依赖缺失时整体失败）。"""
    from memlens.engines import vol3 as _vol3  # noqa: F401
    from memlens.engines import static as _static  # noqa: F401
    from memlens.engines import memstrings as _memstrings  # noqa: F401
    from memlens.engines import memprocfs as _memprocfs  # noqa: F401
    from memlens.engines import container as _container  # noqa: F401

    register(_vol3.Volatility3Adapter)
    register(_static.StaticEngine)
    register(_memstrings.MemStringsEngine)
    register(_memprocfs.MemProcFSAdapter)
    register(_container.ContainerEngine)


_bootstrap()
