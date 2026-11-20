r"""
MemLens · 轻量系统状态采集（供 UI 底部状态栏使用）

## 为什么不引 psutil

本工具是**断网离线**交付的（`offline-check` 实测 0 次出网），
多引一个第三方依赖就要多一份打包体积与供应链面。
状态栏只要两三个数，直接用 Win32 API 就够：

    GetSystemTimes        → 系统 CPU 占用率（空闲/内核/用户 三段时间差）
    GlobalMemoryStatusEx  → 物理内存总量 / 可用量
    GetProcessMemoryInfo  → 本进程工作集（看取证引擎吃多少内存）

非 Windows 平台自动降级：CPU 返回 None，内存读 /proc/meminfo。

## 为什么 CPU 要用"两次采样做差"

Win32 给的是**累计时间**（自开机以来的 tick 数），不是瞬时占用率。
所以必须保存上一次采样值再算差值——首次调用没有基准，返回 None，
下一次调用才有值（UI 侧轮询即可，第一次显示"—"是正常的）。
"""

from __future__ import annotations

import ctypes
import os
import sys
import time
from ctypes import wintypes
from typing import Any

IS_WINDOWS = sys.platform.startswith("win")

#: 上一次的 CPU 采样（累计 tick）
_prev: dict[str, int] = {}

#: 上次取到的进程工作集（MB）
_last_self_mb: float | None = None


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD),
                ("dwHighDateTime", wintypes.DWORD)]


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def _ft(v: _FILETIME) -> int:
    """FILETIME → 64 位整数（单位 100 ns）。"""
    return (v.dwHighDateTime << 32) | v.dwLowDateTime


def _system_cpu_percent() -> float | None:
    """系统 CPU 占用率（需要两次采样）。"""
    if not IS_WINDOWS:
        return None
    try:
        idle, kernel, user = _FILETIME(), _FILETIME(), _FILETIME()
        ok = ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))
        if not ok:
            return None
        cur = {"idle": _ft(idle), "kernel": _ft(kernel), "user": _ft(user)}
    except (AttributeError, OSError):
        return None

    prev = _prev.get("v")
    _prev["v"] = cur  # type: ignore[assignment]
    if not prev:
        return None

    d_idle = cur["idle"] - prev["idle"]          # type: ignore[index]
    d_kernel = cur["kernel"] - prev["kernel"]    # type: ignore[index]
    d_user = cur["user"] - prev["user"]          # type: ignore[index]
    # 注意：kernel 时间**已包含** idle 时间，所以总时间是 kernel+user
    total = d_kernel + d_user
    if total <= 0:
        return None
    busy = total - d_idle
    pct = max(0.0, min(100.0, busy * 100.0 / total))
    return round(pct, 1)


def _memory() -> dict[str, float] | None:
    """物理内存总量 / 已用（MB）。"""
    if IS_WINDOWS:
        try:
            st = _MEMORYSTATUSEX()
            st.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return None
            total = st.ullTotalPhys / 1024 / 1024
            avail = st.ullAvailPhys / 1024 / 1024
            return {"total_mb": round(total, 0), "used_mb": round(total - avail, 0),
                    "percent": round((total - avail) * 100.0 / total, 1) if total else 0.0}
        except (AttributeError, OSError):
            return None
    # 非 Windows：读 /proc/meminfo
    try:
        info: dict[str, int] = {}
        with open("/proc/meminfo", encoding="ascii", errors="ignore") as f:
            for line in f:
                k, _, v = line.partition(":")
                info[k.strip()] = int(v.strip().split()[0])
        total = info.get("MemTotal", 0) / 1024
        avail = info.get("MemAvailable", 0) / 1024
        if not total:
            return None
        return {"total_mb": round(total, 0), "used_mb": round(total - avail, 0),
                "percent": round((total - avail) * 100.0 / total, 1)}
    except (OSError, ValueError):
        return None


def self_rss_mb() -> float | None:
    """本进程工作集（MB）——看取证引擎吃了多少内存，便于解释资源告警。"""
    global _last_self_mb
    if IS_WINDOWS:
        try:
            k32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi
            # ★ 必须显式声明 restype/argtypes：
            #   ctypes 默认把返回值当 c_int，64 位下 HANDLE 会被**截断成 32 位**，
            #   传回去必然调用失败（实测踩过：self_mb 恒为 null）。
            k32.GetCurrentProcess.restype = wintypes.HANDLE
            k32.GetCurrentProcess.argtypes = []
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(_PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD,
            ]
            h = k32.GetCurrentProcess()
            pmc = _PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
            if psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                _last_self_mb = round(pmc.WorkingSetSize / 1024 / 1024, 1)
                return _last_self_mb
        except (AttributeError, OSError):
            pass
    try:
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        _last_self_mb = round(rss / 1024, 1)      # Linux 单位 KB
        return _last_self_mb
    except Exception:
        return _last_self_mb


def snapshot() -> dict[str, Any]:
    """一次完整采样，供 `/api/sysstat` 直接返回。"""
    mem = _memory()
    return {
        "cpu_percent": _system_cpu_percent(),
        "mem": mem,
        "self_mb": self_rss_mb(),
        "load1": (lambda: (os.getloadavg()[0] if hasattr(os, "getloadavg") else None))(),
        "uptime_s": round(time.monotonic() - _START, 1),
        "pid": os.getpid(),
        "platform": sys.platform,
    }


_START = time.monotonic()
