"""
MemLens · 代码注入检测（基于 malfind 的多源推理）

malfind 的原理：在进程 VAD（虚拟地址描述符）树里寻找"内存页被标记为可执行、
但不对应任何磁盘文件"的区域 —— 这是注入（shellcode / 反射式 DLL）的典型特征。

本检测器在 malfind 原始输出之上再加三层推理：
  1. **保护属性分级**：PAGE_EXECUTE_READWRITE（可写+可执行）比 PAGE_EXECUTE_READ 更可疑；
  2. **与模块范围比对**：若该地址落在任何已加载模块（dlllist）的区间之外，则"无文件后备"成立；
  3. **与网络/命令行关联**：同 PID 若有外联或可疑命令行，提升置信度。

所有参与判定的权重都会写进 evidence，便于复核与调参。
"""

from __future__ import annotations

import re
from typing import Any

from memlens.detectors.base import (
    Detection,
    DetectionContext,
    Detector,
    get_field,
    is_whitelisted,
    register,
    to_int,
    truncate,
)

# ★ v1.3：权重外置到规则包（方案 FR-21）。生效值来自 `rulepack.current()`。
from memlens.core import rulepack as _rulepack

W_MALFIND = 0.50             # malfind 命中（基础分）
W_RWX = 0.15                 # 页属性同时可写可执行
W_NO_MODULE = 0.12           # 地址不在任何已加载模块范围内
W_HAS_NETWORK = 0.08         # 该进程有网络连接
W_NON_WHITELIST_NAME = 0.05  # 进程名不在系统白名单
W_MZ_HEADER = 0.10           # 内容以 MZ/PE 头开始（说明是完整 PE 被注入）
W_WHITELIST_PENALTY = -0.15  # 命中白名单进程名 → 降分
CONF_MAX = 0.98


def _T(key: str, default: float) -> float:
    """从当前规则包取阈值（缺项回退内置基线）。"""
    try:
        return _rulepack.threshold(key, default)
    except Exception:
        return default

_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")


def _parse_hex(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    m = _HEX_RE.search(text)
    if m:
        try:
            return int(m.group(0), 16)
        except ValueError:
            return None
    try:
        return int(text, 16)
    except ValueError:
        return None


@register
class InjectionDetector(Detector):
    name = "code_injection"
    display = "代码注入检测"
    needs = ("%malfind%",)
    default_severity = "high"

    def run(self, ctx: DetectionContext) -> list[Detection]:
        malfind = ctx.records("%malfind%")

        # 收集每个 PID 的模块地址范围（用于判定"无文件后备"）
        module_ranges: dict[int, list[tuple[int, int]]] = {}
        for r in ctx.records("%dlllist%"):
            pid = to_int(get_field(r, "PID", "ProcessId"))
            base = _parse_hex(get_field(r, "Base", "BaseAddress", "Offset"))
            size = to_int(get_field(r, "Size", "ImageSize"))
            if pid is None or base is None:
                continue
            module_ranges.setdefault(pid, []).append((base, base + (size or 0x1000)))

        net_pids: set[int] = set()
        for r in ctx.records("%netscan%"):
            pid = to_int(get_field(r, "PID", "ProcessId"))
            if pid is not None:
                net_pids.add(pid)

        findings: list[Detection] = []

        for rec in malfind:
            pid = to_int(get_field(rec, "PID", "ProcessId"))
            if pid is None:
                continue
            process = str(get_field(rec, "Process", "ImageFileName", "Name", default="(未知)"))
            protection = str(get_field(rec, "Protection", "Protect", default="")).upper()
            start = _parse_hex(get_field(rec, "Start VPN", "StartVPN", "Start", "StartAddress"))
            end = _parse_hex(get_field(rec, "End VPN", "EndVPN", "End", "EndAddress"))
            tag = str(get_field(rec, "Tag", default=""))
            hexdump_snip = str(get_field(rec, "Hexdump", "Hex", default=""))
            disasm_snip = str(get_field(rec, "Disasm", "Disassembly", default=""))

            weights: dict[str, float] = {"malfind 判定为注入候选页": _T("injection.w_malfind", W_MALFIND)}
            conf = _T("injection.w_malfind", W_MALFIND)

            if "EXECUTE_READWRITE" in protection or "RWX" in protection:
                weights["页保护含可写+可执行（RWX）"] = _T("injection.w_rwx", W_RWX)
                conf += _T("injection.w_rwx", W_RWX)

            in_module = False
            if start is not None and pid in module_ranges:
                for lo, hi in module_ranges[pid]:
                    if lo <= start < hi:
                        in_module = True
                        break
            if start is not None and not in_module:
                weights["起始地址不属于任何已加载模块（无文件后备）"] = _T("injection.w_no_module", W_NO_MODULE)
                conf += _T("injection.w_no_module", W_NO_MODULE)

            if pid in net_pids:
                weights["该进程存在网络连接"] = _T("injection.w_has_network", W_HAS_NETWORK)
                conf += _T("injection.w_has_network", W_HAS_NETWORK)

            if not is_whitelisted(process):
                weights["进程名不在系统白名单"] = _T("injection.w_non_whitelist_name", W_NON_WHITELIST_NAME)
                conf += _T("injection.w_non_whitelist_name", W_NON_WHITELIST_NAME)
            else:
                weights["进程名命中系统白名单（降分）"] = _T("injection.w_whitelist_penalty", W_WHITELIST_PENALTY)
                conf += _T("injection.w_whitelist_penalty", W_WHITELIST_PENALTY)

            # 内容特征：MZ / PE 头
            head = (hexdump_snip or "").strip().lower()
            if head.startswith("4d 5a") or head.startswith("4d5a") or "mz" == head[:2]:
                weights["页内容以 MZ 头开始（疑似完整 PE 被注入）"] = _T("injection.w_mz_header", W_MZ_HEADER)
                conf += _T("injection.w_mz_header", W_MZ_HEADER)

            conf = max(0.05, min(conf, _T("injection.conf_max", CONF_MAX)))
            addr = f"0x{start:x}" if start is not None else "未知"
            det = Detection(
                title=f"疑似代码注入：{process}（PID {pid} @ {addr}）",
                description=(
                    "malfind 在该进程中发现「可执行但无磁盘文件后备」的内存页。"
                    "此类区域常用于 shellcode、反射式加载或进程镂空（hollowing）落地。"
                    "建议：导出该区域（dumpfile/memmap）后做静态分析，并结合外联行为判断是否为 C2。"
                ),
                confidence=conf,
                sources=["malfind", "dlllist", "netscan"],
                evidence={
                    "pid": pid,
                    "process": process,
                    "protection": truncate(protection, 80),
                    "start": addr,
                    "end": f"0x{end:x}" if end is not None else None,
                    "size": (end - start) if (start is not None and end is not None) else None,
                    "tag": truncate(tag, 32),
                    "weights": weights,
                    "disasm_snippet": truncate(disasm_snip.replace("\n", " | "), 300),
                },
            )
            det.severity = det.severity_from_confidence()
            findings.append(det)

        # 同一进程多个注入页：合并成一条更聚合的发现（降低噪音）
        merged: dict[int, Detection] = {}
        others: list[Detection] = []
        for d in findings:
            pid = d.evidence.get("pid")
            if pid in merged:
                keep = merged[pid]
                keep.evidence.setdefault("additional_regions", []).append(
                    {"start": d.evidence.get("start"), "size": d.evidence.get("size"),
                     "protection": d.evidence.get("protection")}
                )
                keep.confidence = min(CONF_MAX, keep.confidence + 0.03)
                keep.title = f"疑似代码注入：{keep.evidence.get('process')}（PID {pid}，共 " \
                             f"{1 + len(keep.evidence['additional_regions'])} 处可疑页）"
                keep.severity = keep.severity_from_confidence()
            else:
                merged[pid] = d
        others.extend(merged.values())
        return others
