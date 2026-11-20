"""
MemLens · 隐藏进程检测（多源交叉验证）

方法论（这是本工具相对"单插件输出"的核心增量）：
  1. **差集**：池扫描（psscan）能看到已被摘链的 EPROCESS，而活动链表遍历（pslist）看不到；
     因此 `psscan - pslist` 是隐藏进程的第一手候选集。
  2. **反向差集**：`pslist - psscan` 说明链表被破坏/伪造（同样可疑）。
  3. **多源加权**：候选进程若同时出现在网络连接（netscan 的 PID/Owner）、
     或 psxview 也标记、或进程名不在系统白名单，则提高置信度。
  4. **误报控制**：psscan 独有的进程也可能只是"刚退出但内存未回收"，因此默认置信度中等，
     并在描述里明确说明这一点——宁可让分析师复核，也不制造噪音。

置信度由可解释的加权规则给出（每条权重都写进 evidence，便于复核与调参）。
"""

from __future__ import annotations

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

# ★ v1.3：权重表**外置到规则包**（方案 FR-21：阈值不写在代码里，业务侧可调、可版本化）。
#   这里的常量只作"内置基线"，实际生效值来自 `rulepack.current()`。
#   改名规则：常量名保留为兼容别名，检测器内部一律走 `_T("...")` 取当前规则包的值。
from memlens.core import rulepack as _rulepack

# 权重表基线（内置默认值；生效值以规则包为准）
W_POOL_ONLY = 0.55          # 仅池扫描命中（基础分）
W_NOT_IN_LIST = 0.10        # 活动链表里完全没有
W_HAS_NETWORK = 0.12        # 有网络连接
W_NON_WHITELIST_NAME = 0.08 # 名字不在系统白名单
W_PSXVIEW_FLAG = 0.10       # psxview 也把它标为可疑
W_EMPTY_CMDLINE = 0.05      # 命令行拿不到（常见于被篡改/伪装）
W_ORPHAN_PPID = 0.05        # 父进程不存在（孤儿进程）
W_WHITELIST_PENALTY = -0.20 # 命中白名单（名字像系统进程）→ 降分
CONF_MAX = 0.98
#: 差异进程数超过此值 → 合并为一条（避免把采集偏差当成几十个伪造进程）
ORPHAN_MERGE_THRESHOLD = 5


def _T(key: str, default: float) -> float:
    """从当前规则包取阈值（缺项回退内置基线）。"""
    try:
        return _rulepack.threshold(key, default)
    except Exception:
        return default


@register
class HiddenProcessDetector(Detector):
    name = "hidden_process"
    display = "隐藏进程检测"
    needs = ("%psscan%",)
    default_severity = "high"

    def run(self, ctx: DetectionContext) -> list[Detection]:
        scanned = ctx.records("%psscan%")
        listed = ctx.records("%pslist%")

        def index(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
            out: dict[int, dict[str, Any]] = {}
            for r in rows:
                pid = to_int(get_field(r, "PID", "ProcessId"))
                if pid is None:
                    continue
                out.setdefault(pid, r)
            return out

        scan_idx, list_idx = index(scanned), index(listed)

        # 网络连接里的 PID 集合（用于加权）
        net_pids: set[int] = set()
        for r in ctx.records("%netscan%"):
            pid = to_int(get_field(r, "PID", "ProcessId"))
            if pid is not None:
                net_pids.add(pid)

        # psxview 里被标记为"未出现在某来源"的 PID（psxview 输出列名随版本变化，做宽松匹配）
        psx_flag_pids: set[int] = set()
        for r in ctx.records("%psxview%"):
            pid = to_int(get_field(r, "PID", "ProcessId"))
            if pid is None:
                continue
            values = " ".join(str(v).lower() for v in r.values())
            if "false" in values or "missing" in values:
                psx_flag_pids.add(pid)

        # 命令行可得性（拿不到命令行是弱信号）
        cmdline_pids: set[int] = set()
        for r in ctx.records("%cmdline%"):
            pid = to_int(get_field(r, "PID", "ProcessId"))
            if pid is not None:
                cmdline_pids.add(pid)

        findings: list[Detection] = []

        # ---------------- 第一类：在 psscan 却不在 pslist ----------------
        for pid, rec in sorted(scan_idx.items()):
            if pid in list_idx:
                continue
            name = str(get_field(rec, "ImageFileName", "Name", "Owner", default="(未知)"))
            ppid = to_int(get_field(rec, "PPID", "ParentPID"))
            create_time = str(get_field(rec, "CreateTime", "Created", default=""))

            weights: dict[str, float] = {"池扫描命中而活动链表缺失（psscan−pslist）": W_POOL_ONLY}
            conf = _T("hidden_process.w_pool_only", W_POOL_ONLY)

            if pid not in list_idx:
                weights["活动进程链表中不存在"] = _T("hidden_process.w_not_in_list", W_NOT_IN_LIST)
                conf += _T("hidden_process.w_not_in_list", W_NOT_IN_LIST)
            if pid in net_pids:
                weights["存在关联的网络连接"] = _T("hidden_process.w_has_network", W_HAS_NETWORK)
                conf += _T("hidden_process.w_has_network", W_HAS_NETWORK)
            if not is_whitelisted(name):
                weights["进程名不在系统白名单"] = _T("hidden_process.w_non_whitelist_name", W_NON_WHITELIST_NAME)
                conf += _T("hidden_process.w_non_whitelist_name", W_NON_WHITELIST_NAME)
            else:
                weights["进程名命中系统白名单（降分）"] = _T("hidden_process.w_whitelist_penalty", W_WHITELIST_PENALTY)
                conf += _T("hidden_process.w_whitelist_penalty", W_WHITELIST_PENALTY)
            if pid in psx_flag_pids:
                weights["psxview 亦标记异常"] = _T("hidden_process.w_psxview_flag", W_PSXVIEW_FLAG)
                conf += _T("hidden_process.w_psxview_flag", W_PSXVIEW_FLAG)
            if pid not in cmdline_pids:
                weights["无法获取命令行"] = _T("hidden_process.w_empty_cmdline", W_EMPTY_CMDLINE)
                conf += _T("hidden_process.w_empty_cmdline", W_EMPTY_CMDLINE)
            if ppid is not None and ppid not in scan_idx and ppid not in list_idx and ppid != 0:
                weights["父进程在两种来源里都不存在（孤儿进程）"] = _T("hidden_process.w_orphan_ppid", W_ORPHAN_PPID)
                conf += _T("hidden_process.w_orphan_ppid", W_ORPHAN_PPID)

            conf = max(0.05, min(conf, _T("hidden_process.conf_max", CONF_MAX)))
            det = Detection(
                title=f"疑似隐藏进程：{name}（PID {pid}）",
                description=(
                    "该进程结构体存在于内存池中，但未出现在活动进程链表遍历结果里，"
                    "符合「进程被摘链隐藏」的特征。注意：也可能是刚退出、内存尚未回收的进程残留，"
                    "请结合命令行、网络连接与时间线复核。"
                ),
                confidence=conf,
                sources=["psscan"] + (["pslist"] if listed else []) + (["netscan"] if net_pids else []) + (["psxview"] if psx_flag_pids else []),
                evidence={
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "create_time": truncate(create_time, 64),
                    "weights": weights,
                    "record": {k: truncate(v, 120) for k, v in list(rec.items())[:20]},
                },
            )
            det.severity = det.severity_from_confidence()
            findings.append(det)

        # ---------------- 第二类：在 pslist 却不在 psscan ----------------
        # 说明：正常系统里绝不该出现（活动链表里的进程，池扫描必然也能扫到），
        # 出现即说明链表被伪造或池扫描被干扰，属于强信号。
        #
        # ⚠ 但这里必须先做"数据可用性"判断（这是实测踩到的坑）：
        # 曾出现 `psscan` 记录在检测时不可见（产物/记录尚未可读）的情况，
        # 于是 35 个正常系统进程被逐个报成"仅出现于活动链表"，发现项页直接变成
        # 34 条 HIGH 噪声（真正隐藏的 AntSword.exe 反而被埋掉）。
        # 因此：**一边为空、另一边非空**时，只报一条"无法交叉验证"的提示，绝不逐个报。
        if listed and not scanned:
            return [Detection(
                title=f"无法交叉验证：psscan 无有效进程记录（pslist 有 {len(list_idx)} 条）",
                description=(
                    "隐藏进程判定依赖两个独立来源：活动链表遍历（pslist）与内存池扫描（psscan）。"
                    "本次池扫描没有可取用的记录，因此**不做任何隐藏进程结论**——"
                    "逐一比对会把这几十个正常系统进程全部误报成异常。\n"
                    "请确认 windows.psscan 插件成功产出后重新检测。"
                ),
                confidence=0.9,
                sources=["pslist", "psscan"],
                evidence={"pslist_count": len(list_idx), "psscan_count": len(scan_idx)},
            )]

        if listed:
            orphans: list[tuple[int, str]] = []
            for pid, rec in sorted(list_idx.items()):
                if pid in scan_idx:
                    continue
                name = str(get_field(rec, "ImageFileName", "Name", default="(未知)"))
                orphans.append((pid, name))

            if len(orphans) <= int(_T("hidden_process.orphan_threshold", ORPHAN_MERGE_THRESHOLD)):
                for pid, name in orphans:
                    conf = 0.75 + (0.10 if not is_whitelisted(name) else -0.15)
                    conf = max(0.05, min(conf, _T("hidden_process.conf_max", CONF_MAX)))
                    det = Detection(
                        title=f"进程链表异常：{name}（PID {pid}）仅出现于活动链表",
                        description=(
                            "该进程出现在活动进程链表中，却无法被内存池扫描命中。"
                            "正常情况下两者必然同时命中，因此这是**链表伪造或扫描被干扰**的强信号。"
                        ),
                        confidence=conf,
                        sources=["pslist", "psscan"],
                        evidence={"pid": pid, "name": name,
                                  "record": {k: truncate(v, 120) for k, v in list(rec.items())[:20]}},
                    )
                    det.severity = det.severity_from_confidence()
                    findings.append(det)
            elif orphans:
                # 数量过多 → 大概率是池扫描/链表遍历本身有偏差，合并成一条并如实说明
                non_wl = [(p, n) for p, n in orphans if not is_whitelisted(n)]
                findings.append(Detection(
                    title=f"进程链表与池扫描差异过大：{len(orphans)} 个进程仅出现于活动链表"
                          f"（其中 {len(non_wl)} 个非系统进程）",
                    description=(
                        "两个来源的进程集合差异超过 5 个，这更像**采集/解析偏差**而不是"
                        "几十个进程同时被伪造。已合并为一条以便复核：下方列出全部差异进程，"
                        "请优先关注其中名字不像系统进程的那几个。"
                    ),
                    confidence=0.5,
                    sources=["pslist", "psscan"],
                    evidence={"count": len(orphans),
                              "non_whitelist": [{"pid": p, "name": n} for p, n in non_wl][:40],
                              "all": [{"pid": p, "name": n} for p, n in orphans][:80],
                              "debug": {
                                  "scanned_rows": len(scanned),
                                  "pslist_rows": len(listed),
                                  "scan_index": len(scan_idx),
                                  "list_index": len(list_idx),
                                  "scan_pids_sample": sorted(scan_idx)[:12],
                                  "list_pids_sample": sorted(list_idx)[:12],
                              }},
                ))

        return findings
