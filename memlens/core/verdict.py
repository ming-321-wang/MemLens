"""
MemLens · 结论引擎（一页纸回答"这份内存镜像说明了什么"）

## 为什么要有它

内存取证工具最常见的体验问题：**结果散落在七八个页签里**（进程表 / 网络 / 发现项 /
旗标 / 时间线 / 情报），用户要自己拼出结论。本模块把散落证据**聚合成一页**：

    一句话结论 → flag 候选 → 关键事实 → 重点发现 → 下一步建议

判定原则（沿用本项目一贯口径）：
* **flag 优先置顶**：有明文 flag 就先给 flag，再给其它结论；
* **结论必须带证据**：每条发现项都带来源插件与置信度，不做无出处的断言；
* **建议要可执行**：下一步是具体命令/动作（如"dump PID 3192 的内存再扫字符串"），
  而不是"建议进一步调查"这种废话；
* **没有发现就说没有**：不硬凑结论（空结论也是有价值的结论：说明"没查到"而不是"没看"）。
"""

from __future__ import annotations

import json
from typing import Any

from memlens.core.flagbank import collect as collect_flags


def _fmt_bytes(n: Any) -> str:
    try:
        v = float(n)
    except (TypeError, ValueError):
        return "—"
    for u in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or u == "TB":
            return f"{v:,.1f} {u}"
        v /= 1024
    return f"{v:.1f} TB"


def _case_facts(store: Any, case_id: str) -> dict[str, Any]:
    """案件基础信息（从库里取，缺就空）。"""
    case = store.get_case(case_id) or {}
    stats = store.stats(case_id) or {}
    return {
        "case_id": case_id,
        "image_path": case.get("image_path", ""),
        "image_size": case.get("image_size"),
        "container": case.get("container", ""),
        "os_type": case.get("os_type", ""),
        "os_confidence": case.get("os_confidence"),
        "created_at": case.get("created_at", ""),
        "artifacts": stats.get("artifacts", 0),
        "records": stats.get("records", 0),
        "findings": stats.get("findings", 0),
        "findings_by_severity": stats.get("findings_by_severity", {}) or {},
    }


def _counts(store: Any, case_id: str) -> dict[str, int]:
    """几个关键产物各有多少行（进程/网络/异常/环境变量…）。"""
    out: dict[str, int] = {}
    for key, pat in (
        ("进程", "mprocfs.process%"),
        ("网络连接", "mprocfs.net%"),
        ("异常内存", "mprocfs.findevil%"),
        ("环境变量", "mprocfs.envs%"),
        ("命令行", "mprocfs.cmdlines%"),
        ("服务", "mprocfs.services%"),
        ("时间线", "mprocfs.timeline%"),
    ):
        try:
            out[key] = len(store.records_of_plugin(case_id, pat, limit=200_000))
        except Exception:
            out[key] = 0
    return out


def _next_steps(store: Any, case_id: str, facts: dict[str, Any],
                flags: list[dict[str, Any]]) -> list[str]:
    """按当前证据给出**具体可执行**的下一步。"""
    steps: list[str] = []
    counts = facts.get("counts", {})
    sev = facts.get("findings_by_severity", {}) or {}

    if flags:
        v = flags[0].get("value", "")
        steps.append(f"已捕获旗标候选 **{v}** —— 复制后即可提交；"
                     f"若不确定真伪，先用 `records {case_id} --plugin flag` 看上下文。")

    high = int(sev.get("high", 0) or 0) + int(sev.get("critical", 0) or 0)
    if high:
        steps.append(f"有 {high} 条高危发现项：先看「发现项」页按 severity=critical/high 过滤，"
                     f"逐条核对证据里的 PID/路径，再决定要不要 dump 对应进程内存。")

    # 有可疑进程 → 建议 dump
    try:
        proc = store.records_of_plugin(case_id, "mprocfs.process%", limit=5000)
    except Exception:
        proc = []
    suspicious: list[str] = []
    for rec in proc:
        title = str(rec.get("CommandLine") or "")
        path = str(rec.get("UserPath") or "")
        name = str(rec.get("Name") or "")
        low = f"{name} {title} {path}".lower()
        if any(k in low for k in ("antsword", "behinder", "mimikatz", "vault",
                                  "personalvault", "procdump", "hack")):
            pid = str(rec.get("PID") or "")
            if pid and pid not in suspicious:
                suspicious.append(pid)
    if suspicious:
        steps.append(
            "导出可疑进程内存再挖字符串（flag 常在进程堆里，不在文件元数据里）："
            + "；".join(
                f"`analyze <镜像> --engine memprocfs --plugins mprocfs.dump_process "
                f"--param pid={p}`" for p in suspicious[:3]))

    if counts.get("环境变量", 0):
        steps.append("环境变量里常藏凭据：在「产物」页选 `mprocfs.envs` 搜 "
                     "`flag`/`password`/`secret`/`token`。")

    if counts.get("异常内存", 0):
        steps.append(f"`findevil` 命中 {counts['异常内存']} 条：High Entropy / Private RWX "
                     "通常意味着注入或加壳，优先看 PID 与模块路径。")

    if not counts.get("进程"):
        steps.append("没有进程表数据：可能是**内核转储**（只含部分物理内存）。"
                     "建议补一份完整内存镜像，或改用 `--engine memprocfs` 的虚拟盘取证。")

    if not steps:
        steps.append("暂无高危结论。建议：① 跑「深度分析」；② 在「产物」页翻进程/网络表；"
                     "③ 用「情报」页的 IOC/词典匹配补充线索。")
    return steps


def build(store: Any, case_id: str, *, flag_limit: int = 8) -> dict[str, Any]:
    """
    生成一页纸结论。

    Returns:
        {
          "headline": "一句话结论",
          "flags": [ {value, kind, sources, offset_hex} ],
          "key_facts": [ {k, v} ],
          "top_findings": [ {severity, title, confidence, detector, sources, evidence} ],
          "next_steps": [ "..." ],
          "counts": { "进程": 143, ... },
        }
    """
    facts = _case_facts(store, case_id)
    counts = _counts(store, case_id)
    facts["counts"] = counts

    # ---- 发现项 ----
    try:
        findings = store.list_findings(case_id)
    except Exception:
        findings = []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda f: (order.get(str(f.get("severity")), 5),
                                               -float(f.get("confidence") or 0)))
    top = [{
        "severity": f.get("severity", "info"),
        "title": f.get("title", ""),
        "confidence": round(float(f.get("confidence") or 0), 3),
        "detector": f.get("detector", ""),
        "sources": f.get("sources") or [],
        "evidence": f.get("evidence") or {},
        "description": f.get("description", ""),
    } for f in findings[:8]]

    # ---- flag 候选 ----
    try:
        flags = collect_flags(store, case_id, limit=flag_limit, include_loose=False)
    except Exception:
        flags = []
    flags = [{"value": f.get("value", ""), "kind": f.get("kind", ""),
              "sources": f.get("sources") or [], "offset_hex": f.get("offset_hex", ""),
              "count": f.get("count", 1)} for f in flags]

    # ---- 一句话结论 ----
    sev = facts.get("findings_by_severity", {}) or {}
    high = int(sev.get("critical", 0) or 0) + int(sev.get("high", 0) or 0)
    if flags and flags[0].get("kind") == "明文":
        headline = f"★ 捕获明文旗标 {flags[0]['value']}；另有 {high} 条高危发现项。"
    elif flags:
        headline = (f"捕获 {len(flags)} 个旗标候选（最高 {flags[0]['value']}）；"
                    f"另有 {high} 条高危发现项。")
    elif high:
        headline = f"未发现明文旗标，但有 {high} 条高危发现项需确认。"
    else:
        headline = ("未发现旗标，也没有高危发现项——"
                    f"已分析 {facts.get('records', 0):,} 条记录 / "
                    f"{facts.get('artifacts', 0)} 个产物。")

    key_facts = [
        {"k": "证据文件", "v": facts.get("image_path", "")},
        {"k": "大小 / 容器", "v": f"{_fmt_bytes(facts.get('image_size'))} / {facts.get('container') or '—'}"},
        {"k": "操作系统", "v": f"{facts.get('os_type') or '—'}"},
        {"k": "产物 / 记录", "v": f"{facts.get('artifacts', 0)} 个 / {facts.get('records', 0):,} 条"},
        {"k": "进程 / 网络连接", "v": f"{counts.get('进程', 0)} / {counts.get('网络连接', 0)}"},
        {"k": "异常内存命中", "v": str(counts.get("异常内存", 0))},
        {"k": "发现项", "v": " / ".join(f"{k}:{v}" for k, v in sev.items()) or "0"},
    ]

    return {
        "case_id": case_id,
        "headline": headline,
        "flags": flags,
        "key_facts": key_facts,
        "top_findings": top,
        "next_steps": _next_steps(store, case_id, facts, flags),
        "counts": counts,
    }


def to_markdown(v: dict[str, Any]) -> str:
    """把结论渲染成 Markdown（可直接贴进报告/工单）。"""
    out: list[str] = ["# MemLens 结论速览", "", f"**{v.get('headline', '')}**", ""]
    flags = v.get("flags") or []
    if flags:
        out += ["## 旗标候选", ""]
        for f in flags:
            src = "、".join(f.get("sources") or [])
            out.append(f"- `{f.get('value','')}`  [{f.get('kind','')}]"
                       f"{'  来源：' + src if src else ''}"
                       f"{'  偏移：' + f.get('offset_hex','') if f.get('offset_hex') else ''}")
        out.append("")
    if v.get("key_facts"):
        out += ["## 关键事实", ""]
        for r in v["key_facts"]:
            out.append(f"- **{r.get('k','')}**：{r.get('v','')}")
        out.append("")
    if v.get("top_findings"):
        out += ["## 重点发现", ""]
        for f in v["top_findings"]:
            out.append(f"- [{str(f.get('severity','')).upper()}] "
                       f"{f.get('title','')}（置信度 {int(float(f.get('confidence') or 0)*100)}%）"
                       f"{'  来源：' + '、'.join(f.get('sources') or []) if f.get('sources') else ''}")
        out.append("")
    if v.get("next_steps"):
        out += ["## 下一步建议", ""]
        for s in v["next_steps"]:
            out.append(f"1. {s}")
        out.append("")
    return "\n".join(out)


def to_text(v: dict[str, Any]) -> str:
    """终端友好的纯文本结论。"""
    out: list[str] = []
    out.append("=" * 72)
    out.append("MemLens · 结论速览")
    out.append("=" * 72)
    out.append(v.get("headline", ""))
    flags = v.get("flags") or []
    if flags:
        out.append("")
        out.append("【旗标候选】")
        for f in flags:
            out.append(f"  {f.get('value','')}   [{f.get('kind','')}]"
                       f"{'  偏移 ' + f.get('offset_hex','') if f.get('offset_hex') else ''}")
    if v.get("key_facts"):
        out.append("")
        out.append("【关键事实】")
        for r in v["key_facts"]:
            out.append(f"  {r.get('k',''):<16} {r.get('v','')}")
    if v.get("top_findings"):
        out.append("")
        out.append("【重点发现】")
        for f in v["top_findings"]:
            out.append(f"  [{str(f.get('severity','')).upper():^8}] "
                       f"{int(float(f.get('confidence') or 0)*100):>3}%  {f.get('title','')}")
    if v.get("next_steps"):
        out.append("")
        out.append("【下一步建议】")
        for i, s in enumerate(v.get("next_steps") or [], 1):
            out.append(f"  {i}. {s}")
    out.append("=" * 72)
    return "\n".join(out)


def to_json(v: dict[str, Any]) -> str:
    return json.dumps(v, ensure_ascii=False, indent=2, default=str)
