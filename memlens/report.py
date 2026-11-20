r"""
MemLens · 报告生成

把一个案件里的证据、发现项、情报、时间线汇总成**可直接交付**的报告。

输出两种格式：
    Markdown —— 便于贴进工单/知识库/版本管理，可 diff
    HTML     —— 自包含单文件（内联样式），可直接打印成 PDF 或截图提交

报告与原始数据是"同源"的：所有数字都从 SQLite 现取，
因此报告永远与证据一致，不存在"手抄错了"的可能。
"""

from __future__ import annotations

import datetime as _dt
import html
import os
from typing import Any, Sequence

from memlens import timeline as tl
from memlens.intel import builtin, knowledge
from memlens.storage.db import DataStore

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}


# ------------------------------------------------------------------ 取数


def _collect(store: DataStore, case_id: str) -> dict[str, Any]:
    case = store.get_case(case_id) or {}
    artifacts = store.list_artifacts(case_id)
    findings = store.list_findings(case_id)
    rows = store.records_with_source(case_id, skip_plugins=("intel.",))

    ioc_rows = store.records_of_plugin(case_id, "intel.ioc", limit=5000)
    dict_rows: list[dict[str, Any]] = []
    for did in builtin.all_ids():
        dict_rows.extend(store.records_of_plugin(case_id, f"intel.dict.{did}", limit=2000))

    events = tl.build_timeline(rows, limit=5000)
    kb_hits = knowledge.kb().match_artifacts(artifacts)
    # ★ v1.3：缺口清单（方案表 9）与规则包版本（方案 1.5：报告须写明版本号）
    try:
        gaps = store.list_gaps(case_id)
    except Exception:
        gaps = []
    try:
        from memlens.core import rulepack as _rp
        rp_summary = _rp.summary()
    except Exception:
        rp_summary = {}
    return {
        "case": case, "artifacts": artifacts, "findings": findings,
        "rows": rows, "ioc": ioc_rows, "dict": dict_rows,
        "events": events, "knowledge": kb_hits,
        "stats": store.stats(case_id),
        "gaps": gaps, "rulepack": rp_summary,
    }


def _failed(artifacts: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [a for a in artifacts if a.get("status") in ("failed", "cancelled", "partial")]


def _public_iocs(ioc_rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in ioc_rows if r.get("ioc_type") == "ipv4" and r.get("scope") == "公网"]


def _high_dict(dict_rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in dict_rows if str(r.get("severity")) in ("high", "critical")]


# ------------------------------------------------------------------ Markdown


def build_markdown(store: DataStore, case_id: str, *, max_timeline: int = 120,
                   include_knowledge: bool = True) -> str:
    d = _collect(store, case_id)
    case = d["case"]
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    L: list[str] = []

    L.append(f"# 内存取证分析报告 · {case.get('name') or case_id}")
    L.append("")
    L.append(f"> 由 MemLens 自动生成于 {now}")
    L.append("")

    # ---- 一、基本信息 ----
    L.append("## 一、案件基本信息")
    L.append("")
    L.append("| 项 | 值 |")
    L.append("|---|---|")
    rows = [
        ("案件 ID", case_id),
        ("名称", case.get("name", "")),
        ("证据文件", f"`{case.get('image_path','')}`"),
        ("文件大小", f"{int(case.get('image_size') or 0):,} 字节"),
        ("SHA-256", f"`{case.get('image_sha256') or '—'}`"),
        ("容器类型", case.get("container", "")),
        ("操作系统", f"{case.get('os_type','')}（置信度 {case.get('os_confidence') or 0}）"),
        ("建案时间", case.get("created_at", "")),
        ("产物数 / 记录数 / 发现项", f"{d['stats']['artifacts']} / {d['stats']['records']} / {d['stats']['findings']}"),
        ("**规则包版本**", f"{d['rulepack'].get('version', '—')}（发布 {d['rulepack'].get('published_at', '—')}，"
                          f"SHA-256 `{str(d['rulepack'].get('sha256', ''))[:16]}`）"),
        ("**时间基准**", "协调世界时（UTC）存储；报告按记录的原时区偏移还原本地时间"),
    ]
    for k, v in rows:
        L.append(f"| {k} | {v} |")
    L.append("")

    # ---- 二、发现项 ----
    L.append("## 二、发现项")
    L.append("")
    findings = sorted(d["findings"], key=lambda f: (SEV_ORDER.get(f.get("severity", "info"), 9),
                                                  -float(f.get("confidence") or 0)))
    if not findings:
        L.append("_本次分析未产生发现项。_")
    else:
        L.append("| 严重度 | 置信度 | 标题 | 说明 |")
        L.append("|---|---|---|---|")
        for f in findings:
            sev = str(f.get("severity") or "info")
            L.append("| {sev} | {conf:.0%} | {title} | {desc} |".format(
                sev=SEV_LABEL.get(sev, sev),
                conf=float(f.get("confidence") or 0),
                title=_md(f.get("title", "")),
                desc=_md(f.get("description", ""))[:200],
            ))
        L.append("")
        for f in findings[:12]:
            L.append(f"### {_md(f.get('title',''))}")
            L.append("")
            L.append(f"- **严重度**：{SEV_LABEL.get(str(f.get('severity')), f.get('severity'))}")
            L.append(f"- **置信度**：{float(f.get('confidence') or 0):.0%}")
            if f.get("sources"):
                L.append(f"- **证据源**：{', '.join(f.get('sources') or [])}")
            if f.get("description"):
                L.append(f"- **说明**：{f.get('description')}")
            L.append("")
    L.append("")

    # ---- 三、情报 ----
    L.append("## 三、情报指标（IOC）")
    L.append("")
    ioc = d["ioc"]
    if not ioc:
        L.append("_未提取到 IOC（可运行情报扫描）。_")
    else:
        by_kind: dict[str, list[dict[str, Any]]] = {}
        for r in ioc:
            by_kind.setdefault(str(r.get("ioc_type")), []).append(r)
        L.append("| 类型 | 数量 | 示例 |")
        L.append("|---|---|---|")
        for kind, items in sorted(by_kind.items(), key=lambda kv: -len(kv[1])):
            sample = ", ".join(f"`{i.get('value')}`" for i in items[:3])
            L.append(f"| {kind} | {len(items)} | {sample} |")
        L.append("")
        pub = _public_iocs(ioc)
        if pub:
            L.append("**公网 IP（优先核查出网行为）**")
            L.append("")
            L.append("| IP | 出现次数 | 来源插件 |")
            L.append("|---|---|---|")
            for r in pub[:60]:
                L.append(f"| `{r.get('value')}` | {r.get('count')} | {r.get('sources','')} |")
            L.append("")
    L.append("")

    # ---- 四、词典命中 ----
    L.append("## 四、词典命中")
    L.append("")
    high = _high_dict(d["dict"])
    if not high:
        L.append("_无高危及以上命中。_")
    else:
        L.append("| 词典 | 条目 | 命中值 | 次数 | 处置建议 |")
        L.append("|---|---|---|---|---|")
        for r in high[:80]:
            L.append("| {dict} | {entry} | `{val}` | {n} | {advice} |".format(
                dict=_md(r.get("dict", "")), entry=_md(r.get("entry", "")),
                val=_md(str(r.get("match", ""))[:80]), n=r.get("count", ""),
                advice=_md(r.get("advice") or r.get("note") or "")))
    L.append("")

    # ---- 五、时间线 ----
    L.append("## 五、事件时间线")
    L.append("")
    L.append(tl.to_markdown(d["events"], max_rows=max_timeline))
    L.append("")

    # ---- 六、知识 ----
    if include_knowledge and d["knowledge"]:
        L.append("## 六、相关取证要点")
        L.append("")
        L.append("> 以下条目依据本次实际运行的插件自动匹配，用于提示下一步核查方向。")
        L.append("")
        for entry, _kw in d["knowledge"]:
            L.append(f"**{entry.title}**")
            L.append("")
            L.append(f"- 征象：{entry.symptom}")
            L.append(f"- 结论：{entry.meaning}")
            if entry.next:
                L.append("- 下一步：" + "；".join(entry.next))
            if entry.caveat:
                L.append(f"- 注意：{entry.caveat}")
            L.append("")

    # ---- 七、缺口清单（方案 FR-07 的必备件）----
    L.append("## 七、缺口清单")
    L.append("")
    gaps = d.get("gaps") or []
    if not gaps:
        L.append("_本次分析未记录数据源缺口（所有计划内产物均已执行）。_")
    else:
        L.append("| 范围 | 维度/数据源 | 缺失原因 | 影响 | 结论上限 | 建议补证 |")
        L.append("|---|---|---|---|---|---|")
        for g in gaps[:120]:
            L.append("| {scope} | {dim} | {reason} | {impact} | {cap} | {sug} |".format(
                scope=_md(g.get("scope", "")),
                dim=_md(g.get("dimension", "") or g.get("source", "")),
                reason=_md(str(g.get("reason", ""))[:160]),
                impact=_md(g.get("impact", "")),
                cap=_md(g.get("level_cap", "") or "—"),
                sug=_md(str(g.get("suggestion", ""))[:160]),
            ))
        L.append("")
        L.append("> 缺口不是「已排除」。上表中的每一项都意味着**相应结论缺乏证据支撑**，"
                 "须按「建议补证」补齐后方可提高结论强度。")
    L.append("")

    # ---- 八、执行情况与局限 ----
    L.append("## 八、执行情况与局限")
    L.append("")
    ok = sum(1 for a in d["artifacts"] if a.get("status") == "ok")
    L.append(f"- 共执行 {len(d['artifacts'])} 项，成功 {ok} 项，异常 {len(_failed(d['artifacts']))} 项。")
    bad = _failed(d["artifacts"])
    if bad:
        L.append("")
        L.append("| 引擎 | 插件 | 状态 | 说明 |")
        L.append("|---|---|---|---|")
        for a in bad[:40]:
            L.append(f"| {a.get('engine')} | `{a.get('plugin')}` | {a.get('status')} | {_md(str(a.get('error') or ''))[:160]} |")
        L.append("")
        L.append("> 上表中的失败项意味着**相应结论缺乏证据支撑**，请勿当作「已排除」。")
    L.append("")
    L.append("### 复现信息")
    L.append("")
    L.append("每个产物的原始命令行都完整留存在数据库 `artifacts.argv_json`，原始输出落盘于 `work/artifacts/` 且记录了 SHA-256，可逐条复现与校验。")
    L.append("")
    if d["rulepack"].get("change_log"):
        L.append("### 所用规则包")
        L.append("")
        L.append(f"- 版本：{d['rulepack'].get('version')}　发布日期：{d['rulepack'].get('published_at')}")
        L.append(f"- SHA-256：`{d['rulepack'].get('sha256')}`")
        L.append(f"- 变更记录：{d['rulepack'].get('change_log')}")
        L.append("")

    # ---- 固定免责表述（方案 5.7：三条写入每份报告，不得删改）----
    L.append("### 免责与证明边界")
    L.append("")
    L.append("1. 主机侧未发现痕迹，不等于未使用；路由级或虚拟机内代理不可见。")
    L.append("2. 单机采集的结论等级存在上限，上限已在前文标注。")
    L.append("3. 本报告不建议作为司法鉴定结论使用，如需鉴定请另行委托具备资质的机构。")
    L.append("")
    return "\n".join(L)


def _md(s: Any) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", " ")


# ------------------------------------------------------------------ HTML


_HTML_CSS = """
:root{--fg:#1c1e21;--mut:#6b7280;--bd:#e5e7eb;--bg:#fff;--crit:#b91c1c;--high:#c2410c;
--med:#a16207;--low:#2563eb;--info:#4b5563}
*{box-sizing:border-box}
body{font:14px/1.7 "Segoe UI","Microsoft YaHei",system-ui,sans-serif;color:var(--fg);
background:#f6f7f9;margin:0;padding:32px}
.page{max-width:1080px;margin:0 auto;background:var(--bg);padding:40px 44px;
border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:25px;margin:0 0 6px;border-bottom:3px solid var(--fg);padding-bottom:12px}
h2{font-size:18px;margin:34px 0 12px;padding-left:10px;border-left:4px solid var(--fg)}
h3{font-size:15px;margin:20px 0 8px}
table{width:100%;border-collapse:collapse;margin:10px 0 18px;font-size:13px}
th,td{border:1px solid var(--bd);padding:7px 10px;text-align:left;vertical-align:top}
th{background:#f3f4f6;font-weight:600}
tr:nth-child(even) td{background:#fafafa}
code,.mono{font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;
background:#f3f4f6;padding:1px 5px;border-radius:3px;word-break:break-all}
.tag{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:12px}
.critical{background:var(--crit)} .high{background:var(--high)}
.medium{background:var(--med)} .low{background:var(--low)} .info{background:var(--info)}
.muted{color:var(--mut)} .note{background:#fffbeb;border-left:4px solid #f59e0b;
padding:10px 14px;margin:12px 0;border-radius:0 6px 6px 0}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--bd);
color:var(--mut);font-size:12px}
@media print{body{background:#fff;padding:0}.page{box-shadow:none;padding:0}}
"""


def build_html(store: DataStore, case_id: str, *, max_timeline: int = 120,
               include_knowledge: bool = True) -> str:
    d = _collect(store, case_id)
    case = d["case"]
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    e = html.escape

    findings = sorted(d["findings"], key=lambda f: (SEV_ORDER.get(f.get("severity", "info"), 9),
                                                  -float(f.get("confidence") or 0)))
    rp = d.get("rulepack") or {}
    rows = [
        ("案件 ID", case_id), ("名称", case.get("name", "")),
        ("证据文件", case.get("image_path", "")),
        ("大小", f"{int(case.get('image_size') or 0):,} 字节"),
        ("SHA-256", case.get("image_sha256") or "—"),
        ("容器 / 系统", f"{case.get('container','')} / {case.get('os_type','')}"),
        ("规则包版本", f"{rp.get('version','—')}（发布 {rp.get('published_at','—')}，"
                      f"SHA-256 {str(rp.get('sha256',''))[:16]}）"),
        ("时间基准", "协调世界时（UTC）存储；按记录的原时区偏移还原本地时间"),
    ]

    parts: list[str] = [
        "<!DOCTYPE html><html lang='zh-CN'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>内存取证分析报告 · {e(str(case.get('name') or case_id))}</title>",
        f"<style>{_HTML_CSS}</style></head><body><div class='page'>",
        f"<h1>内存取证分析报告 · {e(str(case.get('name') or case_id))}</h1>",
        f"<p class='muted'>由 MemLens 自动生成于 {e(now)}</p>",
        "<h2>一、案件基本信息</h2><table>",
        "".join(f"<tr><th style='width:180px'>{e(k)}</th><td><code>{e(str(v))}</code></td></tr>"
                for k, v in rows),
    ]

    # 发现项
    parts.append("<h2>二、发现项</h2>")
    if not findings:
        parts.append("<p class='muted'>本次分析未产生发现项。</p>")
    else:
        parts.append("<table><tr><th>严重度</th><th>置信度</th><th>标题</th><th>说明</th></tr>")
        for f in findings:
            sev = str(f.get("severity") or "info")
            parts.append(
                f"<tr><td><span class='tag {e(sev)}'>{e(SEV_LABEL.get(sev, sev))}</span></td>"
                f"<td>{float(f.get('confidence') or 0):.0%}</td>"
                f"<td>{e(str(f.get('title','')))}</td>"
                f"<td class='muted'>{e(str(f.get('description',''))[:300])}</td></tr>")
        parts.append("</table>")

    # IOC
    parts.append("<h2>三、情报指标（IOC）</h2>")
    ioc = d["ioc"]
    if not ioc:
        parts.append("<p class='muted'>未提取到 IOC。</p>")
    else:
        by_kind: dict[str, int] = {}
        for r in ioc:
            k = str(r.get("ioc_type"))
            by_kind[k] = by_kind.get(k, 0) + 1
        parts.append("<table><tr><th>类型</th><th>数量</th><th>示例</th></tr>")
        for kind, n in sorted(by_kind.items(), key=lambda kv: -kv[1]):
            sample = ", ".join(f"<code>{e(str(r.get('value')))}</code>"
                               for r in ioc if str(r.get("ioc_type")) == kind)[:400]
            parts.append(f"<tr><td>{e(kind)}</td><td>{n}</td><td>{sample}</td></tr>")
        parts.append("</table>")
        pub = _public_iocs(ioc)
        if pub:
            parts.append("<p><b>公网 IP（优先核查）</b></p><table>"
                         "<tr><th>IP</th><th>次数</th><th>来源</th></tr>")
            for r in pub[:60]:
                parts.append(f"<tr><td><code>{e(str(r.get('value')))}</code></td>"
                             f"<td>{r.get('count')}</td>"
                             f"<td class='muted'>{e(str(r.get('sources',''))[:200])}</td></tr>")
            parts.append("</table>")

    # 词典
    parts.append("<h2>四、词典命中（高危及以上）</h2>")
    high = _high_dict(d["dict"])
    if not high:
        parts.append("<p class='muted'>无高危及以上命中。</p>")
    else:
        parts.append("<table><tr><th>词典</th><th>条目</th><th>命中值</th><th>次数</th><th>建议</th></tr>")
        for r in high[:80]:
            parts.append(
                f"<tr><td>{e(str(r.get('dict','')))}</td><td>{e(str(r.get('entry','')))}</td>"
                f"<td><code>{e(str(r.get('match',''))[:80])}</code></td>"
                f"<td>{r.get('count')}</td>"
                f"<td class='muted'>{e(str(r.get('advice') or r.get('note') or ''))}</td></tr>")
        parts.append("</table>")

    # 时间线
    parts.append("<h2>五、事件时间线</h2>")
    if d["events"]:
        parts.append("<table><tr><th style='width:170px'>时间(UTC)</th><th style='width:170px'>本地时间</th>"
                     "<th style='width:200px'>来源</th><th>事件</th></tr>")
        for ev in d["events"][:max_timeline]:
            t = ev.ts_utc or (ev.raw_time or "—")
            loc = ev.to_local() or "—"
            parts.append(f"<tr><td class='mono'>{e(t)}</td>"
                         f"<td class='mono muted'>{e(loc)}</td>"
                         f"<td class='mono muted'>{e(ev.source_plugin)}</td>"
                         f"<td>{e(ev.title[:200])}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p class='muted'>未提取到带时间戳的记录。</p>")

    # 知识
    if include_knowledge and d["knowledge"]:
        parts.append("<h2>六、相关取证要点</h2>")
        for entry, _kw in d["knowledge"]:
            parts.append(f"<h3>{e(entry.title)}</h3>")
            parts.append(f"<p><b>征象：</b>{e(entry.symptom)}</p>")
            parts.append(f"<p><b>结论：</b>{e(entry.meaning)}</p>")
            if entry.next:
                parts.append("<ul>" + "".join(f"<li>{e(n)}</li>" for n in entry.next) + "</ul>")
            if entry.caveat:
                parts.append(f"<div class='note'>{e(entry.caveat)}</div>")

    # 缺口清单（方案 FR-07 必备件）
    parts.append("<h2>七、缺口清单</h2>")
    gaps = d.get("gaps") or []
    if not gaps:
        parts.append("<p class='muted'>本次分析未记录数据源缺口。</p>")
    else:
        parts.append("<div class='note'>缺口不是『已排除』——每一项都意味着相应结论"
                     "<strong>缺乏证据支撑</strong>，须按建议补证后方可提高结论强度。</div>")
        parts.append("<table><tr><th>范围</th><th>维度/数据源</th><th>缺失原因</th>"
                     "<th>影响</th><th>上限</th><th>建议补证</th></tr>")
        for g in gaps[:120]:
            parts.append(
                f"<tr><td>{e(str(g.get('scope','')))}</td>"
                f"<td class='mono'>{e(str(g.get('dimension') or g.get('source') or ''))}</td>"
                f"<td class='muted'>{e(str(g.get('reason',''))[:200])}</td>"
                f"<td>{e(str(g.get('impact','')))}</td>"
                f"<td>{e(str(g.get('level_cap') or '—'))}</td>"
                f"<td class='muted'>{e(str(g.get('suggestion',''))[:200])}</td></tr>")
        parts.append("</table>")

    # 局限
    ok = sum(1 for a in d["artifacts"] if a.get("status") == "ok")
    bad = _failed(d["artifacts"])
    parts.append("<h2>八、执行情况与局限</h2>")
    parts.append(f"<p>共执行 {len(d['artifacts'])} 项，成功 {ok} 项，异常 {len(bad)} 项。</p>")
    if bad:
        parts.append("<div class='note'>下列失败项意味着相应结论<strong>缺乏证据支撑</strong>，"
                     "不能理解为『已排除』。</div>")
        parts.append("<table><tr><th>引擎</th><th>插件</th><th>状态</th><th>说明</th></tr>")
        for a in bad[:40]:
            parts.append(f"<tr><td>{e(str(a.get('engine')))}</td>"
                         f"<td class='mono'>{e(str(a.get('plugin')))}</td>"
                         f"<td>{e(str(a.get('status')))}</td>"
                         f"<td class='muted'>{e(str(a.get('error') or '')[:300])}</td></tr>")
        parts.append("</table>")

    if rp.get("change_log"):
        parts.append(f"<p class='muted'><b>所用规则包：</b>{e(str(rp.get('version')))}"
                     f"（发布 {e(str(rp.get('published_at')))}）　"
                     f"变更记录：{e(str(rp.get('change_log'))[:300])}</p>")
    parts.append(
        "<footer>每个产物的原始命令行留存于数据库 <code>artifacts.argv_json</code>，"
        "原始输出落盘并记录 SHA-256，可逐条复现与校验。<br><br>"
        "<b>免责与证明边界</b><br>"
        "1. 主机侧未发现痕迹，不等于未使用；路由级或虚拟机内代理不可见。<br>"
        "2. 单机采集的结论等级存在上限，上限已在前文标注。<br>"
        "3. 本报告不建议作为司法鉴定结论使用，如需鉴定请另行委托具备资质的机构。"
        "</footer>")
    parts.append("</div></body></html>")
    return "".join(parts)


# ------------------------------------------------------------------ 导出


def export(store: DataStore, case_id: str, out_path: str, *, fmt: str = "html",
           **kw: Any) -> str:
    """
    生成报告文件。

    Args:
        fmt: md / markdown / html
    Returns: 写入的路径
    """
    ext = str(fmt).lower()
    if ext in ("md", "markdown"):
        text = build_markdown(store, case_id, **kw)
    elif ext in ("html", "htm"):
        text = build_html(store, case_id, **kw)
    else:
        raise ValueError(f"不支持的报告格式：{fmt}（可用：md / html）")
    path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fp:
        fp.write(text)
    return path
