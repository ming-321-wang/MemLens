# -*- coding: utf-8 -*-
"""
MemLens · 浏览器历史分析报告（境外 IP 访问识别 + 风险分级，单独输出）

把 `browser_history.collect()` 得到的访问记录，逐条做 URL / 境外 IP / 风险分析，
输出一份**独立报告**，包含：
  · 风险分布（高/中/低）；
  · 境外（疑似）地址访问清单（含 URL、IP、归属、风险等级、时间、浏览器）；
  · 按浏览器 / 按域名聚合；
  · 可导出 JSON / CSV / Markdown / HTML。

境外识别依赖 `url_analyze`（离线中国网段判定）。域名 URL 默认**不联网**：
只有 `resolve=True` 才做 DNS 解析；也可以用 `ip_map={域名: IP}` 从流量/抓包
（pcap 产物）提供精确的 域名↔IP 映射，避免误判。
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from memlens.core import url_analyze
from memlens.core.browser_history import Visit


@dataclass
class ReportItem:
    browser: str
    profile: str
    url: str
    title: str
    visited_at: str
    host: str = ""
    ip: str = ""
    country: str = ""
    region: str = ""
    risk: str = "低"
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        d = {
            "browser": self.browser, "profile": self.profile, "url": self.url,
            "title": self.title, "visited_at": self.visited_at,
            "host": self.host, "ip": self.ip, "country": self.country,
            "region": self.region, "risk": self.risk, "reasons": list(self.reasons),
        }
        return d


def build_report(visits: Iterable[Visit], *, ip_map: Mapping[str, str] | None = None,
                 resolve: bool = False) -> dict[str, Any]:
    """
    把访问记录变成结构化报告。

    ip_map：{域名: IP}（可从 pcap/流量提取，精确境外识别）。
    resolve：是否联网做 DNS 解析（默认 False，离线）。
    """
    ip_map = ip_map or {}
    items: list[ReportItem] = []
    for v in visits:
        # 提取 host（无 scheme 的 URL 补 "//" 才能解析出 host）
        pu = url_analyze.urlparse(v.url if "://" in v.url else "//" + v.url)
        host = (pu.hostname or "").lower()
        info = url_analyze.analyze_url(v.url, resolve=resolve,
                                       ip_hint=ip_map.get(host, ""))
        items.append(ReportItem(
            browser=v.browser, profile=v.profile, url=v.url, title=v.title,
            visited_at=v.visited_at, host=info.host, ip=info.ip,
            country=info.country, region=info.region, risk=info.risk,
            reasons=info.reasons,
        ))

    stats = url_analyze.risk_stats(items)
    by_risk = {"高": 0, "中": 0, "低": 0, "待解析": 0}
    overseas: list[dict[str, Any]] = []
    by_browser: dict[str, int] = {}
    for it in items:
        by_risk[it.risk] = by_risk.get(it.risk, 0) + 1
        by_browser[it.browser] = by_browser.get(it.browser, 0) + 1
        if it.country == "境外（疑似）" or it.risk == "高":
            overseas.append(it.as_dict())

    return {
        "summary": {
            "total": len(items),
            "by_risk": by_risk,
            "overseas_count": len(overseas),
            "by_browser": by_browser,
            "ip_map_loaded": len(ip_map),
        },
        "overseas_access": overseas,
        "items": [it.as_dict() for it in items],
    }


def export_json(report: dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def export_csv(report: dict[str, Any], path: str) -> int:
    items = report.get("items", [])
    if not items:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write("browser,profile,url,title,visited_at,host,ip,country,risk,reasons\n")
        return 0
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(items[0].keys()))
        w.writeheader()
        w.writerows(items)
    return len(items)


def export_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    out = io.StringIO()
    out.write("# MemLens 浏览器历史分析报告\n\n")
    out.write(f"- 总访问：**{s['total']:,}** 条\n")
    out.write(f"- 风险分布：高 {s['by_risk']['高']} / 中 {s['by_risk']['中']} / "
              f"低 {s['by_risk']['低']} / 待解析 {s['by_risk']['待解析']}\n")
    out.write(f"- 境外（疑似）访问：**{s['overseas_count']}** 条\n")
    out.write(f"- 按浏览器：{' / '.join(f'{k} {v}' for k, v in s['by_browser'].items())}\n\n")

    if s["overseas_count"]:
        out.write("## 境外（疑似）地址访问\n\n")
        out.write("| 时间 | 浏览器 | 域名 | IP | 归属 | 风险 | 原因 |\n")
        out.write("|---|---|---|---|---|---|---|\n")
        for it in report["overseas_access"]:
            out.write(f"| {it['visited_at']} | {it['browser']} | {it['host']} | "
                      f"{it['ip']} | {it['country']} | {it['risk']} | "
                      f"{'；'.join(it['reasons'][:4])} |\n")
        out.write("\n")

    out.write("## 全量访问（按风险降序）\n\n")
    order = {"高": 0, "中": 1, "低": 2, "待解析": 3}
    rows = sorted(report["items"], key=lambda x: order.get(x["risk"], 9))
    for it in rows[:200]:
        out.write(f"- [{it['risk']}] {it['visited_at']} {it['browser']} "
                  f"{(it['title'] or '')[:30]} <{it['url'][:90]}>\n")
    return out.getvalue()
