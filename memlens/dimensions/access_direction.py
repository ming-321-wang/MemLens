r"""
MemLens · 维度五：访问方向界定（FR-05）

对应方案 4.2.3(5)。

## 只采集域名与时间（方案原文）

> 该维度**只采集域名与时间，涉及内容的字段一律不取**。
> 判定方法是**域名分类而非简单二分**：按学术、技术、新闻、社交、流媒体五类打标，
> 不同类别在打分时权重不同，避免"**访问境外即违规**"的粗暴判断
> ——访问境外学术数据库与访问境外流媒体，在合规判断上不是一回事。

## 权限必须单列（方案原文）

> 该维度涉及使用人偏好，**权限必须单列，默认关闭，需单独授权开启**，
> 且授权按案件、按期失效。**关闭时该维不出结论，报告标注"未启用"，
> 不影响其余四维的判定与出证。**
> 这条设计不是保守，而是让"能不能查"由制度决定，不由操作员决定。

⇒ 本模块实现 `enabled` 开关：默认 **关闭**，
调用方必须显式传 `allow_direction=True` 才产出结论；
关闭时该维返回 `state="disabled"` 且**不出结论**（不参与总分）。

## 合规通道白名单（方案 4.2.3(4)）

> 全部维度共用的白名单为**合规通道清单**：经批准的国际专线、境外分支机构、
> 国际学术数据库、云服务接口、境外软件更新节点。
> 清单按**域名与地址段双重匹配**，由网络管理方每季度复核一次。

⇒ 词表与白名单都在**规则包**里，业务侧维护，改规则不发版。
"""

from __future__ import annotations

from typing import Any

from memlens.dimensions.base import Dimension, DimensionResult
from memlens.detectors.base import get_field

#: 五类的相对权重（方案：不同类别在打分时权重不同）
CATEGORY_WEIGHT: dict[str, float] = {
    "academic": 0.30,      # 学术：合规判断上最接近"正常业务"
    "technical": 0.70,     # 技术：开发/运维场景常见
    "news": 0.90,          # 新闻：灰色
    "social": 1.00,        # 社交：与管理行为无直接关系，权重最高
    "streaming": 1.00,     # 流媒体：权重最高
    "other": 0.60,         # 未分类
}


class AccessDirectionDimension(Dimension):
    """FR-05 访问方向界定（默认关闭，需单独授权）。"""

    dimension = "access_direction"
    sources = ("mprocfs.netdns%", "mprocfs.browser_history%")
    level_cap = "A"

    def __init__(self, *, enabled: bool = False) -> None:
        #: 方案 4.2.3(5)：权限默认关闭
        self.enabled = bool(enabled)

    def run(self, ctx, pack) -> DimensionResult:
        res = DimensionResult(dimension=self.dimension, level_cap=self.level_cap)

        if not self.enabled:
            # 方案：关闭时该维**不出结论**，报告标注"未启用"，不影响其余四维
            res.state = "disabled"
            res.score = 0.0
            res.independent_sources = 0
            res.findings.append("访问方向维度**未启用**（按权限要求默认关闭）"
                                "——该维不出结论，不影响其余四维判定。")
            res.gaps.append(self.gap(
                "访问方向维度", "维度未启用（权限默认关闭，需单独授权）",
                impact="none", level_cap="",
                suggestion="如案件需要该维结论，由审核人员单独授权后开启。"))
            return res

        used, missing = self.available_sources(ctx)
        res.sources_used = used
        res.sources_missing = missing

        # ---- 采集域名（只采域名与时间，不采任何内容字段）----
        domains: dict[str, int] = {}
        times: dict[str, str] = {}
        for r in ctx.records("mprocfs.netdns%", limit=20000):
            host = str(get_field(r, "Host", "Name", "Answer", default="") or "").strip().lower()
            if not host:
                continue
            domains[host] = domains.get(host, 0) + 1
            t = str(get_field(r, "Time", default="") or "")
            if t and host not in times:
                times[host] = t
        for r in ctx.records("mprocfs.browser_history%", limit=20000):
            url = str(get_field(r, "URL", "url", default="") or "")
            if not url:
                continue
            host = url.split("//")[-1].split("/")[0].split(":")[0].lower()
            if not host:
                continue
            domains[host] = domains.get(host, 0) + 1
            t = str(get_field(r, "访问时间", "visited_at", default="") or "")
            if t and host not in times:
                times[host] = t

        if not domains:
            res.state = "not_found"
            res.score = 0.0
            res.findings.append("未采集到任何域名（该维无对象）")
            return res

        # ---- 分类打标 ----
        cats = pack.wordlist_get("domain_category") or {}
        compliant = [str(x).lower() for x in (pack.wordlist_get("compliant_channel") or [])]

        # 域名 → 类别（按词表匹配，命中父域也算）
        def _classify(host: str) -> str:
            for cat, pats in (cats or {}).items():
                for pat in pats or []:
                    pat = str(pat).lower()
                    if host == pat or host.endswith("." + pat) or pat in host:
                        return str(cat)
            return "other"

        by_cat: dict[str, list[tuple[str, int]]] = {}
        classified: list[dict[str, Any]] = []
        compliant_hits = 0
        for host, n in domains.items():
            cat = _classify(host)
            by_cat.setdefault(cat, []).append((host, n))
            is_compliant = any(c and (host == c or host.endswith("." + c) or c in host)
                               for c in compliant)
            if is_compliant:
                compliant_hits += 1
            classified.append({"host": host, "count": n, "category": cat,
                               "compliant": is_compliant,
                               "time": times.get(host, "")})

        # ---- 评分：按类别加权 ----
        total_weight = 0.0
        total_n = 0
        for cat, items in by_cat.items():
            w = CATEGORY_WEIGHT.get(cat, CATEGORY_WEIGHT["other"])
            for _h, n in items:
                total_weight += w * n
                total_n += n
        score = (total_weight / total_n) if total_n else 0.0

        # 合规通道命中的域名不计入"方向"分（方案：白名单排除）
        if compliant_hits and total_n:
            kept = total_n - compliant_hits
            if kept > 0:
                score = min(score, (total_weight - compliant_hits * CATEGORY_WEIGHT["other"]) / kept)

        res.score = max(0.0, min(1.0, score))
        res.independent_sources = 1 if domains else 0
        res.state = "established" if res.score >= 0.3 else "not_found"

        res.findings.append(
            f"域名分类：共 {len(domains)} 个域名 / {total_n} 条记录，"
            f"按学术·技术·新闻·社交·流媒体五类打标")
        for cat in sorted(by_cat, key=lambda c: -len(by_cat[c])):
            items = sorted(by_cat[cat], key=lambda kv: -kv[1])[:5]
            res.findings.append(
                f"  {cat}（权重 {CATEGORY_WEIGHT.get(cat, 0.6):.2f}）："
                + "、".join(f"{h}×{n}" for h, n in items))
        if compliant_hits:
            res.findings.append(f"合规通道白名单命中 {compliant_hits} 个域名，已按方案排除")
        for c in classified[:15]:
            res.evidence_refs.append(f"domain:{c['host']}:{c['category']}")

        if not compliant:
            res.gaps.append(self.gap(
                "合规通道清单", "规则包未配置合规通道白名单，无法排除批准的跨境业务",
                impact="downgrade", level_cap="B",
                suggestion="由网络管理方在规则包中维护合规通道清单（域名与地址段双重匹配，"
                           "每季度复核一次）。"))
        return res
