# -*- coding: utf-8 -*-
"""
MemLens · URL / 境外 IP 分析

把浏览器历史/流量里的 URL 解析成结构化信息，并做**境外 IP 识别 + 风险分级**：

  · 境外识别：IP 不在内置中国网段（且非私有/保留）→ 判为"境外（疑似）"。
    内置一份**精简中国网段**（教育网 + 主要运营商核心段），离线可用；
    可用 `set_cn_networks()` 传入更完整的中国网段文件覆盖（精确升级）。
  · 风险分级（高/中/低）：
      高 —— 境外 IP 直连 / 暗网 .onion / 已知可疑 TLD / 明显恶意关键词；
      中 —— 境外 IP（域名解析）、非 HTTPS、可疑免费 TLD；
      低 —— 境内 + HTTPS + 正常域名。

纯本地、不联网（除非显式 `resolve=True` 做 DNS 解析）。
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlparse, unquote

# ----------------------------------------------------------------------
# 内置精简中国 IPv4 网段（离线兜底；**保守**——只放确定的中国段，
# 未命中公有 IP 判"境外（疑似）"，宁可多标境外也不漏掉境外风险）。
# 覆盖：CERNET 教育网全段 + 常见中国段。要精确用 set_cn_networks() 加载完整 CN 段。
# ----------------------------------------------------------------------
_BUILTIN_CN: tuple[str, ...] = (
    # CERNET 教育网（202.112–202.127, 210.28–210.47, 211.64–211.99, 219.216–219.227）
    "202.112.0.0/13", "202.120.0.0/13", "210.28.0.0/14", "210.32.0.0/12",
    "211.64.0.0/13", "211.80.0.0/12", "219.216.0.0/13", "219.224.0.0/14",
    # 常见中国段（运营商/政企，较确定）
    "202.96.0.0/16", "202.97.0.0/16", "202.99.0.0/16", "202.100.0.0/16",
    "202.101.0.0/16", "202.102.0.0/16", "202.103.0.0/16", "202.104.0.0/16",
    "202.105.0.0/16", "202.106.0.0/16", "202.107.0.0/16", "202.108.0.0/16",
    "202.109.0.0/16", "202.110.0.0/16", "202.111.0.0/16",
    "218.0.0.0/14", "218.4.0.0/14", "218.8.0.0/14", "218.12.0.0/14",
    "218.16.0.0/13", "218.24.0.0/14", "218.28.0.0/14", "218.60.0.0/15",
    "218.64.0.0/12", "218.80.0.0/12", "218.96.0.0/12", "219.128.0.0/11",
    "220.160.0.0/11", "221.0.0.0/12", "221.192.0.0/11", "222.32.0.0/12",
    "223.64.0.0/10",
    # 国内云（阿里云/腾讯云/百度/华为/京东 主要国内段，减少国内云误标境外）
    "39.106.0.0/16", "47.98.0.0/16", "47.99.0.0/16", "47.100.0.0/16",
    "47.101.0.0/16", "47.102.0.0/16", "47.103.0.0/16", "121.196.0.0/16",
    "121.197.0.0/16", "121.198.0.0/16", "81.68.0.0/16", "129.204.0.0/16",
    "134.175.0.0/16", "140.143.0.0/16", "106.54.0.0/16", "39.156.0.0/16",
    "121.36.0.0/16", "124.70.0.0/16", "159.138.0.0/16", "119.3.0.0/16",
    "129.226.0.0/16", "129.211.0.0/16",
)

#: 已知高风险/可疑顶级域（廉价/免费注册，常被钓鱼/恶意使用）
_SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "click", "link",
    "work", "loan", "bid", "download", "stream", "win", "party", "review",
    "date", "trade", "science", "racing", "accountant", "pics", "gdn",
    "mom", "kim", "men", "zip", "mov", "onion",
}
#: 明显恶意/风险关键词（出现在 URL 里）
_RISKY_KEYWORDS = (
    "login", "signin", "verify", "secure", "account", "pay", "payment",
    "bank", "wallet", "bitcoin", "crypto", "coinbase", "phish", "webhook",
    "c2", "shell", "backdoor", "ransom", "onion", "tor",
)
#: 常见境外云/托管段（用于佐证"境外"，可空）
_OVERSEAS_CLOUD = (
    "52.0.0.0/8", "54.0.0.0/8", "13.0.0.0/8", "3.0.0.0/8", "18.0.0.0/8",
    "35.0.0.0/8", "44.0.0.0/8", "104.0.0.0/8", "151.0.0.0/8", "185.0.0.0/8",
)

_cn_networks: tuple[ipaddress.IPv4Network, ...] | None = None
_overseas_networks: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.ip_network(x) for x in _OVERSEAS_CLOUD
)


def set_cn_networks(path: str | None) -> int:
    """加载外部中国网段文件（每行一个 CIDR，`#` 注释）。返回段数。"""
    global _cn_networks
    if not path:
        _cn_networks = None
        return 0
    nets = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue
    _cn_networks = tuple(nets)
    return len(nets)


def _cn() -> tuple[ipaddress.IPv4Network, ...]:
    global _cn_networks
    if _cn_networks is None:
        _cn_networks = tuple(ipaddress.ip_network(x) for x in _BUILTIN_CN)
    return _cn_networks


# ---------------------------------------------------------------------- 判定


def _is_private(ip: ipaddress.IPv4Address) -> bool:
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def ip_country(ip: str) -> tuple[str, str]:
    """返回 (归属, 说明)。归属：`境内` / `境外（疑似）` / `内网`。"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "未知", "非 IP"
    if _is_private(a):
        return "内网", "私有/保留地址（本机/内网）"
    if any(a in n for n in _cn()):
        return "境内", "命中内置中国网段"
    if any(a in n for n in _overseas_networks):
        return "境外（疑似）", "命中常见境外云/托管段"
    return "境外（疑似）", "未命中中国网段（离线判定）"


def _risk_keywords(url: str) -> list[str]:
    low = url.lower()
    return [k for k in _RISKY_KEYWORDS if k in low]


def risk_level(host: str, ip: str | None, url: str,
               country: str = "") -> tuple[str, list[str]]:
    """返回 (等级, 原因列表)。等级：高 / 中 / 低。"""
    reasons: list[str] = []
    tld = (host.rsplit(".", 1)[-1] if "." in host else "").lower()
    low = url.lower()
    kws = _risk_keywords(url)

    if country == "境外（疑似）":
        reasons.append("访问境外（疑似）地址")
    if country == "内网":
        reasons.append("内网地址")
    if tld in _SUSPICIOUS_TLDS:
        reasons.append(f"可疑/免费顶级域 .{tld}")
    if ".onion" in low:
        reasons.append("暗网 .onion")
    if not low.startswith("https://") and low.startswith("http://"):
        reasons.append("非 HTTPS 明文")
    for k in kws:
        reasons.append(f"URL 含风险关键词「{k}」")

    high = any(r in ("访问境外（疑似）地址", "暗网 .onion") for r in reasons) \
        or (tld in _SUSPICIOUS_TLDS and country == "境外（疑似）")
    mid = bool(reasons) and not high
    if high:
        return "高", reasons
    if mid:
        return "中", reasons
    return "低", reasons


# ---------------------------------------------------------------------- URL


@dataclass
class UrlInfo:
    url: str
    host: str = ""
    scheme: str = ""
    port: int = 0
    path: str = ""
    query: str = ""
    title: str = ""
    fingerprint: str = ""
    ip: str = ""
    country: str = ""
    region: str = ""
    risk: str = "低"
    reasons: list[str] = field(default_factory=list)
    resolved: bool = False

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _lookup_ip(host: str) -> str:
    """DNS 解析（仅显式 resolve=True 时调用）。失败返回空。"""
    import socket
    try:
        return socket.getaddrinfo(host, None)[0][4][0]
    except (socket.gaierror, OSError, IndexError):
        return ""


def analyze_url(url: str, *, resolve: bool = False, ip_hint: str = "",
                title: str = "", fingerprint: str = "") -> UrlInfo:
    """解析单个 URL：域名 / IP / 境外识别 / 风险等级。title/指纹为可选元数据。"""
    url = (url or "").strip()
    info = UrlInfo(url=url)
    if not url:
        return info
    u = urlparse(url if "://" in url else "//" + url)
    info.scheme = u.scheme or ""
    info.host = (u.hostname or "").lower()
    try:
        info.port = u.port or 0
    except ValueError:
        info.port = 0
    info.path = unquote(u.path or "")
    info.query = unquote(u.query or "")
    info.title = title or ""
    info.fingerprint = fingerprint or ""

    # IP：host 直连 IP，或 ip_hint，或 DNS 解析
    ip = ip_hint
    if not ip:
        try:
            ipaddress.ip_address(info.host)
            ip = info.host
        except ValueError:
            pass
    if not ip and resolve:
        ip = _lookup_ip(info.host)
    info.ip = ip
    info.resolved = bool(ip)

    if ip:
        country, region = ip_country(ip)
        info.country = country
        info.region = region
    risk, reasons = risk_level(info.host, ip, url, info.country)
    info.risk = risk
    info.reasons = reasons
    return info


def analyze_urls(urls: Iterable[str], *, resolve: bool = False,
                 ip_map: dict[str, str] | None = None) -> list[UrlInfo]:
    """批量分析。ip_map 可提供 {域名: ip} 免解析。"""
    ip_map = ip_map or {}
    out = []
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        out.append(analyze_url(u, resolve=resolve, ip_hint=ip_map.get(host, "")))
    return out


def risk_stats(items: Iterable[UrlInfo]) -> dict[str, Any]:
    """按风险等级 / 境外 / 顶级域聚合。"""
    by_risk = {"高": 0, "中": 0, "低": 0}
    overseas = 0
    hosts: dict[str, int] = {}
    for it in items:
        by_risk[it.risk] = by_risk.get(it.risk, 0) + 1
        if it.country == "境外（疑似）":
            overseas += 1
        if it.host:
            hosts[it.host] = hosts.get(it.host, 0) + 1
    return {
        "total": len(items),
        "by_risk": by_risk,
        "overseas": overseas,
        "top_hosts": sorted(hosts.items(), key=lambda kv: -kv[1])[:20],
    }


def parse_scanner_output(text: str) -> dict[str, Any]:
    """
    解析扫描器 `result.txt` 输出（WP 0x05 的内网扫描结果格式）：

        [icmp] 192.168.100.100
        [url]  http://192.168.100.1:8098
        [title] http://192.168.100.1:8098      小米路由器
        [finger] http://192.168.100.100:80      打印机

    返回 {items:[UrlInfo.as_dict...], icmp_hosts:[...], stats:{...}}。
    每条 URL 带 port / title / fingerprint 与境外 IP 识别 / 风险等级。
    """
    urls: dict[str, dict[str, str]] = {}
    icmps: list[str] = []
    text = text.lstrip("\ufeff")   # 兼容带 BOM 的日志/结果文件
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^\[icmp\]\s+(\S+)", line)
        if m:
            icmps.append(m.group(1))
            continue
        m = re.match(r"^\[url\]\s+(\S+)", line)
        if m:
            urls.setdefault(m.group(1), {})
            continue
        # title / finger 行独立携带 URL（不依赖 [url] 块顺序）
        m = re.match(r"^\[title\]\s+(\S+)\s+(.*)", line)
        if m:
            urls.setdefault(m.group(1), {})["title"] = m.group(2).strip()
            continue
        m = re.match(r"^\[finger\]\s+(\S+)\s+(.*)", line)
        if m:
            urls.setdefault(m.group(1), {})["fingerprint"] = m.group(2).strip()
    items = []
    for u, meta in urls.items():
        it = analyze_url(u, title=meta.get("title", ""),
                         fingerprint=meta.get("fingerprint", ""))
        items.append(it.as_dict())
    return {"items": items, "icmp_hosts": icmps,
            "stats": risk_stats([analyze_url(u) for u in urls])}
