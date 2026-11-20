# -*- coding: utf-8 -*-
"""
MemLens · 网站访问日志分析（WP 0x05 服务器取证）

解析 nginx/apache access log（common / combined 格式），提取：
  · 攻击者 IP（触发可疑探测 / 文件上传 / 一句话木马访问）；
  · 可疑请求（/?s=admin、/?s=captcha&test=-1、invokefunction、file_put_contents 等）；
  · 一句话木马（`<?php @eval($_POST[...])?>` 等）及其 SHA-256（大写）；
  · 每个 IP 的请求统计与风险标记。

纯本地文本解析，不依赖挂载系统（日志可由 MemLens 容器/XFS 通道提取后传入）。
"""

from __future__ import annotations

import dataclasses
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# nginx/apache combined 日志行
_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]*)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)
# 可疑探测/利用路径
_SUSPICIOUS_PATH = re.compile(
    r'(\?s=(admin|captcha|index|login))|(invokefunction)|(file_put_contents)|'
    r'(\$_POST)|(@eval)|(eval\s*\(|\bassert\s*\()|(\.php[?%])|(upload|shell|webshell|cmd)',
    re.I,
)
# 一句话木马完整语句（eval/assert/system/passthru/shell_exec + $_POST/GET 回调，到 ?>
# 或行尾）。snippet 取整条木马，sha256 对整条内容（WP 0x05 题 12 口径）。
_WEBSHELL_RE = re.compile(
    r'<\?php[^?>]*?@?(?:eval|assert|system|passthru|shell_exec)\s*\('
    r'\s*\$_(?:POST|GET|REQUEST|COOKIE)\s*\[[^\]]*\]\s*\)[^?>]*?(?:\?>|$)',
    re.I | re.S,
)


@dataclass
class LogEntry:
    ip: str = ""
    time: str = ""
    method: str = ""
    path: str = ""
    status: int = 0
    referer: str = ""
    ua: str = ""
    suspicious: bool = False
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def _suspicious_reason(path: str) -> str:
    m = _SUSPICIOUS_PATH.search(path)
    return m.group(0) if m else ""


def parse_log_lines(text: str) -> list[LogEntry]:
    """解析日志文本 → LogEntry 列表（仅成功匹配的行）。"""
    out = []
    for line in text.splitlines():
        m = _LOG_RE.match(line.strip())
        if not m:
            continue
        path = m.group("path")
        reason = _suspicious_reason(path)
        out.append(LogEntry(
            ip=m.group("ip"), time=m.group("time"), method=m.group("method"),
            path=path, status=int(m.group("status") or 0),
            referer=m.group("referer"), ua=m.group("ua"),
            suspicious=bool(reason), reason=reason,
        ))
    return out


def detect_webshell(text: str) -> list[dict[str, Any]]:
    """从文本/文件内容里识别一句话木马 → [{sha256(大写), snippet}]。"""
    hits = []
    for m in _WEBSHELL_RE.finditer(text):
        snippet = m.group(0)
        hits.append({
            "sha256": hashlib.sha256(snippet.encode("utf-8", "replace")).hexdigest().upper(),
            "snippet": snippet[:160],
        })
    # 去重
    seen, uniq = set(), []
    for h in hits:
        if h["sha256"] in seen:
            continue
        seen.add(h["sha256"])
        uniq.append(h)
    return uniq


def analyze_access_log(text: str, *, keyword: str = "") -> dict[str, Any]:
    """
    网站访问日志分析：
      · attackers：触发可疑/上传/木马访问的 IP（含次数、可疑请求）；
      · suspicious：可疑请求明细；
      · webshell：一句话木马内容与 SHA-256（大写）；
      · summary：总行 / 攻击者数 / 可疑请求数 / 木马数。
    """
    text = text.lstrip("\ufeff")   # 兼容带 BOM 的日志文件
    entries = parse_log_lines(text)
    if keyword:
        entries = [e for e in entries if keyword.lower() in e.path.lower()]
    suspicious = [e for e in entries if e.suspicious]
    by_ip: dict[str, list[LogEntry]] = {}
    for e in entries:
        by_ip.setdefault(e.ip, []).append(e)

    attackers = []
    for ip, es in by_ip.items():
        sus = [e for e in es if e.suspicious]
        uploads = [e for e in es if re.search(r'\.php|upload|\.php[?%]', e.path, re.I)]
        if sus or uploads:
            attackers.append({
                "ip": ip,
                "requests": len(es),
                "suspicious": len(sus),
                "uploads": len(uploads),
                "paths": sorted({e.path for e in es})[:20],
                "methods": sorted({e.method for e in es}),
            })
    attackers.sort(key=lambda a: -a["suspicious"])

    return {
        "summary": {
            "total_lines": len(entries),
            "suspicious_count": len(suspicious),
            "attacker_count": len(attackers),
            "webshell_count": len(detect_webshell(text)),
        },
        "attackers": attackers,
        "suspicious": [e.as_dict() for e in suspicious[:200]],
        "webshell": detect_webshell(text),
    }
