"""
MemLens · IOC 提取器

在任意文本（插件产出的字段值、镜像里的字符串、命令行…）里提取"可作为指标"的实体。

工程要点（都是踩过的坑）：
  1. **必须去噪**。内存镜像里大量 x86 机器码，随便一个宽松正则都会把
     `D$ Hc@<H` 这类字节判成邮箱/IP。判据不是"正则匹配上了"，而是
     `plausible()` 这一层的结构性检查（字母占比、字符集、词法位置）。
  2. **私有地址与公网地址要分开**。内网 IP 是正常业务，外网 IP 才是线索。
  3. **每个 IOC 必须带出处**（来自哪个插件的哪条记录），否则无法复核。
  4. 正则全部**预编译一次**，扫描时不重复编译。
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
import string
from typing import Any, Callable, Iterable, Iterator


# ------------------------------------------------------------------ 数据结构


@dataclasses.dataclass(frozen=True)
class IOC:
    """一个提取到的指标。"""

    kind: str                      # ipv4 / url / domain / email / ...
    value: str                     # 归一化后的值
    extra: dict[str, Any] = dataclasses.field(default_factory=dict)   # 公网/私网、端口、路径深度…
    span: tuple[int, int] | None = None        # 在原文中的位置

    def to_record(self) -> dict[str, Any]:
        d = {"ioc_type": self.kind, "value": self.value}
        d.update(self.extra)
        return d


@dataclasses.dataclass(frozen=True)
class IOCSpec:
    """一类 IOC 的提取规则。"""

    kind: str
    pattern: re.Pattern[str]
    #: 归一化与附加属性
    enrich: Callable[[re.Match[str]], dict[str, Any]] | None = None
    #: 结构性合理性检查（返回 False 丢弃）
    plausible: Callable[[str], bool] | None = None
    #: 是否默认开启（噪声较大的规则可关）
    enabled: bool = True
    #: 严重度提示
    severity: str = "low"
    #: 中文说明
    note: str = ""


# ------------------------------------------------------------------ 合理性


_PRINTABLE = set(string.printable)
_HEX = set("0123456789abcdefABCDEF")

#: RFC 5737 文档保留网段。Python 的 `is_private` 会把它们算成 True（因为它把
#: "非全球可达"都归入私有），若不分出来，203.0.113.x 这类地址会被误标成"私网"。
_DOC_NETS = tuple(
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def _letter_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isalpha() for c in s) / len(s)


def _all_printable(s: str) -> bool:
    return all(c in _PRINTABLE for c in s)


# ------------------------------------------------------------------ 归一化


def _ip_extra(value: str | re.Match[str]) -> dict[str, Any]:
    """
    IPv4 的地址属性 —— 这是最实用的一条附加信息。

    参数既接受字符串也接受 `re.Match`：IOCSpec.enrich 的协议是传 Match 对象，
    这里两种都收。否则调用方传错类型会抛 ValueError，再被上层的
    `except Exception: pass` 静默吞掉，表现为"公网/私网字段莫名其妙是空的"。
    """
    if hasattr(value, "group"):
        value = value.group(0)
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return {}
    scope = "公网"
    if ip.is_loopback:
        scope = "回环"
    elif ip.is_link_local:
        scope = "链路本地"
    elif ip.is_multicast:
        scope = "组播"
    elif ip.is_unspecified:
        scope = "未指定"
    elif any(ip in n for n in _DOC_NETS):
        scope = "文档段"
    elif ip.is_private:
        scope = "私网"
    elif ip.is_reserved:
        scope = "保留"
    extra: dict[str, Any] = {"scope": scope}
    # 文档段也按"值得看一眼"处理：它在真实数据里通常就是拿来做演示/占位的公网地址
    if scope in ("公网", "文档段"):
        extra["severity"] = "medium"
    return extra


# ------------------------------------------------------------------ 各类型规则

# ---- IPv4 ----
_IPV4_RE = re.compile(
    r"(?<![\w.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?![\w.])"
)

# ---- IPv6（基础形态：冒号分组 + 最多 1 次 ::）----
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"(?![0-9A-Fa-f:])"
)

# ---- URL ----
_URL_RE = re.compile(r"\b(?:https?|ftp|smb|file)://[^\s\"'<>\\]{4,300}", re.IGNORECASE)

# ---- 邮箱 ----
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")

# ---- 域名（含至少两段，且 TLD 为字母）----
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:com|net|org|cn|ru|io|cc|info|biz|top|xyz|tk|ml|ga|cf|gq|pw|onion|co|uk|de|fr|jp|kr|in|br|su|site|online|shop|fun|icu|vip|work|live|me|tv|us|eu)"
    r"\b",
    re.IGNORECASE,
)

# ---- 钱包 ----
_BTC_RE = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# ---- 路径 ----
# ⚠ 关键：字符类里**绝不能放空格**。写成 `[^\\/:*?"<>|]+` 会让路径一路吞掉整行，
# 实测 `C:\Users\Public\x.exe HKLM\...\Run bitcoin 1A1...` 会被整条吃成一个"路径"。
#
# 正确的分段规则（同时满足"允许 C:\Program Files 又不让它越界"）：
#   · 中间段允许含空格（C:\Program Files\、C:\Users\John Doe\ 都成立）
#   · 但中间段里**不允许出现像文件名的词元**（`svc.exe`/`x.dll`/`a.dat`）——
#     一旦出现就说明这里已经是文件名，路径到此为止，后面的空格不属于路径。
#   · 最后一段不含空格。
_FILE_EXT = r"(?:exe|dll|sys|bat|cmd|ps1|vbs|js|tmp|dat|log|ini|cfg|bin|drv|ocx|cpl|cab|etl|evtx)"
_TOK = r"[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*"
_NOT_FILE_TOK = rf"(?!{_TOK}\.{_FILE_EXT}\b)"
# 一个中间段 = 可选的"词元+空格"序列，最后跟一个非文件词元
_SEG = rf"{_NOT_FILE_TOK}(?:{_TOK}[ ]+)*{_NOT_FILE_TOK}{_TOK}"
# 最后一段：无空格，允许带扩展名
_SEG_LAST = r"[^\\/:*?\"<>|\r\n ]+"

_WIN_PATH_RE = re.compile(rf"\b[A-Za-z]:\\(?:{_SEG}\\)*{_SEG_LAST}")
_UNC_PATH_RE = re.compile(rf"\\\\[A-Za-z0-9._$-]+\\(?:{_SEG}\\)*{_SEG_LAST}")
_UNIX_PATH_RE = re.compile(
    r"(?<![\w/])/(?:usr|etc|var|tmp|home|root|bin|sbin|lib|opt|dev|proc|sys|boot)"
    r"(?:/[\w.@+-]+){1,12}"
)
# ---- 注册表键 ----
# 注册表键名允许空格但极罕见，这里直接禁止空格换取零误吞。
_REG_KEY_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKU|HKCR|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS|"
    r"HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG)"
    r"\\[A-Za-z0-9_.\\-]{1,200}",
    re.IGNORECASE,
)

# ---- JWT ----
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")

# ---- GUID ----
_GUID_RE = re.compile(r"\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}")

# ---- MAC ----
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

# ---- Windows 用户名 ----
_WIN_USER_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_.\-]{2,15}\\Users\\([A-Za-z0-9_.\-]{1,40})\\")


# ---- 去噪函数 ----


def _plausible_ip(v: str) -> bool:
    if not _all_printable(v):
        return False
    # 排除版本号样式的 "1.2.3.4" 常见误伤：整串不能被当成常见端口号段
    parts = v.split(".")
    if all(p.isdigit() and 0 <= int(p) <= 5 for p in parts):
        return False        # 像版本号 1.2.3.4
    return True


def _plausible_email(v: str) -> bool:
    if not _all_printable(v):
        return False
    local, _, domain = v.partition("@")
    if len(local) < 2 or local.endswith(".") or ".." in local:
        return False
    if not domain or domain.startswith("-") or domain.endswith("."):
        return False
    tld = domain.rsplit(".", 1)[-1]
    if not (2 <= len(tld) <= 24) or not tld.isalpha():
        return False
    # 机器码常把字节看成 "xx@yy.zz"（实测 `fQh@2Z.QQ` 就是这样混进来的）。
    # 真实域名的每一段标签都应是纯字母，因此要求**至少存在一段全字母标签**；
    # 这一条能挡掉整段都是十六进制/数字的情况。
    labels = domain.split(".")
    if not any(len(lb) >= 2 and lb.isalpha() for lb in labels[:-1]):
        return False
    return _letter_ratio(local) >= 0.5 and _letter_ratio(domain) >= 0.5


def _plausible_domain(v: str) -> bool:
    if not _all_printable(v):
        return False
    label = v.rsplit(".", 1)[0]
    if _letter_ratio(label) < 0.4:
        return False
    return not v.lower().endswith((".dll", ".sys", ".exe"))    # 避免与文件名混淆


def _plausible_url(v: str) -> bool:
    if not _all_printable(v):
        return False
    body = v.split("://", 1)[1]
    return _letter_ratio(body) >= 0.4


def _plausible_btc(v: str) -> bool:
    body = v[1:] if v.startswith("1") else v
    return all(c in _HEX for c in body)


def _plausible_guid(v: str) -> bool:
    return True


# ------------------------------------------------------------------ 规则表

SPECS: tuple[IOCSpec, ...] = (
    IOCSpec("url", _URL_RE, plausible=_plausible_url, severity="medium",
            note="含协议的 URL，常见于 C2 回连与外传"),
    IOCSpec("email", _EMAIL_RE, enrich=lambda m: {"severity": "low"},
            plausible=_plausible_email, note="邮箱地址"),
    IOCSpec("ipv4", _IPV4_RE, enrich=_ip_extra, plausible=_plausible_ip,
            severity="medium", note="IPv4 地址；公网地址通常比私网更值得关注"),
    IOCSpec("ipv6", _IPV6_RE, severity="low", note="IPv6 地址"),
    IOCSpec("domain", _DOMAIN_RE, plausible=_plausible_domain, severity="medium",
            note="域名；与 URL 同源出现时优先看 URL"),
    IOCSpec("bitcoin", _BTC_RE, severity="high", note="比特币地址（勒索赎金常见）"),
    IOCSpec("ethereum", _ETH_RE, severity="high", note="以太坊地址"),
    IOCSpec("jwt", _JWT_RE, severity="high", note="JSON Web Token，可能携带会话凭据"),
    IOCSpec("guid", _GUID_RE, plausible=_plausible_guid, severity="low",
            note="GUID；常见于 COM/计划任务 CLSID，需结合上下文判断"),
    IOCSpec("unc_path", _UNC_PATH_RE, severity="medium", note="UNC 网络共享路径（横向移动线索）"),
    IOCSpec("registry_key", _REG_KEY_RE, severity="medium",
            note="注册表键路径；命中 Run/RunOnce/Services 等即为持久化线索"),
    IOCSpec("windows_path", _WIN_PATH_RE, severity="low",
            note="Windows 绝对路径"),
    IOCSpec("unix_path", _UNIX_PATH_RE, severity="low", note="Linux 绝对路径"),
    IOCSpec("mac", _MAC_RE, severity="low", note="MAC 地址"),
    IOCSpec("win_user", _WIN_USER_RE, severity="low",
            note="从路径中提取出的用户名"),
)


# ------------------------------------------------------------------ 扫描


def scan_text(text: str, *, kinds: Iterable[str] | None = None, limit_per_kind: int = 2000,
               ) -> list[IOC]:
    """
    在一段文本里提取所有 IOC。

    Args:
        text: 待扫描文本。
        kinds: 只提取指定类型；None 表示全部。
        limit_per_kind: 每类最多返回多少个（去重后），防止单条记录里刷出上万个 IP。

    Returns:
        IOC 列表（已按 (kind, value) 去重）。
    """
    if not text or len(text) > 8_000_000:
        return []
    wanted = set(kinds) if kinds else None
    out: list[IOC] = []
    for spec in SPECS:
        if wanted is not None and spec.kind not in wanted:
            continue
        seen: set[str] = set()
        for m in spec.pattern.finditer(text):
            raw = m.group(0)
            value = raw
            extra: dict[str, Any] = {}
            if spec.kind == "win_user":
                value = m.group(1)
                extra["full"] = raw
            if spec.plausible and not spec.plausible(value):
                continue
            if value in seen:
                continue
            seen.add(value)
            if spec.enrich:
                try:
                    extra.update(spec.enrich(m))
                except Exception as exc:      # noqa: BLE001 —— enrich 失败不该中断整篇扫描
                # 但必须留下痕迹：静默吞掉会让人以为"公网/私网字段莫名为空"
                    extra.setdefault("enrich_error", f"{type(exc).__name__}: {exc}")
            extra.setdefault("severity", spec.severity)
            if spec.note:
                extra.setdefault("note", spec.note)
            out.append(IOC(spec.kind, value, extra, (m.start(), m.end())))
            if len(seen) >= limit_per_kind:
                break
    return out


def scan_records(records: Iterable[dict[str, Any]], *, kinds: Iterable[str] | None = None,
                 fields: tuple[str, ...] | None = None, limit_per_record: int = 64,
                 ) -> list[tuple[dict[str, Any], str, IOC]]:
    """
    对一批记录做 IOC 提取。

    Returns:
        (原记录, 命中的字段名, IOC) 三元组列表。
    """
    out: list[tuple[dict[str, Any], str, IOC]] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        picked = (
            {k: v for k, v in rec.items() if k in fields}
            if fields else rec
        )
        for key, val in picked.items():
            if not isinstance(val, str) or len(val) < 4:
                continue
            if len(val) > 200_000:
                val = val[:200_000]
            for ioc in scan_text(val, kinds=kinds, limit_per_kind=limit_per_record):
                out.append((rec, key, ioc))
    return out


def kind_summary(iocs: Iterable[IOC]) -> dict[str, int]:
    """按类型统计命中数量。"""
    counts: dict[str, int] = {}
    for i in iocs:
        counts[ioc.kind] = counts.get(ioc.kind, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def public_only(iocs: Iterable[IOC]) -> list[IOC]:
    """只保留公网 IP —— 这是出网线索里最有价值的一类。"""
    return [i for i in iocs if i.kind == "ipv4" and i.extra.get("scope") == "公网"]


def iter_specs() -> Iterator[IOCSpec]:
    return iter(SPECS)
