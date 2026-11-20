r"""
MemLens · 规则包（Rule Pack）—— 判定阈值与词表的外置治理机制

## 为什么必须做（方案 FR-21 / 1.5 / 3.4）

方案《计算机系统数字取证工作台开发方案》三处强调同一件事：

1. **1.5 结论强度与判据来源**
   > 所有判定阈值、白名单、域名分类词表以**规则包**形式发布，带**版本号与发布日期**；
   > 报告首页写明所用规则包版本。
   > 任何一次阈值调整须评审、留痕，并在变更记录中说明理由与影响范围。
   > 没有这一条，"同一台机器两个人跑出两个结论"就无法解释。

2. **3.4 关键设计决策·其三：规则与阈值外置**
   > 指纹库、判定阈值、域名分类词表以文件形式存放，支持离线包升级与版本回滚。
   > 代理工具特征变化快，改规则不应发版；更重要的是，**规则维护责任在业务侧，
   > 不在开发侧**，外置才能让业务人员自己调。

3. **表 9 数据实体「规则包」**
   > 版本号、发布日期、阈值集合、白名单、域名词表、变更记录。
   > 报告须引用版本号，这是结论可复现的前提。

## 本模块提供什么

- **一个规则包的文件格式**（单个 JSON，字段见 `RulePack`）；
- **加载 / 校验 / 激活 / 回滚**（离线包，不联网）；
- **一个全局只读访问点** `current()`，供检测器取阈值（不再读硬编码常量）；
- **内置默认规则包**（把现有的硬编码权重/白名单搬进来，作为 `1.0.0` 基线版本），
  保证"改阈值不用改代码"这件事从今天起成立。

## 阈值取值的三条规矩

1. **缺项回退到内置默认**，绝不因为规则包不完整就让检测器崩掉；
2. **取值范围校验**：置信度权重必须落在 `[0, 1]`，否则拒绝加载并报明确原因；
3. **规则包哈希入库**：每次激活记 SHA-256，报告引用"版本号 + 哈希"，可逐字节复核。

## 与检测器的衔接

检测器改为从 `current().threshold("hidden_process.w_pool_only", default=0.55)` 取值。
这样：
- 业务侧改阈值 → 改规则包 JSON → 重新导入 → **不发版**；
- 报告写明版本号 → 复核时能取回同一份规则包重跑 → 结论可复现。
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

#: 规则包目录（相对工作目录）：`work/rulepacks/`
RULEPACK_DIRNAME = "rulepacks"

#: 内置默认阈值（= 现有代码里的硬编码常量，作为 1.0.0 基线）
DEFAULT_THRESHOLDS: dict[str, float] = {
    # ── hidden_process ──
    "hidden_process.w_pool_only": 0.55,      # 仅池扫描命中（基础分）
    "hidden_process.w_not_in_list": 0.10,    # 活动链表里完全没有
    "hidden_process.w_has_network": 0.12,    # 有网络连接
    "hidden_process.w_non_whitelist_name": 0.08,
    "hidden_process.w_psxview_flag": 0.10,
    "hidden_process.w_empty_cmdline": 0.05,
    "hidden_process.w_orphan_ppid": 0.05,
    "hidden_process.w_whitelist_penalty": -0.20,
    "hidden_process.conf_max": 0.98,
    "hidden_process.orphan_threshold": 5,    # 差异超过这个数 → 合并为一条
    # ── injection ──
    "injection.w_malfind": 0.50,
    "injection.w_rwx": 0.15,
    "injection.w_no_module": 0.12,
    "injection.w_has_network": 0.08,
    "injection.w_non_whitelist_name": 0.05,
    "injection.w_mz_header": 0.10,
    "injection.w_whitelist_penalty": -0.15,
    "injection.conf_max": 0.98,
}

#: 内置默认白名单
DEFAULT_WHITELIST: dict[str, list[str]] = {
    # 系统进程白名单（隐藏进程检测的降分依据）
    "system_process": [
        "system", "system idle process", "registry", "smss.exe", "csrss.exe",
        "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
        "explorer.exe", "taskhostw.exe", "sihost.exe", "ctfmon.exe",
        "fontdrvhost.exe", "spoolsv.exe", "wmiprvse.exe", "searchindexer.exe",
        "memcompression.exe", "runtimebroker.exe", "dashost.exe",
        "securityhealthservice.exe", "msmpeng.exe", "audiodg.exe",
        "conhost.exe", "dllhost.exe", "backgroundtaskhost.exe", "wudfhost.exe",
    ],
}

#: 五维权重（方案表 13）
DEFAULT_DIMENSION_WEIGHTS: dict[str, float] = {
    "tool_presence": 0.20,      # 工具存在
    "channel_config": 0.20,     # 通道配置
    "execution_trace": 0.25,    # 实际执行
    "data_egress": 0.25,        # 数据外联
    "access_direction": 0.10,   # 访问方向
}

#: 五维判定阈值（方案 4.2.4 定档规则）
DEFAULT_DIMENSION_THRESHOLDS: dict[str, float] = {
    "scoring.confirmed_total": 0.75,     # 加权总分 ≥ 此值 且 外联维达标 → 已确认
    "scoring.risk_total": 0.40,          # ≥ 此值 → 存在风险；低于 → 记录备查
    "scoring.egress_floor": 0.50,        # 外联维下限（防"装而未用"被误定为已确认）
    "scoring.magnitude_match": 0.60,     # 主机侧计量 ≥ 网络侧记录的此比例 → 视为匹配
    "scoring.magnitude_suspect": 0.30,  # 低于此比例 → 量级不匹配诊断
    "scoring.level_a_sources": 2,        # 独立来源数 ≥ 此值 → A 级
    "scoring.level_b_sources": 1,        # 单来源内部多点一致 → B 级
    "scoring.trace_intersect_hours": 24, # 五源首次运行时间交集判定窗口（小时）
}

#: 代理/隧道工具指纹库（方案 4.2.3(1)）
#:
#: 指纹分强弱两级（方案原文）：
#:   * **强指纹** —— 数字签名主体 / 程序版本信息 / 配置目录结构。
#:     任一项单独命中即可定位，几乎不会误撞。
#:   * **弱指纹** —— 文件名 / 图标哈希 / 目录关键字。
#:     必须两项以上组合命中才采信，且其中至少一项必须是**路径类**特征。
#:
#: 白名单按**签名主体与安装路径**匹配，不按名称匹配（方案点名这是实践踩过的坑）。
#: 这里的 `exclude_paths` / `exclude_names` 就是给业务侧维护的白名单入口。
DEFAULT_PROXY_TOOLS: list[dict[str, Any]] = [
    {
        "id": "v2ray",
        "display": "V2Ray",
        "category": "proxy",
        "strong": {"process": ["v2ray.exe", "v2ray"], "path_keyword": ["\\v2ray\\", "\\v2rayn\\"]},
        "weak": {"process": ["v2ray"], "path_keyword": ["v2ray"]},
        "exclude_paths": ["\\v2rayn\\speedtest\\"],
    },
    {
        "id": "xray",
        "display": "Xray",
        "category": "proxy",
        "strong": {"process": ["xray.exe", "xray"], "path_keyword": ["\\xray\\"]},
        "weak": {"process": ["xray"], "path_keyword": ["xray"]},
        "exclude_paths": [],
    },
    {
        "id": "singbox",
        "display": "sing-box",
        "category": "proxy",
        "strong": {"process": ["sing-box.exe"], "path_keyword": ["\\sing-box\\"]},
        "weak": {"process": ["sing-box"], "path_keyword": ["sing-box"]},
        "exclude_paths": [],
    },
    {
        "id": "clash",
        "display": "Clash / Mihomo",
        "category": "proxy",
        "strong": {"process": ["clash.exe", "clash-verge.exe", "mihomo.exe", "clash.meta"],
                   "path_keyword": ["\\clash\\", "\\mihomo\\", "\\clash-verge\\"]},
        "weak": {"process": ["clash", "mihomo"], "path_keyword": ["clash", "mihomo"]},
        "exclude_paths": [],
    },
    {
        "id": "shadowsocks",
        "display": "Shadowsocks",
        "category": "proxy",
        "strong": {"process": ["ss-local.exe", "ss-server.exe", "shadowsocks.exe"],
                   "path_keyword": ["\\shadowsocks\\", "\\shadowsocks-rust\\"]},
        "weak": {"process": ["ss-local", "ss-server"], "path_keyword": ["shadowsocks"]},
        "exclude_paths": [],
    },
    {
        "id": "trojan",
        "display": "Trojan",
        "category": "proxy",
        "strong": {"process": ["trojan.exe", "trojan-go.exe"], "path_keyword": ["\\trojan\\"]},
        "weak": {"process": ["trojan"], "path_keyword": ["trojan"]},
        "exclude_paths": [],
    },
    {
        "id": "frp",
        "display": "FRP（内网穿透）",
        "category": "tunnel",
        "strong": {"process": ["frpc.exe", "frps.exe"], "path_keyword": ["\\frp\\"]},
        "weak": {"process": ["frpc", "frps"], "path_keyword": ["frp"]},
        "exclude_paths": [],
    },
    {
        "id": "ngrok",
        "display": "ngrok",
        "category": "tunnel",
        "strong": {"process": ["ngrok.exe"], "path_keyword": ["\\ngrok\\"]},
        "weak": {"process": ["ngrok"], "path_keyword": ["ngrok"]},
        "exclude_paths": [],
    },
    {
        "id": "chisel",
        "display": "Chisel",
        "category": "tunnel",
        "strong": {"process": ["chisel.exe"], "path_keyword": ["\\chisel\\"]},
        "weak": {"process": ["chisel"], "path_keyword": ["chisel"]},
        "exclude_paths": [],
    },
    {
        "id": "wireguard",
        "display": "WireGuard",
        "category": "vpn",
        "strong": {"process": ["wireguard.exe"], "path_keyword": ["\\wireguard\\"]},
        "weak": {"process": ["wireguard"], "path_keyword": ["wireguard"]},
        "exclude_paths": [],
    },
    {
        "id": "openvpn",
        "display": "OpenVPN",
        "category": "vpn",
        "strong": {"process": ["openvpn.exe"], "path_keyword": ["\\openvpn\\"]},
        "weak": {"process": ["openvpn"], "path_keyword": ["openvpn"]},
        "exclude_paths": [],
    },
    {
        "id": "gost",
        "display": "GOST",
        "category": "tunnel",
        "strong": {"process": ["gost.exe"], "path_keyword": ["\\gost\\"]},
        "weak": {"process": ["gost"], "path_keyword": ["gost"]},
        "exclude_paths": [],
    },
    {
        "id": "privoxy",
        "display": "Privoxy",
        "category": "proxy",
        "strong": {"process": ["privoxy.exe"], "path_keyword": ["\\privoxy\\"]},
        "weak": {"process": ["privoxy"], "path_keyword": ["privoxy"]},
        "exclude_paths": [],
    },
    {
        "id": "squid",
        "display": "Squid",
        "category": "proxy",
        "strong": {"process": ["squid.exe"], "path_keyword": ["\\squid\\"]},
        "weak": {"process": ["squid"], "path_keyword": ["squid"]},
        "exclude_paths": [],
    },
    {
        "id": "proxychains",
        "display": "ProxyChains",
        "category": "proxy",
        "strong": {"process": ["proxychains.exe"], "path_keyword": ["\\proxychains\\"]},
        "weak": {"process": ["proxychains"], "path_keyword": ["proxychains"]},
        "exclude_paths": [],
    },
]

#: 内置默认词表（方案 FR-05 的域名分类骨架）
DEFAULT_WORDLIST: dict[str, Any] = {
    # 五类打标（方案 4.2.3(5)：学术 / 技术 / 新闻 / 社交 / 流媒体）
    "domain_category": {
        "academic": ["scholar.google.com", "arxiv.org", "ieeexplore.ieee.org",
                     "acm.org", "doi.org", "springer.com", "sciencedirect.com"],
        "technical": ["stackoverflow.com", "github.com", "developer.mozilla.org",
                      "docs.microsoft.com", "learn.microsoft.com", "kernel.org",
                      "python.org", "docs.python.org"],
        "news": ["bbc.com", "reuters.com", "xinhuanet.com", "thepaper.cn",
                 "36kr.com", "cnbeta.com"],
        "social": ["weibo.com", "twitter.com", "x.com", "zhihu.com",
                   "douban.com", "reddit.com"],
        "streaming": ["youtube.com", "netflix.com", "bilibili.com",
                      "iqiyi.com", "youku.com", "twitch.tv"],
    },
    # 合规通道清单（方案 4.2.3(4)：白名单按域名与地址段双重匹配）
    "compliant_channel": [],
    # 反取证行为特征（方案 4.3.2(6) 后果评估）
    "anti_forensics": [
        "vssadmin delete shadows", "wmic shadowcopy delete",
        "wevtutil cl", "clear-eventlog", "bcdedit /set", "recoveryenabled no",
    ],
}


@dataclasses.dataclass
class RulePack:
    """
    一个规则包。

    Attributes:
        version: 版本号（报告必须引用）
        published_at: 发布日期
        thresholds: 阈值集合（点分路径 → 数值）
        whitelist: 白名单（分类 → 条目列表）
        wordlist: 词表（域名分类 / 合规通道 / 反取证特征）
        change_log: 变更记录（理由 + 影响范围）
        source_path: 来源路径（离线包位置）
        sha256: 规则包文件哈希
    """

    version: str
    published_at: str = ""
    thresholds: dict[str, float] = dataclasses.field(default_factory=dict)
    whitelist: dict[str, list[str]] = dataclasses.field(default_factory=dict)
    wordlist: dict[str, Any] = dataclasses.field(default_factory=dict)
    #: 五维权重（方案表 13）
    dimension_weights: dict[str, float] = dataclasses.field(default_factory=dict)
    #: 代理/隧道工具指纹库（方案 4.2.3(1)）：强/弱指纹分层
    proxy_tools: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    change_log: str = ""
    source_path: str = ""
    sha256: str = ""
    pack_id: str = ""
    #: 落盘文件名（从磁盘加载时保留）——避免 pack_id 与 version 脱钩导致互相覆盖
    filename: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id or self.version,
            "version": self.version,
            "published_at": self.published_at,
            "thresholds": dict(self.thresholds),
            "whitelist": {k: list(v) for k, v in self.whitelist.items()},
            "wordlist": self.wordlist,
            "dimension_weights": dict(self.dimension_weights),
            "proxy_tools": list(self.proxy_tools),
            "change_log": self.change_log,
            "source_path": self.source_path,
            "sha256": self.sha256,
            "filename": self.filename,
        }

    def threshold(self, key: str, default: float | None = None) -> float:
        """
        取阈值。**缺项回退**：先查规则包，再查内置默认，最后用传入的 default。

        这样即使规则包只覆盖部分键，检测器也不会因为缺阈值而崩。
        """
        if key in self.thresholds:
            return float(self.thresholds[key])
        if key in DEFAULT_THRESHOLDS:
            return float(DEFAULT_THRESHOLDS[key])
        if default is not None:
            return float(default)
        return 0.0

    def whitelist_list(self, category: str) -> list[str]:
        """取白名单条目（小写比较，便于匹配）。"""
        items = self.whitelist.get(category)
        if items is None:
            items = DEFAULT_WHITELIST.get(category, [])
        return [str(x).lower() for x in items]

    def wordlist_get(self, key: str) -> Any:
        """取词表条目。"""
        val = self.wordlist.get(key)
        if val is None:
            return DEFAULT_WORDLIST.get(key)
        return val

    def dimension_weight(self, dimension: str) -> float:
        """取五维权重（缺项回退内置基线）。"""
        if dimension in self.dimension_weights:
            return float(self.dimension_weights[dimension])
        return float(DEFAULT_DIMENSION_WEIGHTS.get(dimension, 0.0))

    def tools(self) -> list[dict[str, Any]]:
        """代理/隧道工具指纹库（缺项回退内置基线）。"""
        return self.proxy_tools or list(DEFAULT_PROXY_TOOLS)

    def tool_by_id(self, tool_id: str) -> dict[str, Any] | None:
        for t in self.tools():
            if str(t.get("id")) == tool_id:
                return t
        return None


# ------------------------------------------------------------------ 校验

class RulePackError(ValueError):
    """规则包不合法（版本缺失 / 阈值越界 / JSON 损坏）。"""


#: 计数类阈值的键名特征（不受 [-1, 1] 约束）
_COUNT_THRESHOLD_HINTS: tuple[str, ...] = (
    "conf_max", "threshold", "sources", "hours", "count", "level_a", "level_b",
    "max_", "min_",
)


def _is_count_threshold(key: str) -> bool:
    """该阈值是否属于计数类（来源数 / 小时数 / 条数）。"""
    k = str(key).lower()
    return any(h in k for h in _COUNT_THRESHOLD_HINTS)


def validate(pack: dict[str, Any]) -> list[str]:
    """
    校验规则包内容。

    Returns: 问题清单（空 = 通过）
    Raises: RulePackError（版本号缺失这种致命问题）
    """
    problems: list[str] = []
    version = str(pack.get("version") or "").strip()
    if not version:
        raise RulePackError("规则包缺少 version（版本号）——报告必须引用它")
    thresholds = pack.get("thresholds") or {}
    if not isinstance(thresholds, dict):
        problems.append("thresholds 必须是对象（点分路径 → 数值）")
        thresholds = {}
    for k, v in thresholds.items():
        try:
            fv = float(v)
        except (TypeError, ValueError):
            problems.append(f"阈值 {k} 不是数值：{v!r}")
            continue
        # ★ 阈值分两类：
        #   · **权重类**（置信度权重、系数）——取值应在 [-1, 1]
        #   · **计数类**（来源数、小时数、条数）——是整数计数，不受 [-1,1] 约束
        # 早先只按 "conf_max"/"threshold" 放行计数类，导致
        # `scoring.level_a_sources=2`、`scoring.trace_intersect_hours=24`
        # 被误报成"越界"（实测踩过）。
        if not _is_count_threshold(k) and not (-1.0 <= fv <= 1.0):
            problems.append(f"阈值 {k}={fv} 超出权重取值范围 [-1, 1]")
    weights = pack.get("dimension_weights") or {}
    if weights and not isinstance(weights, dict):
        problems.append("dimension_weights 必须是对象（维度 → 权重）")
    else:
        for k, v in (weights or {}).items():
            try:
                fv = float(v)
            except (TypeError, ValueError):
                problems.append(f"维度权重 {k} 不是数值：{v!r}")
                continue
            if not (0.0 <= fv <= 1.0):
                problems.append(f"维度权重 {k}={fv} 超出 [0, 1]")
    tools = pack.get("proxy_tools") or []
    if tools and not isinstance(tools, list):
        problems.append("proxy_tools 必须是列表")
    else:
        for t in tools:
            if not isinstance(t, dict):
                problems.append("proxy_tools 的每一项必须是对象")
                continue
            if not t.get("id"):
                problems.append("proxy_tools 条目缺少 id")
    whitelist = pack.get("whitelist") or {}
    if not isinstance(whitelist, dict):
        problems.append("whitelist 必须是对象（分类 → 列表）")
    for k, v in whitelist.items():
        if not isinstance(v, list):
            problems.append(f"白名单 {k} 必须是列表")
    wordlist = pack.get("wordlist") or {}
    if not isinstance(wordlist, dict):
        problems.append("wordlist 必须是对象")
    if not str(pack.get("published_at") or "").strip():
        problems.append("缺少 published_at（发布日期）——方案要求规则包带发布日期")
    return problems


# ------------------------------------------------------------------ 加载

def load_pack(path: str | os.PathLike) -> RulePack:
    """从 JSON 文件加载规则包（不做写操作）。"""
    p = Path(path)
    if not p.is_file():
        raise RulePackError(f"规则包文件不存在：{p}")
    raw = p.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise RulePackError(f"规则包 JSON 解析失败：{exc}") from exc
    if not isinstance(data, dict):
        raise RulePackError("规则包根节点必须是对象")
    problems = validate(data)
    if problems:
        raise RulePackError("规则包校验不通过：" + "；".join(problems))
    version = str(data.get("version"))
    return RulePack(
        filename=p.name,
        version=version,
        published_at=str(data.get("published_at") or ""),
        thresholds={k: float(v) for k, v in (data.get("thresholds") or {}).items()},
        whitelist={k: list(v) for k, v in (data.get("whitelist") or {}).items()},
        wordlist=dict(data.get("wordlist") or {}),
        # ★ 缺字段回退内置默认 —— 旧版本写出的规则包文件（没有维度权重/
        #   工具指纹这两节）也能正常加载，不会因为"文件里没这个键"而丢维度权重。
        dimension_weights={k: float(v)
                           for k, v in (data.get("dimension_weights") or {}).items()} \
            or dict(DEFAULT_DIMENSION_WEIGHTS),
        proxy_tools=list(data.get("proxy_tools") or []) or [dict(t) for t in DEFAULT_PROXY_TOOLS],
        change_log=str(data.get("change_log") or ""),
        source_path=str(p.resolve()),
        sha256=hashlib.sha256(raw).hexdigest(),
        pack_id=str(data.get("pack_id") or version),
    )


def _safe(name: str) -> str:
    """把版本号/ID 转成安全文件名。"""
    out = "".join(ch if (ch.isalnum() or ch in "-_.") else "_" for ch in str(name))
    return out.strip("._") or "pack"


def _pack_file(pack: RulePack) -> str:
    """
    规则包落盘文件名。

    ★ **优先用 pack_id**（它是稳定标识），但**必须与版本号解耦**——
      否则导入一个 pack_id 沿用旧值的新版本时，会把旧版本的文件覆盖掉，
      "回滚到基线"就变成了"回到被覆盖的假基线"（实测踩过）。
      做法：文件名 = pack_id + "@" + version，两部分都对得上才命中同一文件。
    """
    if pack.filename:
        return pack.filename
    pid = _safe(pack.pack_id or pack.version)
    ver = _safe(pack.version)
    return f"{pid}@{ver}.json" if pid != ver else f"{pid}.json"



def _pack_matches(pack: RulePack, path: Path, wanted: str) -> bool:
    """
    判断某个规则包文件是不是" wanted "指的那个。

    兼容三种写法：
      · 完整 pack_id（如 `1.0.0`）
      · 版本号（如 `1.0.0`）
      · 旧式带前缀写法（如 `builtin-1.0.0`）——前缀 `builtin-` 会被忽略
    """
    w = _safe(wanted)
    if pack.pack_id == wanted or pack.version == wanted:
        return True
    if w.startswith("builtin-") and (pack.version == w[len("builtin-"):]
                                      or pack.pack_id == w[len("builtin-"):]):
        return True
    return path.stem.startswith(w)


def default_pack() -> RulePack:
    """内置默认规则包（1.0.0 基线）——现有硬编码常量的正式化。"""
    return RulePack(
        version="1.0.0",
        published_at="2026-11-12",
        thresholds={**DEFAULT_THRESHOLDS, **DEFAULT_DIMENSION_THRESHOLDS},
        whitelist={k: list(v) for k, v in DEFAULT_WHITELIST.items()},
        wordlist={k: (list(v) if isinstance(v, list) else dict(v))
                  for k, v in DEFAULT_WORDLIST.items()},
        dimension_weights=dict(DEFAULT_DIMENSION_WEIGHTS),
        proxy_tools=[dict(t) for t in DEFAULT_PROXY_TOOLS],
        change_log="基线版本：将代码内硬编码的判定阈值、白名单与词表正式外置为规则包。",
        source_path="(builtin)",
        sha256=hashlib.sha256(
            json.dumps({"thresholds": {**DEFAULT_THRESHOLDS, **DEFAULT_DIMENSION_THRESHOLDS},
                        "whitelist": DEFAULT_WHITELIST,
                        "wordlist": DEFAULT_WORDLIST,
                        "dimension_weights": DEFAULT_DIMENSION_WEIGHTS,
                        "proxy_tools": DEFAULT_PROXY_TOOLS},
                       sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest(),
        pack_id="1.0.0",
        filename="1.0.0.json",
    )


# ------------------------------------------------------------------ 管理

class RulePackManager:
    """
    规则包管理器：目录存储 + 激活 + 回滚（**全程离线**）。

    目录布局（相对工作目录）：
        work/rulepacks/
            builtin-1.0.0.json        ← 内置基线（自动生成）
            2026-11-20-agent-v3.json  ← 业务侧导入的离线包
            active.json               ← 当前激活包的指针
    """

    def __init__(self, workdir: str | os.PathLike) -> None:
        self.root = Path(workdir) / RULEPACK_DIRNAME
        self._lock = threading.Lock()
        self._cache: RulePack | None = None

    # ------------------------------------------------------------ 目录
    @property
    def active_pointer(self) -> Path:
        return self.root / "active.json"

    def _ensure_dir(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------ 激活
    def activate(self, pack: RulePack) -> RulePack:
        """把规则包写入目录并设为激活。"""
        with self._lock:
            self._ensure_dir()
            fname = _pack_file(pack)
            dst = self.root / fname
            payload = pack.to_dict()
            dst.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                           encoding="utf-8")
            self.active_pointer.write_text(
                json.dumps({"pack_id": pack.pack_id or pack.version,
                            "version": pack.version,
                            "file": fname,
                            "activated_at": time.strftime("%Y-%m-%d %H:%M:%S")},
                           ensure_ascii=False, indent=2), encoding="utf-8")
            self._cache = None
            return pack

    def current(self) -> RulePack:
        """
        当前生效的规则包。

        读不到时回退到**内置基线**——绝不因为规则包缺失就让分析跑不起来。
        """
        with self._lock:
            if self._cache is not None:
                return self._cache
        pack = self._load_active()
        if pack is None:
            pack = self._seed_builtin()
        with self._lock:
            self._cache = pack
        return pack

    def _seed_builtin(self) -> RulePack:
        """
        首次使用时把**内置基线包落盘**并设为生效。

        为什么必须落盘：否则"回滚到内置基线"没有目标——
        业务侧换了规则包之后想退回原始阈值，却找不到基线包文件。
        """
        pack = default_pack()
        try:
            self._ensure_dir()
            dst = self.root / _pack_file(pack)
            payload = pack.to_dict()
            payload.pop("filename", None)
            need_write = not dst.is_file()
            if not need_write:
                # 已存在的基线包若是**旧格式**（缺维度权重/工具指纹），自动重播种，
                # 否则磁盘上会一直留着过时内容，报告引用的版本却是"新格式"。
                try:
                    old = json.loads(dst.read_text(encoding="utf-8"))
                    need_write = (not old.get("dimension_weights")
                                  or not old.get("proxy_tools"))
                except Exception:
                    need_write = True
            if need_write:
                dst.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                               encoding="utf-8")
            if not self.active_pointer.is_file():
                self.active_pointer.write_text(
                    json.dumps({"pack_id": pack.pack_id, "version": pack.version,
                                "file": _pack_file(pack),
                                "activated_at": time.strftime("%Y-%m-%d %H:%M:%S")},
                               ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        return pack

    def _load_active(self) -> RulePack | None:
        try:
            if not self.active_pointer.is_file():
                return None
            ptr = json.loads(self.active_pointer.read_text(encoding="utf-8"))
            fname = ptr.get("file") or f"{ptr.get('pack_id')}.json"
            p = self.root / fname
            if not p.is_file():
                return None
            return load_pack(p)
        except Exception:
            return None

    def list_packs(self) -> list[dict[str, Any]]:
        """列出目录里的所有规则包（按版本倒序）。"""
        out: list[dict[str, Any]] = []
        if not self.root.is_dir():
            return out
        for p in sorted(self.root.glob("*.json")):
            if p.name == "active.json":
                continue
            try:
                pk = load_pack(p)
                out.append({"pack_id": pk.pack_id, "version": pk.version,
                            "published_at": pk.published_at,
                            "sha256": pk.sha256, "source_path": pk.source_path,
                            "change_log": pk.change_log,
                            "active": self._is_active(pk)})
            except Exception as exc:
                out.append({"pack_id": p.stem, "version": "?",
                            "published_at": "", "sha256": "",
                            "source_path": str(p), "change_log": "",
                            "active": False, "error": str(exc)})
        out.sort(key=lambda x: x.get("published_at") or "", reverse=True)
        return out

    def _is_active(self, pack: RulePack) -> bool:
        try:
            if not self.active_pointer.is_file():
                return False
            ptr = json.loads(self.active_pointer.read_text(encoding="utf-8"))
            return ptr.get("pack_id") == (pack.pack_id or pack.version)
        except Exception:
            return False

    def rollback(self, pack_id: str) -> RulePack:
        """回滚到指定版本（把它的指针重新指过去）。"""
        # 先按文件名找，找不到再按 pack_id 匹配目录里的包
        p = self.root / f"{pack_id}.json"
        if not p.is_file():
            for cand in sorted(self.root.glob("*.json")):
                if cand.name == "active.json":
                    continue
                try:
                    pk0 = load_pack(cand)
                except Exception:
                    continue
                if _pack_matches(pk0, cand, pack_id):
                    p = cand
                    break
        if not p.is_file():
            raise RulePackError(f"规则包不存在，无法回滚：{pack_id}")
        pk = load_pack(p)
        return self.activate(pk)

    def import_pack(self, path: str | os.PathLike, *, activate: bool = True) -> RulePack:
        """
        导入离线规则包（**不联网**）。

        流程：读取 → 校验 → 落盘到规则包目录 → （可选）激活。
        校验不通过会明确报出所有问题，不"宽容地"半导入。
        """
        pk = load_pack(path)
        self._ensure_dir()
        # ★ 解耦：导入的文件若沿用了旧 pack_id，强制改用版本号派生，
        #   否则会覆盖同名旧版本文件（"回滚到基线"会拿到被覆盖的内容）。
        pk.pack_id = _safe(pk.version)
        pk.filename = ""
        fname = _pack_file(pk)
        dst = self.root / fname
        payload = pk.to_dict()
        payload.pop("filename", None)
        dst.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        pk.filename = fname
        if activate:
            return self.activate(pk)
        return pk

    def export_pack(self, pack_id: str, out_path: str | os.PathLike) -> str:
        """导出规则包（交付给业务侧改阈值用）。"""
        p = self.root / f"{pack_id}.json"
        if not p.is_file():
            for cand in sorted(self.root.glob("*.json")):
                if cand.name == "active.json":
                    continue
                try:
                    pk0 = load_pack(cand)
                except Exception:
                    continue
                if _pack_matches(pk0, cand, pack_id):
                    p = cand
                    break
        if not p.is_file():
            raise RulePackError(f"规则包不存在：{pack_id}")
        shutil.copy2(p, out_path)
        return str(Path(out_path).resolve())


# ------------------------------------------------------------------ 全局访问点

_MANAGER: RulePackManager | None = None


def configure(workdir: str | os.PathLike) -> RulePackManager:
    """绑定规则包目录（进程内单例）。"""
    global _MANAGER
    _MANAGER = RulePackManager(workdir)
    return _MANAGER


def manager() -> RulePackManager:
    """取规则包管理器（未配置时用临时目录，不影响运行）。"""
    global _MANAGER
    if _MANAGER is None:
        _MANAGER = RulePackManager(Path(tempfile.gettempdir()) / "memlens-rulepacks")
    return _MANAGER


def current() -> RulePack:
    """
    当前规则包（全局只读访问点）。

    检测器调这个取阈值，**不再读硬编码常量**。
    """
    return manager().current()


def threshold(key: str, default: float | None = None) -> float:
    """便捷：取阈值。"""
    return current().threshold(key, default)


def whitelist_list(category: str) -> list[str]:
    """便捷：取白名单。"""
    return current().whitelist_list(category)


def wordlist_get(key: str) -> Any:
    """便捷：取词表。"""
    return current().wordlist_get(key)


def summary() -> dict[str, Any]:
    """规则包摘要（写进报告与 /api/health）。"""
    pk = current()
    return {
        "version": pk.version,
        "published_at": pk.published_at,
        "sha256": pk.sha256,
        "source_path": pk.source_path,
        "threshold_count": len(pk.thresholds),
        "whitelist_groups": sorted(pk.whitelist.keys()),
        "wordlist_keys": sorted(pk.wordlist.keys()),
        "dimension_weights": (dict(pk.dimension_weights)
                              or dict(DEFAULT_DIMENSION_WEIGHTS)),
        "proxy_tool_count": len(pk.tools()),
        "change_log": pk.change_log,
    }
