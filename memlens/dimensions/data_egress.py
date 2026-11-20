r"""
MemLens · 维度四：数据外联证实（FR-04）

对应方案 4.2.3(4)。

## 四类替代证据（方案原文）

> 单机条件下，本维度**不能依赖网络会话**，改以主机侧的计量与台账替代，
> 按证明力由强到弱取四类：
> ① **会话记录**（防火墙日志、进程网络事件）证明谁连到哪；
> ② **字节计量**（系统资源使用统计、网卡累计计数）证明确实传输及传输量；
> ③ **域名台账**（代理客户端缓存、域名缓存、浏览器记录）证明访问对象；
> ④ **存在性痕迹**（应用标识表、程序兼容性数据库、虚拟网卡创建时间）证明工具与使用人。
> 四类逐级收敛，**不因缺少网络会话而放弃本维度**。

## 量级比对（方案原文）

> 主机侧计量不低于网络侧记录的**六成**，视为匹配（差额由协议封装与重传开销解释）；
> 低于**三成**触发量级不匹配诊断；介于两者之间记为"量级存疑"，该维上限降一级。
> 这两条线是可以调的经验值，**写在规则包里，不写在代码里**。

## 现实（内存镜像的边界）

- ① 会话记录 → **可得**（`mprocfs.net`：连接五元组 + 归属进程 + 时间）；
- ② 字节计量 → **不可得**（SRUM/网卡计数在磁盘或内核态，内存镜像里没有）；
- ③ 域名台账 → **部分可得**（`mprocfs.netdns` DNS 缓存 + 浏览器历史）；
- ④ 存在性痕迹 → **部分可得**（进程/模块表）。

因此本维在内存域的实际证明力是「**会话 + 域名台账**」，
按方案表 12 的精神，**上限封顶 B 级**（除非接入网络侧设备记录完成三处交叉）。
"""

from __future__ import annotations

import ipaddress
from typing import Any

from memlens.dimensions.base import Dimension, DimensionResult
from memlens.detectors.base import get_field

#: 内网网段（不作为"外联"证据）
_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
)


#: RFC 5737 文档网段。Python 的 `is_private` 把它们也算成私有，
#: 但在本维度里"文档网段"同样是**对外地址**（测试镜像常用它代表外联目标），
#: 所以必须单独排除，否则外联证据会被整片丢掉（实测踩过）。
_DOC_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def _is_private(addr: str) -> bool:
    """判断是否内网/回环/保留地址（文档网段**不算**内网）。"""
    try:
        ip = ipaddress.ip_address(addr.strip())
    except ValueError:
        return True
    if any(ip in net for net in _DOC_NETS):
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return True
    return any(ip in net for net in _PRIVATE_NETS)


class DataEgressDimension(Dimension):
    """FR-04 数据外联证实。"""

    dimension = "data_egress"
    sources = ("mprocfs.net%", "mprocfs.netdns%", "mprocfs.browser_history%")
    level_cap = "B"          # 方案表 12：单机采集外联维上限 B

    def run(self, ctx, pack) -> DimensionResult:
        used, missing = self.available_sources(ctx)
        res = DimensionResult(dimension=self.dimension, level_cap=self.level_cap)
        res.sources_used = used
        res.sources_missing = missing

        # ---- ① 会话记录 ----
        net_rows = ctx.records("mprocfs.net%", limit=50000)
        external: list[dict[str, Any]] = []
        local_listen: list[dict[str, Any]] = []
        for r in net_rows:
            dst = str(get_field(r, "DstAddr", "RemoteAddr", default="") or "")
            dport = str(get_field(r, "DstPort", default="") or "")
            state = str(get_field(r, "State", default="") or "").upper()
            if not dst:
                continue
            if state in ("LISTEN", "LISTENING"):
                local_listen.append(r)
                continue
            if _is_private(dst):
                continue
            external.append({
                "dst": dst, "port": dport,
                "process": str(get_field(r, "Process", default="") or ""),
                "pid": get_field(r, "PID", default=""),
                "proto": str(get_field(r, "Proto", default="") or ""),
                "time": str(get_field(r, "Time", default="") or ""),
                "src": str(get_field(r, "SrcAddr", default="") or ""),
            })

        # ---- ③ 域名台账 ----
        domains: dict[str, int] = {}
        for r in ctx.records("mprocfs.netdns%", limit=20000):
            host = str(get_field(r, "Host", "Name", "Answer", default="") or "").strip()
            if host:
                domains[host.lower()] = domains.get(host.lower(), 0) + 1
        browser_domains: dict[str, int] = {}
        for r in ctx.records("mprocfs.browser_history%", limit=20000):
            url = str(get_field(r, "URL", "url", default="") or "")
            if not url:
                continue
            for part in url.split("//")[-1].split("/")[0].split(":")[0].lower().split("."):
                pass
            host = url.split("//")[-1].split("/")[0].split(":")[0].lower()
            if host:
                browser_domains[host] = browser_domains.get(host, 0) + 1
        domain_ledger = {**domains}
        for k, v in browser_domains.items():
            domain_ledger[k] = domain_ledger.get(k, 0) + v

        # ---- ④ 存在性痕迹 ----
        proc_rows = ctx.records("mprocfs.process%", limit=20000)

        # ---- 降级：字节计量不可得 ----
        res.gaps.append(self.gap(
            "字节计量", "字节计量源缺失：系统资源使用统计（SRUM）与网卡累计计数"
                            "不在内存镜像中，无法计量传输量",
            impact="downgrade", level_cap="B",
            suggestion="如需传输量证据，从目标磁盘提取 SRUM 数据库，或接入网络侧会话记录。"))
        if "mprocfs.net%" in missing:
            res.gaps.append(self.gap(
                "连接表", "缺少连接表产物，无会话记录可用",
                impact="downgrade", level_cap="C",
                suggestion="补齐 mprocfs.net 产物。"))

        # ---- 评分：按四类证据逐级收敛 ----
        have_classes: list[str] = []
        score = 0.0
        independent = 0

        if external:
            have_classes.append("会话记录")
            independent = max(independent, 1)
            # 有进程归属的外联证明力更强（可落到"机器—进程—人"的收口）
            attributed_any = any(
                str(get_field(r, "Process", default="") or "").strip()
                for r in net_rows
                if str(get_field(r, "DstAddr", default="") or "").strip()
                and not _is_private(str(get_field(r, "DstAddr", default="") or "")))
            score = max(score, 0.65 if attributed_any else 0.45)
            # 外联由**哪个进程**发起很关键（机器—进程—人的收口）
            procs = {str(get_field(p, "PID", default="")): p for p in proc_rows}
            procs_by_name: dict[str, int] = {}
            for e in external:
                pid = str(e.get("pid") or "")
                p = procs.get(pid)
                pname = ""
                if p:
                    pname = str(get_field(p, "Name", default="") or "")
                if not pname:
                    pname = e.get("process") or "(未知进程)"
                procs_by_name[pname] = procs_by_name.get(pname, 0) + 1
            top = sorted(procs_by_name.items(), key=lambda kv: -kv[1])[:5]
            # ★ **如实区分"已归属进程"与"未归属（系统级）"**：
            #   内存里的连接表大量条目 PID=0（内核态/已回收），
            #   把它们统统算作某进程的"外联"是造假阳性。
            attributed = sum(c for n, c in procs_by_name.items() if n != "(未知进程)")
            unattributed = len(external) - attributed
            res.findings.append(
                f"会话记录：{len(external)} 条指向非内网地址的连接"
                f"（已归属进程 {attributed} 条 / 未归属系统级 {unattributed} 条）")
            if attributed:
                res.findings.append(
                    "主要发起进程：" + "、".join(f"{n}×{c}" for n, c in top if n != "(未知进程)"))
            else:
                res.findings.append(
                    "⚠ 全部外联连接**均无进程归属**（PID=0）："
                    "该批连接无法落到具体程序，本维证据力受限。")
            for e in external[:10]:
                res.evidence_refs.append(
                    f"net:{e['dst']}:{e['port']}:pid={e.get('pid','')}")
            res.findings.append("注：外联存在**不等于**违规——需与域名分类（访问方向维）"
                                "与合规通道白名单交叉后由综合判定给出结论。")

        if domain_ledger:
            have_classes.append("域名台账")
            independent = max(independent, 1)
            score = max(score, 0.45)
            res.findings.append(f"域名台账：{len(domain_ledger)} 个域名"
                                f"（DNS 缓存 {len(domains)} + 浏览器记录 {len(browser_domains)}）")
            for h, c in sorted(domain_ledger.items(), key=lambda kv: -kv[1])[:8]:
                res.evidence_refs.append(f"domain:{h}")

        if proc_rows:
            have_classes.append("存在性痕迹")
            independent = max(independent, 1)
            score = max(score, 0.3)

        # ---- 量级比对（需要网络侧记录时才可做）----
        t_match = self.threshold(pack, "scoring.magnitude_match", 0.60)
        t_suspect = self.threshold(pack, "scoring.magnitude_suspect", 0.30)
        res.gaps.append(self.gap(
            "量级比对", "未接入网络侧会话记录，无法做主机侧/网络侧字节量级比对",
            impact="downgrade", level_cap="B",
            suggestion=f"导入上网行为管理设备的会话记录后自动比对"
                       f"（匹配线 {t_match:.0%}、存疑线 {t_suspect:.0%}，均可调）。"))

        if not have_classes:
            res.state = "not_found"
            res.score = 0.0
            res.findings.append("无任何外联证据可用")
            res.independent_sources = 0
            return res

        res.score = min(1.0, score)
        res.state = "established" if res.score >= 0.5 else "not_found"
        res.independent_sources = independent
        # ★ 三处交叉（时间 / 域名 / 进程·使用人）只有在**接入网络侧设备记录**
        #   后才成立。当前工具尚无网络侧记录接入能力 ⇒ 恒为 False，
        #   于是整体等级按方案 4.2.4 封顶 B（这是正确的保守取值）。
        res.external_cross_ok = False
        res.findings.insert(0, "已取得的替代证据类别：" + "、".join(have_classes))
        return res
