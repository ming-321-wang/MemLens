r"""
MemLens · 维度二：通道配置核查（FR-02）

对应方案 4.2.3(2)。

## 三个配置面（方案原文）

> 用户级代理（注册表当前用户配置单元）、系统级代理、浏览器独立配置。
> 三者要分别读取，只查其中一个会漏——**不少工具只改浏览器配置或只改系统代理，
> 用户级代理为空，只查用户级就会判为"无通道"**。

## 四类异常面（方案原文）

> 虚拟网卡（适配器类型、驱动信息、创建时间——**创建时间价值极高，
> 可与首次运行时间对齐**）、路由（默认路由指向虚拟网关、特定网段路由、分流域名路由）、
> 域名解析（指向本地回环、加密域名解析启用、hosts 变更）、
> 进程网络行为（代理进程监听本地端口、其他进程经该端口出网）。

## 高价值项（方案原文）

> **自动配置脚本地址单列为高价值项**：这类地址常直接暴露订阅来源与分发渠道，
> 一个脚本地址可以牵出整条订阅链路，其证据价值高于单个代理服务器地址。

## 降级（方案原文）

> 用户级配置因权限读不到时，仅保留系统级与浏览器级结论，
> 在证据清单中标注"用户级未覆盖"，该维得分按缺失项折算，**不得按满分计**。

## 数据来源与现实

本工具是**内存镜像**取证，注册表读取走 MemProcFS 收获的注册表虚拟 FS。
因此：

- **系统级代理**（HKLM Internet Settings）：可在收获阶段抓取 → 可判定；
- **用户级代理**（HKU\<SID> Internet Settings）：需遍历所有用户 SID → 可判定但需扩展收获；
- **浏览器独立配置**（Chromium Preferences 文件）：需先 dump 文件 → **缺失即降级**；
- **虚拟网卡 / 路由 / hosts**：内存镜像里只有当前连接表与 DNS 缓存，
  **不含完整适配器与路由表** → 明确降级，不假装判过。
"""

from __future__ import annotations

import re
from typing import Any

from memlens.dimensions.base import Dimension, DimensionResult
from memlens.detectors.base import get_field

#: 代理配置相关注册表键（相对 HKLM / HKU\<SID>）
PROXY_KEY_SUFFIX = "Software/Microsoft/Windows/CurrentVersion/Internet Settings"

#: 代理配置取值名（**一律小写**——比较时用 name.lower()，
#: 早先写成混合大小写却拿小写去比，永远匹配不上（实测踩过：一条代理配置都判不出来））
_PROXY_VALUES = ("proxyenable", "proxyserver", "proxyoverride", "autoconfigurl",
                 "autodetect", "migrateproxy")


def _reg(rec: dict[str, Any], cn: str, *en: str) -> Any:
    """注册表记录取值：**先精确取中文列名**，再回退英文别名。

    与 get_field 的区别：get_field 是"候选里第一个命中就返回"，
    对中文列名不可靠（键名/值名/数据三个都是中文名）。
    """
    if cn in rec and rec[cn] not in (None, ""):
        return rec[cn]
    for k in en:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return None


def _is_proxy_process(proc_name: str, pack) -> bool:
    """进程名是否命中工具指纹库。"""
    low = str(proc_name or "").lower()
    if not low:
        return False
    for tool in pack.tools():
        for key in ("strong", "weak"):
            for n in (tool.get(key) or {}).get("process") or []:
                n = str(n).lower()
                if n and (n == low or low.startswith(n)):
                    return True
    return False


class ChannelConfigDimension(Dimension):
    """FR-02 通道配置核查。"""

    dimension = "channel_config"
    sources = ("mprocfs.registry_proxy%", "mprocfs.net%", "mprocfs.netdns%")
    level_cap = "A"

    def run(self, ctx, pack) -> DimensionResult:
        used, missing = self.available_sources(ctx)
        res = DimensionResult(dimension=self.dimension, level_cap=self.level_cap)
        res.sources_used = used
        res.sources_missing = missing

        # ---- ① 三个代理配置面 ----
        proxy_rows = ctx.records("mprocfs.registry_proxy%", limit=5000)
        surfaces = {
            "user": [],     # 用户级
            "system": [],   # 系统级
            "browser": [],  # 浏览器级
        }
        for r in proxy_rows:
            # ⚠ **不能**用 get_field 的"首个候选命中"语义取这三个字段：
            #   get_field(r, "注册表键", ...) 会返回**键路径**，
            #   而"名称"要的是**值名**（ProxyEnable / AutoConfigURL …）——
            #   两者都是中文键名，靠候选顺序区分不住（实测踩过：
            #   结果把整条注册表路径当成值名，导致代理配置一条都判不出来）。
            key = str(_reg(r, "注册表键", "Key", "key") or "")
            name = str(_reg(r, "名称", "Name", "name") or "")
            val = str(_reg(r, "数据", "Value", "value", "Data") or "")
            if not name:
                continue
            bucket = "system" if key.upper().startswith("HKLM") else "user"
            surfaces[bucket].append((key, name, val))

        score = 0.0
        found_any = False
        evidence: list[str] = []
        refs: list[str] = []

        for surface in ("system", "user"):
            for key, name, val in surfaces[surface]:
                if name.lower() not in _PROXY_VALUES:
                    continue
                if not val or val.strip() in ("", "0"):
                    continue
                found_any = True
                # 自动配置脚本地址 = **高价值项**（方案原文）
                if name.lower() == "autoconfigurl" and val.strip():
                    score = max(score, 0.95)
                    evidence.append(f"★ 自动配置脚本地址（高价值）：{val[:160]}")
                elif name.lower() == "proxyserver" and val.strip():
                    score = max(score, 0.8)
                    evidence.append(f"代理服务器地址：{val[:160]}")
                elif name.lower() == "proxyenable" and val.strip() not in ("0",):
                    score = max(score, 0.6)
                    evidence.append(f"代理已启用：{key} → {name}={val}")
                else:
                    score = max(score, 0.45)
                    evidence.append(f"代理配置项：{key} → {name}={val[:80]}")
                refs.append(f"registry:{key}:{name}")

        # ---- ② 浏览器级配置（若收获到了）----
        browser_rows = ctx.records("mprocfs.registry_browser_proxy%", limit=2000)
        for r in browser_rows:
            name = str(get_field(r, "名称", "Name", default="") or "")
            val = str(get_field(r, "数据", "Value", default="") or "")
            if name.lower() in ("proxyserver", "autoconfigurl", "proxy") and val:
                found_any = True
                score = max(score, 0.8)
                evidence.append(f"浏览器独立代理配置：{name}={val[:120]}")
                refs.append(f"browser_proxy:{name}")

        # ---- ③ 异常面：本地回环解析 / 代理进程本地监听 ----
        dns_rows = ctx.records("mprocfs.netdns%", limit=5000)
        local_dns = 0
        for r in dns_rows:
            host = str(get_field(r, "Host", "Name", "Answer", "host", default="") or "")
            if host.strip() in ("127.0.0.1", "::1", "localhost", "0.0.0.0"):
                local_dns += 1
        if local_dns:
            found_any = True
            score = max(score, 0.55)
            evidence.append(f"DNS 缓存出现 {local_dns} 条指向本地回环的解析（疑似本地代理分流）")

        net_rows = ctx.records("mprocfs.net%", limit=20000)
        # ★ 方案 4.2.3(2) 的异常面是"**代理进程**监听本地端口"——
        #   不是"有进程在监听"（那是再正常不过的事：每个系统服务都在监听）。
        #   所以这里只把**命中工具指纹的进程**的监听算作异常。
        #
        # ★ 端口取 **SrcPort**：监听套接字的本地端口在源端口侧，
        #   DstPort 对监听态恒为 0（实测 MemProcFS netscan 就是这样）。
        proxy_listen: list[str] = []
        other_listen = 0
        for r in net_rows:
            state = str(get_field(r, "State", default="") or "").upper()
            if state not in ("LISTEN", "LISTENING"):
                continue
            proc = str(get_field(r, "Process", default="") or "")
            port = get_field(r, "SrcPort", "Port")
            if _is_proxy_process(proc, pack):
                proxy_listen.append(f"{proc} 监听本地端口 {port}")
            else:
                other_listen += 1
        if proxy_listen:
            found_any = True
            score = max(score, 0.8)
            res.independent_sources = max(res.independent_sources, 2)
            evidence.append(f"★ 代理进程存在本地监听（异常面）：{proxy_listen[0]}")
            if len(proxy_listen) > 1:
                evidence.append(f"另有 {len(proxy_listen) - 1} 个代理进程监听端口")
        elif other_listen:
            evidence.append(f"存在 {other_listen} 个非代理进程的监听套接字（属正常系统行为，不计分）")

        # ---- ④ 降级与缺口 ----
        if not proxy_rows:
            res.gaps.append(self.gap(
                "注册表代理配置", "未取得 Internet Settings 键（系统级/用户级代理未覆盖）",
                impact="downgrade", level_cap="B",
                suggestion="执行带代理注册表收获的取证收集，或在目标机上只读读取 "
                           "HKLM/HKU 的 Internet Settings 键。"))
        if "mprocfs.netdns%" in missing:
            res.gaps.append(self.gap(
                "DNS 缓存", "缺少 DNS 缓存产物，域名解析异常面未覆盖",
                impact="downgrade", level_cap="B",
                suggestion="补齐 mprocfs.netdns 产物。"))
        if "mprocfs.net%" in missing:
            res.gaps.append(self.gap(
                "网络连接表", "缺少连接表产物，进程网络行为面未覆盖",
                impact="downgrade", level_cap="B",
                suggestion="补齐 mprocfs.net 产物。"))

        # ---- ④b 明确未覆盖的面（方案：不得假装判过）----
        res.findings.append("未覆盖：浏览器独立配置（需先 dump 浏览器 Profile 文件）、"
                            "虚拟网卡适配器信息与完整路由表（内存镜像不含）")

        if not found_any:
            res.state = "not_found"
            res.score = 0.0
            res.findings.append("未发现任何代理配置面有有效设置")
            return res

        res.score = min(1.0, score)
        res.state = "established" if res.score >= 0.5 else "not_found"
        res.independent_sources = max(res.independent_sources, 2 if proxy_rows else 1)
        res.findings.extend(evidence[:12])
        res.evidence_refs.extend(refs[:30])
        return res
