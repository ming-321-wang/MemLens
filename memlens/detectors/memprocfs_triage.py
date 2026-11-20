r"""
MemLens · 检测器：MemProcFS 产物的取证推理

为什么单独一个检测器：MemProcFS 与 Volatility 的**数据形态完全不同**
（前者是 process.csv / net.csv / findevil.csv + 注册表虚拟 FS，后者是 pslist/netscan 表），
所以判定逻辑要按它自己的字段写，不能复用 windows.* 的规则。

判定原则（避免"一堆废话发现项"）：
  * 只报**有证据**的：每条发现项都带具体 PID / 进程名 / 路径 / 连接五元组；
  * 多源加权：同一进程同时被 findevil、可疑路径、可疑外连命中 → 置信度叠加；
  * 白名单只降置信度、不过滤（攻击者最爱伪装成 svchost.exe）；
  * 该说的也要说：例如"注册表 hive 已收获，可离线解凭据"这种**行动建议**，
    对用户来说比一条假阳性有价值得多。
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from memlens.detectors.base import (
    Detection,
    DetectionContext,
    Detector,
    get_field,
    is_whitelisted,
    register,
    truncate,
)

#: 典型的"非系统"落地目录（攻击者放工具/木马的地方）
_SUSPICIOUS_PATH_RE = re.compile(
    r"(\\Temp\\|\\tmp\\|\\AppData\\|\\Users\\Public\\|\\Downloads\\|\\Desktop\\|"
    r"\\ProgramData\\|\\Windows\\Tasks\\|\\Recycle|\\PerfLogs\\|\\$Recycle)",
    re.IGNORECASE,
)
#: **强可疑目录**：这些目录里出现"进程映像"本身就是高危信号。
#: 为什么与 _SUSPICIOUS_PATH_RE 分开：AppData / ProgramData 里住着绝大多数正常软件
#: （OneDrive / Edge / Defender / Chrome…），实测 8 GB 真实镜像里把 AppData 当可疑
#: 会把 Defender、OneDrive 全判成"可疑进程" —— **误报比漏报更伤**。
_STRONG_PATH_RE = re.compile(
    r"(\\Desktop\\|\\Downloads\\|\\Users\\Public\\|\\Public\\|\\Temp\\|\\tmp\\|"
    r"\\PerfLogs\\|\\Windows\\Tasks\\|\\Startup\\)",
    re.IGNORECASE,
)
#: 已知的攻防工具/后门常见文件名（CTF 与应急里都是高频信号）
_TOOL_NAME_RE = re.compile(
    r"(antsword|behinder|冰蝎|godzilla|哥斯拉|mimikatz|mimilib|procdump|pwdump|"
    r"wce\.exe|fgdump|nc\.exe|ncat|socat|frp[cs]?|ngrok|chisel|venom|"
    r"cobalt|beacon|meterpreter|shellcode|webshell|evil|hack|backdoor|"
    r"psexec|wmic\.exe.*/node|rundll32.*javascript)",
    re.IGNORECASE,
)
#: 监听/外连里不算"可疑"的地址
_LOCAL_NET = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("0.0.0.0/8"),
)


def _is_external(addr: str) -> bool:
    addr = (addr or "").strip()
    if not addr or addr in ("***", "::", "*"):
        return False
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return False          # 主机名（罕见）：不臆断
    if ip.version == 6:
        return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)
    return not any(ip in net for net in _LOCAL_NET)


#: findevil 的 Description 里抽模块路径：`Module:[\??\C:\Users\a\Desktop\xxx.sys]` 与 `Image ---wxc \path\a.dll`
_MODULE_PATH_RE = re.compile(r"Module:\[\?\?\\([^\]]+)\]")
_ANY_PATH_RE = re.compile(r"((?:[A-Za-z]:\\|\\)[^\s\"',]{3,260}?\.(?:dll|sys|exe))", re.IGNORECASE)
#: 用户可写目录
_USER_WRITABLE_RE = re.compile(
    r"(\\users\\|\\desktop\\|\\downloads\\|\\temp\\|\\appdata\\|\\programdata\\|"
    r"\\public\\|\\perflogs\\)", re.IGNORECASE)
#: 系统目录
_SYSTEM_DIR_RE = re.compile(r"(\\windows\\system32\\|\\driver\\|\\windows\\syswow64\\)", re.IGNORECASE)
#: 出现在系统目录里、但**不像 Windows 自带组件**的文件名特征（伪装 DLL）
_FAKE_DLL_RE = re.compile(
    r"(assets|helper|hook|inject|loader|crypt|password|passwd|vault|steal|"
    r"keylog|update|upd_|svc_|svc[0-9]|tmp|cache|drv)", re.IGNORECASE)


def _paths_from_description(desc: str) -> list[str]:
    """从 findevil 的 Description 里抽出所有模块/文件路径（去重、保持原样）。"""
    out: list[str] = []
    m = _MODULE_PATH_RE.search(desc or "")
    if m:
        out.append(m.group(1).strip())
    for mm in _ANY_PATH_RE.finditer(desc or ""):
        p = mm.group(1).strip()
        if p and p not in out:
            out.append(p)
    return out


#: findevil 的 Type → (严重度, 置信度)。
#: 依据实测（强网杯 8 GB 转储，41 行 findevil）：
#:   * HIGH_ENTROPY / PRIVATE_RWX = 真信号（注入、加壳、可写可执行私有页）
#:   * PE_PATCHED = 正常软件也在报（Edge/OneDrive 都有）→ 降级
#:   * PRIVATE_RX / THREAD = 绝大多数是正常行为 → 降级
#:   * DRIVER_PATH / PROC_DEBUG → 单独规则处理（见 _check_module_paths）
_TYPE_RANK: dict[str, tuple[str, float]] = {
    "HIGH_ENTROPY": ("high", 0.82),
    "PRIVATE_RWX": ("high", 0.80),
    "PRIVATE_RX": ("low", 0.35),
    "PRIVATE_RO": ("low", 0.30),
    "PE_PATCHED": ("medium", 0.50),
    "THREAD": ("low", 0.30),
    "DRIVER_PATH": ("medium", 0.55),
    "PROC_DEBUG": ("medium", 0.60),
}


@register
class MemProcFSTriage(Detector):
    """MemProcFS 综合研判：异常内存、可疑进程、外连、持久化、凭据可用性。"""

    name = "memprocfs_triage"
    display = "MemProcFS 综合研判"
    #: 只要跑过 MemProcFS 的进程表就能研判；其余产物缺了不影响主流程
    needs = ("mprocfs.process%",)
    default_severity = "medium"

    # ------------------------------------------------------------------ 入口
    def run(self, ctx: DetectionContext) -> list[Detection]:
        out: list[Detection] = []
        suspicious_pids: dict[str, set[str]] = {}      # pid -> 命中的理由
        suspicious_names: dict[str, set[str]] = {}

        def _mark(pid: str, name: str, reason: str) -> None:
            if pid:
                suspicious_pids.setdefault(pid, set()).add(reason)
            if name:
                suspicious_names.setdefault(name.lower(), set()).add(reason)

        out += self._check_findevil(ctx, _mark)
        out += self._check_module_paths(ctx, _mark)
        out += self._check_drivers(ctx)
        out += self._check_processes(ctx, _mark)
        out += self._check_network(ctx, suspicious_pids, suspicious_names)
        out += self._check_unloaded(ctx, _mark)
        out += self._check_services(ctx)
        out += self._check_yara(ctx)
        out += self._check_persistence(ctx)
        out += self._check_credentials(ctx)
        out += self._correlate(suspicious_pids, suspicious_names)
        return out

    # ------------------------------------------------------------------ 1 异常内存
    def _check_findevil(self, ctx: DetectionContext, mark) -> list[Detection]:
        """findevil：MemProcFS 内建异常检测（高熵可执行页 = 注入/加壳马）。"""
        rows = ctx.records("mprocfs.findevil%")
        out: list[Detection] = []
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for rec in rows:
            pid = str(get_field(rec, "PID", default="") or "")
            name = str(get_field(rec, "ProcessName", "Name", default="") or "")
            grouped.setdefault((pid, name), []).append(rec)

        for (pid, name), items in grouped.items():
            types = sorted({str(get_field(r, "Type", default="")) for r in items})
            # **按类型分级**（实测：8 GB 真实镜像里 findevil 有 41 行，若一律 HIGH，
            #   Edge/OneDrive/smartscreen 的正常 PE 异常会把真信号淹掉 —— 实测 34 条发现项里
            #   22 条 HIGH 有一大半是噪音，用户根本看不到真正的驱动加载路径那条）
            sev, conf = "medium", 0.6
            worst = ""
            for t in types:
                s, c = _TYPE_RANK.get(t.upper(), ("medium", 0.55))
                if c > conf:
                    sev, conf, worst = s, c, t
            if is_whitelisted(name):
                # 白名单进程也可能被注入（sppsvc 加壳内存很常见）→ 降分但不忽略
                conf = min(conf, 0.6)
                if sev == "high":
                    sev = "medium"
            out.append(Detection(
                title=f"异常内存：{name or '(未知进程)'}"
                      + (f"（PID {pid}）" if pid else "")
                      + f" — {', '.join(t for t in types if t)}",
                description=(
                    "MemProcFS 异常检测在这些进程的内存里发现了非镜像页/高熵可执行段，"
                    "常见于进程注入、加壳木马与内存马。需要用 memlens.dump_process 把该进程"
                    "内存导出来做字符串与静态分析。"),
                severity=sev,
                confidence=conf,
                sources=["mprocfs.findevil"],
                evidence={
                    "pid": pid, "process": name,
                    "types": types,
                    "details": [truncate(get_field(r, "Description", "说明", default=""), 200)
                                for r in items[:6]],
                    "地址": [str(get_field(r, "Address", default="")) for r in items[:6]],
                },
                rule_id="memprocfs.findevil",
            ))
            mark(pid, name, "findevil 异常内存")
        return out

    # ------------------------------------------------------------------ 2 进程
    def _check_processes(self, ctx: DetectionContext, mark) -> list[Detection]:
        """可疑进程：非白名单 + 可疑路径/工具名/无镜像路径。"""
        rows = ctx.records("mprocfs.process%")
        out: list[Detection] = []
        for rec in rows:
            pid = str(get_field(rec, "PID", default="") or "")
            name = str(get_field(rec, "Name", "ShortName", default="") or "")
            user = str(get_field(rec, "User", default="") or "")
            cmd = str(get_field(rec, "CommandLine", "CmdLine", default="") or "")
            upath = str(get_field(rec, "UserPath", "Path", default="") or "")
            kpath = str(get_field(rec, "KernelPath", default="") or "")
            created = str(get_field(rec, "CreateTime", default="") or "")
            reasons: list[str] = []
            strong = False
            if _TOOL_NAME_RE.search(name) or _TOOL_NAME_RE.search(cmd):
                reasons.append("进程名/命令行命中已知工具特征")
                strong = True
            if _STRONG_PATH_RE.search(upath):
                reasons.append("从强可疑目录（桌面/下载/公开/Temp）运行")
                strong = True
            elif _SUSPICIOUS_PATH_RE.search(upath):
                # AppData/ProgramData 只算"弱信号"，单独出现不报（正常软件都住这儿）
                reasons.append("从用户应用数据目录运行（需结合其它证据）")
            if not upath and not kpath and not is_whitelisted(name):
                reasons.append("无镜像路径（可能已卸载/内存加载）")
            if not reasons or (not strong and len(reasons) == 1 and
                               reasons[0].startswith("从用户应用数据目录")):
                continue
            sev = "high" if (strong and len(reasons) > 1) or (strong and not is_whitelisted(name)) \
                else ("medium" if strong else "low")
            conf = min(0.9, 0.55 + 0.18 * len(reasons)) if strong else 0.4
            out.append(Detection(
                title=f"可疑进程：{name or '(未知)'}（PID {pid}）",
                description="；".join(reasons) + "。",
                severity=sev,
                confidence=conf,
                sources=["mprocfs.process"],
                evidence={
                    "pid": pid, "process": name, "user": user,
                    "命令行": truncate(cmd, 300), "用户态路径": upath, "内核路径": kpath,
                    "创建时间": created, "理由": reasons,
                },
                rule_id="memprocfs.suspicious_process",
            ))
            mark(pid, name, "可疑进程路径/名称")
        return out

    # ------------------------------------------------------------------ 3 网络
    def _check_network(
        self,
        ctx: DetectionContext,
        suspicious_pids: dict[str, set[str]],
        suspicious_names: dict[str, set[str]],
    ) -> list[Detection]:
        """外连：只报"外部地址 + 已建立/监听"这类真信号。"""
        rows = ctx.records("mprocfs.net%")
        out: list[Detection] = []
        seen: set[tuple[str, str, str]] = set()
        for rec in rows:
            proto = str(get_field(rec, "Proto", default="") or "")
            state = str(get_field(rec, "State", default="") or "").upper()
            dst = str(get_field(rec, "DstAddr", default="") or "")
            dport = str(get_field(rec, "DstPort", default="") or "")
            src = str(get_field(rec, "SrcAddr", default="") or "")
            sport = str(get_field(rec, "SrcPort", default="") or "")
            pid = str(get_field(rec, "PID", default="") or "")
            pname = str(get_field(rec, "Process", "ProcessName", default="") or "")
            ppath = str(get_field(rec, "ProcessPath", default="") or "")
            if state not in ("ESTABLISHED", "SYN_SENT", "LISTENING", "UDP"):
                continue
            external = _is_external(dst) or _is_external(src)
            if not external:
                continue
            key = (dst or src, dport or sport, f"{pname}:{pid}")
            if key in seen:
                continue
            seen.add(key)
            known_bad = (pid in suspicious_pids
                         or pname.lower() in suspicious_names
                         or bool(_TOOL_NAME_RE.search(pname))
                         or bool(_SUSPICIOUS_PATH_RE.search(ppath)))
            # 高位端口监听 + 用户可写目录路径 = 后门监听，是最该报的
            listening_odd = state == "LISTENING" and (dport or sport or "").isdigit() \
                and int(dport or sport or 0) > 1024 and bool(ppath) and known_bad
            if not (known_bad or listening_odd or state == "ESTABLISHED"):
                continue
            conf = 0.5
            sev = "low"
            if known_bad:
                conf, sev = 0.78, "high"
            elif state == "ESTABLISHED":
                conf, sev = 0.6, "medium"
            out.append(Detection(
                title=f"网络外连：{pname or '未知进程'} → {dst or src}:{dport or sport}"
                      + (f"（PID {pid}）" if pid else ""),
                description=(
                    f"{proto} {state} 连接指向非内网地址"
                    + ("；该进程同时被其它规则标记为可疑" if known_bad else "") + "。"),
                severity=sev,
                confidence=conf,
                sources=["mprocfs.net"],
                evidence={
                    "proto": proto, "state": state,
                    "五元组": f"{src}:{sport} → {dst}:{dport}",
                    "pid": pid, "process": pname, "process_path": ppath,
                },
                rule_id="memprocfs.external_connection",
            ))
        return out

    # ------------------------------------------------------------------ 4 无文件模块
    def _check_unloaded(self, ctx: DetectionContext, mark) -> list[Detection]:
        rows = ctx.records("mprocfs.unloaded_modules%")
        out: list[Detection] = []
        for rec in rows[:40]:
            name = str(get_field(rec, "ModuleName", "Name", default="") or "")
            pname = str(get_field(rec, "Process", default="") or "")
            pid = str(get_field(rec, "PID", default="") or "")
            path = str(get_field(rec, "Path", default="") or "")
            if not name:
                continue
            if is_whitelisted(pname) and ".sys" in name.lower():
                continue          # 系统进程卸载驱动是常态
            if not (_SUSPICIOUS_PATH_RE.search(path) or not is_whitelisted(pname)):
                continue
            out.append(Detection(
                title=f"已卸载模块：{name}（进程 {pname} / PID {pid}）",
                description="模块已从加载链卸载但内存痕迹还在，常见于无文件加载、反射式 DLL 注入。",
                severity="medium", confidence=0.6,
                sources=["mprocfs.unloaded_modules"],
                evidence={"pid": pid, "process": pname, "module": name, "path": path},
                rule_id="memprocfs.unloaded_module",
            ))
            mark(pid, pname, "无文件模块")
        return out

    # ------------------------------------------------------------------ 5 服务
    def _check_services(self, ctx: DetectionContext) -> list[Detection]:
        rows = ctx.records("mprocfs.services%")
        out: list[Detection] = []
        for rec in rows:
            name = str(get_field(rec, "ServiceName", default="") or "")
            disp = str(get_field(rec, "DisplayName", default="") or "")
            path = str(get_field(rec, "ImagePath", "DriverpathOrCmdline", default="") or "")
            start = str(get_field(rec, "StartType", default="") or "")
            if not path:
                continue
            if _STRONG_PATH_RE.search(path) or re.search(
                    r"(cmd(\.exe)?\s+/c|powershell|rundll32|regsvr32|mshta|wscript|cscript)",
                    path, re.IGNORECASE):
                out.append(Detection(
                    title=f"可疑服务：{name or disp} — 镜像路径异常",
                    description="服务指向用户可写目录或由脚本宿主拉起，是常见的持久化与提权手法。",
                    severity="high", confidence=0.75,
                    sources=["mprocfs.services"],
                    evidence={"service": name, "display": disp,
                              "image_path": truncate(path, 300), "start": start},
                    rule_id="memprocfs.suspicious_service",
                ))
            elif path and not path.lower().startswith(("\\systemroot", "c:\\windows",
                                                      "%systemroot%", "system32")):
                # 非系统目录的服务：值得记一笔但不重判
                out.append(Detection(
                    title=f"非系统目录的驱动/服务：{name or disp}",
                    description="服务可执行体不在系统目录，建议核对数字签名与来源。",
                    severity="low", confidence=0.45,
                    sources=["mprocfs.services"],
                    evidence={"service": name, "image_path": truncate(path, 300)},
                    rule_id="memprocfs.nonstandard_service_path",
                ))
            if len(out) >= 40:
                break
        return out

    # ------------------------------------------------------------------ 6 YARA
    def _check_yara(self, ctx: DetectionContext) -> list[Detection]:
        rows = ctx.records("mprocfs.yara%")
        out: list[Detection] = []
        for rec in rows:
            rule = str(get_field(rec, "Tags", "Description", "RuleAuthor", default="") or "")
            pid = str(get_field(rec, "PID", default="") or "")
            pname = str(get_field(rec, "ProcessName", "Process", default="") or "")
            strings = [str(get_field(rec, f"String{i}", default="") or "") for i in range(5)]
            out.append(Detection(
                title=f"YARA 命中：{rule or '未命名规则'}"
                      + (f"（{pname} / PID {pid}）" if pname or pid else ""),
                description="MemProcFS 内建 YARA 规则在内存中命中特征串。",
                severity="high", confidence=0.8,
                sources=["mprocfs.yara"],
                evidence={"rule": rule, "pid": pid, "process": pname,
                          "命中字符串": [s for s in strings if s]},
                rule_id="memprocfs.yara_match",
            ))
        return out

    # ------------------------------------------------------------------ 7 持久化
    def _check_persistence(self, ctx: DetectionContext) -> list[Detection]:
        rows = ctx.records("mprocfs.registry_run%")
        out: list[Detection] = []
        for rec in rows:
            key = str(get_field(rec, "注册表键", "Key", default="") or "")
            name = str(get_field(rec, "名称", "Name", default="") or "")
            data = str(get_field(rec, "数据", "Data", "Value", default="") or "")
            if not (name or data):
                continue
            risk = bool(_SUSPICIOUS_PATH_RE.search(data) or _TOOL_NAME_RE.search(data))
            out.append(Detection(
                title=f"自启动项：{name} → {truncate(data, 90)}",
                description=("该自启动项指向用户可写目录或已知工具，高度可疑。"
                             if risk else "系统或软件的正常自启动项，请与基线核对。"),
                severity="high" if risk else "low",
                confidence=0.75 if risk else 0.35,
                sources=["mprocfs.registry_run"],
                evidence={"key": key, "name": name, "data": truncate(data, 500)},
                rule_id="memprocfs.autorun",
            ))
        return out

    # ------------------------------------------------------------------ 8 凭据可用性
    def _check_credentials(self, ctx: DetectionContext) -> list[Detection]:
        """把"能离线解凭据"这件事明确告诉用户（否则他永远想不到还能这么干）。"""
        hives = ctx.records("mprocfs.registry_hives%")
        if not hives:
            return []
        names = [str(get_field(r, "配置单元", "Name", default="") or "") for r in hives]
        hits = [n for n in names
                if re.search(r"(SAM|SYSTEM|SECURITY|NTUSER)", n or "", re.IGNORECASE)]
        if not hits:
            return []
        return [Detection(
            title=f"注册表配置单元已收获（{len(hits)} 个可解凭据的 hive）",
            description=(
                "内存里抓到了 SAM/SYSTEM/SECURITY（或用户 NTUSER）配置单元。"
                "用它们可以离线导出本地账户口令哈希 / LSA 机密 / 最近访问痕迹 —— "
                "这是 CTF 内存取证与应急响应里最常出分的环节。\n"
                "MemLens 已把它们复制到会话目录的 harvest/registry_hives/ 下。"),
            severity="medium", confidence=0.9,
            sources=["mprocfs.registry_hives"],
            evidence={"hives": hits[:20], "数量": len(names)},
            rule_id="memprocfs.hives_available",
        )]

    # ------------------------------------------------------------------ 9 关联
    def _correlate(
        self,
        suspicious_pids: dict[str, set[str]],
        suspicious_names: dict[str, set[str]],
    ) -> list[Detection]:
        """同一进程被多类规则命中 → 单独给一条"重点对象"。"""
        out: list[Detection] = []
        for name, reasons in suspicious_names.items():
            if len(reasons) < 3:
                continue
            pids = [p for p, rs in suspicious_pids.items() if reasons & rs]
            out.append(Detection(
                title=f"重点排查对象：{name}（同时命中 {len(reasons)} 类规则）",
                description="该进程被多类独立规则命中（异常内存/可疑路径/外连/无文件模块），"
                            "建议优先导出其内存与命令行做深入分析。",
                severity="high", confidence=0.88,
                sources=["mprocfs.findevil", "mprocfs.process", "mprocfs.net",
                         "mprocfs.unloaded_modules"],
                evidence={"process": name, "理由": sorted(reasons), "pid": pids[:8]},
                rule_id="memprocfs.multi_signal",
            ))
        return out

    # ------------------------------------------------------- 10 模块路径 / 驱动
    def _check_module_paths(self, ctx: DetectionContext, mark) -> list[Detection]:
        """
        从 findevil 的 Description 里抽出**模块路径**并按危险度分级。

        实测依据（强网杯 Personal Vault 的 8 GB 内核转储）：
        `findevil.csv` 里出现了
        `4,System,DRIVER_PATH,... Driver:[test] Module:[\\??\\C:\\Users\\a\\Desktop\\personalVaultKernel.sys]`
        与 `2200,svchost.exe,HIGH_ENTROPY,... \\Windows\\System32\\whesvc_assets.dll`
        —— **驱动从用户桌面加载**、**System32 里出现来路不明的 DLL**，
        这两条才是本题真正的入口，光报"高熵内存"等于没报。
        """
        rows = ctx.records("mprocfs.findevil%")
        out: list[Detection] = []
        for rec in rows:
            pid = str(get_field(rec, "PID", default="") or "")
            name = str(get_field(rec, "ProcessName", "Name", default="") or "")
            rtype = str(get_field(rec, "Type", default="") or "").upper()
            desc = str(get_field(rec, "Description", "说明", default="") or "")
            paths = _paths_from_description(desc)
            if not paths:
                continue

            # ---- 规则 A：驱动 / 模块从用户可写目录加载 → HIGH ----
            bad = [p for p in paths if _USER_WRITABLE_RE.search(p)]
            if bad or rtype == "DRIVER_PATH":
                target = bad[0] if bad else (paths[0] if paths else "")
                sev, conf = "high", 0.9
                if rtype == "DRIVER_PATH" and not bad:
                    sev, conf = "medium", 0.6
                out.append(Detection(
                    title=f"可疑模块加载路径：{Path(target).name or target}",
                    description=(
                        "该模块/驱动从**用户可写目录**加载（桌面/下载/Temp/AppData）。"
                        "这是 rootkit、挖矿木马、凭据窃取器的典型落地方式；"
                        "建议 dump 该进程内存并查它的导出函数与驱动入口。"),
                    severity=sev, confidence=conf,
                    sources=["mprocfs.findevil"],
                    evidence={"pid": pid, "process": name, "type": rtype,
                              "模块路径": target, "全部路径": paths,
                              "描述": truncate(desc, 300)},
                    rule_id="memprocfs.user_writable_module",
                ))
                mark(pid, name, "模块从用户目录加载")
                continue

            # ---- 规则 B：HIGH_ENTROPY + 系统目录里的"陌生"DLL → 伪装 DLL ----
            if rtype == "HIGH_ENTROPY":
                dll = next((p for p in paths if p.lower().endswith((".dll", ".sys", ".exe"))), "")
                if dll and _SYSTEM_DIR_RE.search(dll) and _FAKE_DLL_RE.search(dll):
                    out.append(Detection(
                        title=f"疑似伪装 DLL：{Path(dll).name} 出现在系统目录",
                        description=(
                            f"该 DLL 位于 {Path(dll).parent}（系统目录），但文件名不像"
                            f"Windows 自带组件（{Path(dll).name}）→ 极可能是伪装成系统组件的"
                            "木马 DLL。把它 dump 出来做导入表/字符串分析即可确认。"),
                        severity="high", confidence=0.82,
                        sources=["mprocfs.findevil"],
                        evidence={"pid": pid, "process": name, "dll": dll,
                                  "描述": truncate(desc, 300)},
                        rule_id="memprocfs.masquerade_dll",
                    ))
                    mark(pid, name, "伪装 DLL")
                continue

            # ---- 规则 C：进程处于被调试状态 ----
            if rtype == "PROC_DEBUG":
                out.append(Detection(
                    title=f"进程被调试：{name or '(未知)'}（PID {pid}）",
                    description="该进程处于被调试状态（PROC_DEBUG）："
                                "可能是反调试对抗、注入器/调试器自身，或勒索软件的自检逻辑。",
                    severity="medium", confidence=0.7,
                    sources=["mprocfs.findevil"],
                    evidence={"pid": pid, "process": name, "描述": truncate(desc, 200)},
                    rule_id="memprocfs.proc_debug",
                ))
                mark(pid, name, "被调试进程")
        return out

    # ------------------------------------------------------------------ 11 驱动
    def _check_drivers(self, ctx: DetectionContext) -> list[Detection]:
        """drivers.csv：驱动镜像路径不在系统驱动目录 → 高度可疑。"""
        rows = ctx.records("mprocfs.drivers%")
        out: list[Detection] = []
        for rec in rows[:80]:
            name = str(get_field(rec, "DriverName", "Name", default="") or "")
            path = str(get_field(rec, "DriverPath", default="") or "")
            if not path:
                continue
            if _SYSTEM_DIR_RE.search(path) or path.lower().startswith(("system32", "\\driver")):
                continue
            out.append(Detection(
                title=f"驱动加载自非系统路径：{name or path}",
                description="驱动映像不在 \\Windows\\System32\\drivers 下，"
                            "属于用户可写位置加载的驱动（rootkit 常用手法）。",
                severity="high", confidence=0.85,
                sources=["mprocfs.drivers"],
                evidence={"driver": name, "path": path,
                          "服务键": str(get_field(rec, "ServiceKey", default=""))},
                rule_id="memprocfs.driver_path",
            ))
        return out
