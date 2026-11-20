r"""
MemLens · 取证知识库

定位：**「我看到这个现象，说明什么，下一步查哪里」**。

与"每个插件配一段说明书"的区别（那只是帮助文档）：
  * 条目按 **征象 → 结论 → 下一步** 三段式组织，征象是可检索的关键词集合；
  * `match()` 会拿**案件里真实产出的记录**去检索，把当前这份证据"说得通"的条目挑出来；
  * 同一个征象可能有多种解释，条目会写明各自的**区分方法**（交叉验证怎么做）。

所以它不是"读手册"，而是"看结果时自动递给你该想的那句话"。
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Iterable, Sequence


@dataclasses.dataclass(frozen=True)
class Knowledge:
    id: str
    title: str
    symptom: str            # 征象：你看到了什么
    meaning: str            # 结论：这通常说明什么
    next: tuple[str, ...]   # 下一步：接着做什么
    plugins: tuple[str, ...] = ()   # 相关插件
    keywords: tuple[str, ...] = ()  # 检索关键词
    caveat: str = ""        # 误判提醒

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "symptom": self.symptom,
            "meaning": self.meaning, "next": list(self.next),
            "plugins": list(self.plugins), "keywords": list(self.keywords),
            "caveat": self.caveat,
        }


#: 内置知识条目（内容为本项目独立编写的通用取证经验）
ENTRIES: tuple[Knowledge, ...] = (
    Knowledge(
        id="hidden-process-diff",
        title="psscan 有、pslist 无：进程可能被隐藏",
        symptom="psscan 能扫到某 PID，但 pslist（活动 EPROCESS 链）里没有它；"
                 "或反之（pslist 有而 psscan 扫不到）。",
        meaning="双向差集都指向 DKOM（Direct Kernel Object Manipulation）："
                "攻击者从活动链表里摘掉了进程，但对象还在池里；"
                "反向差集更多是残留对象或扫描窗口期问题。",
        next=("跑 psxview 做多源交叉，确认隐藏性质",
              "看该 PID 是否仍有句柄、模块或网络连接（有则进程仍存活）",
              "检查 SSDT / callbacks / driverirp 是否有可疑钩子",
              "对该 PID 做 memdump，看内部线程与模块"),
        plugins=("windows.psscan", "windows.pslist", "windows.psxview",
                 "windows.handles", "windows.ssdt", "windows.callbacks"),
        keywords=("psscan", "pslist", "psxview", "隐藏进程", "dkom", "摘链", "unlink"),
        caveat="仅差集不足以定案：进程正常退出时也可能只在一侧出现，必须靠 psxview 或句柄佐证。",
    ),
    Knowledge(
        id="malfind-memrwx",
        title="malfind 报出私有 RWX 区域且含 PE 头",
        symptom="malfind 发现 Private 的 RWX 页，Disassembly/PAGE 属性异常，"
                 "Region 常以 MZ/PE 或可执行代码开头。",
        meaning="高度怀疑进程内存在注入的代码（线程劫持、反射加载或 payload 落地）。",
        next=("看 mdll 分布：正常进程的 RWX 页不应出现可执行节区",
              "对照 ldrmodules，注入代码往往不在模块加载链里",
              "看 threads 是否有起止异常的线程",
              "对该 PID 做 memdump 并提取其中字符串（cmdline/URL/flag）"),
        plugins=("windows.malfind", "windows.ldrmodules", "windows.threads",
                 "windows.memmap", "windows.vadinfo"),
        keywords=("malfind", "rwx", "injection", "注入", "mz", "pe头"),
        caveat="JIT、浏览器、.NET 运行时会产生合法 RWX 区；必须结合「不在模块链里」这一点才能定性。",
    ),
    Knowledge(
        id="netscan-public",
        title="存在公网 IP 的外联连接",
        symptom="netscan/netstat 中出现 scope=公网 的远端地址，且连接状态非 LISTEN。",
        meaning="该机器曾主动向外通信，可能是 C2 回连、漏洞利用或数据外传。",
        next=("按 PID 关联出进程，拿到 cmdline 判断是什么程序发起",
              "把该 IP 与情报词典/威胁库比对",
              "看是否有大量周期性短连接（典型 beacon 心跳）",
              "查对应时间点的 DNS 记录，确认是否域名解析后直连"),
        plugins=("windows.netscan", "windows.netstat", "windows.cmdline",
                 "windows.pstree", "banners.DnsCache"),
        keywords=("netscan", "netstat", "公网", "外联", "c2", "beacon", "remote"),
        caveat="浏览器、系统更新、Defender 云查杀都会产生公网外联，务必先看发起进程再下结论。",
    ),
    Knowledge(
        id="unloaded-module",
        title="已卸载模块/驱动里有可疑文件",
        symptom="unloadedmodules 或 modscan 出现路径在临时目录、用户可写目录的模块。",
        meaning="动态加载后又卸载是隐藏手法；路径可写意味着攻击者已经取得落地能力。",
        next=("核对该路径是否在 %TEMP% / %APPDATA% / C:\\Users 下",
              "在文件对象里找同名残留（filescan）",
              "检查对应驱动的 IRP 表（driverirp）是否被钩"),
        plugins=("windows.unloadedmodules", "windows.modscan", "windows.filescan",
                 "windows.driverirp"),
        keywords=("unloaded", "卸载", "modscan", "driverirp", "临时目录"),
    ),
    Knowledge(
        id="run-key-persistence",
        title="注册表 Run 键指向非常规路径",
        symptom=r"printkey / registry.* 里 CurrentVersion\Run 的值指向 %TEMP%、"
                r"用户目录，或指向非预期可执行文件。",
        meaning="自启动持久化，且程序路径可写——说明攻击者已有落地文件。",
        next=("取出目标文件路径与创建时间",
              "确认是哪个用户的 hive（HKU\\S-1-5-21-...）",
              "在 filescan 里找该文件是否还在内存中",
              "同时检查 RunOnce / Winlogon\\Userinit / AppInit_DLLs / IFEO"),
        plugins=("windows.registry.printkey", "windows.registry.hivelist",
                 "windows.filescan"),
        keywords=("run", "runonce", "userinit", "appinit_dlls", "ifeo", "自启", "持久化"),
    ),
    Knowledge(
        id="cred-material",
        title="存在凭据材料（SAM/LSA/域缓存）",
        symptom="lsadump / hashdump / cachedump 产出了非空结果，或发现 mimikatz 痕迹。",
        meaning="系统内存在可被直接利用的凭据材料；若有 mimikatz 痕迹则已被导出。",
        next=("确认工具是否还在运行、是否有落盘副本",
              "检查是否有对应的横向连接（445/3389/5985）",
              "评估受影响账号范围并走应急轮换流程"),
        plugins=("windows.hashdump", "windows.lsadump", "windows.cachedump",
                 "windows.cmdline"),
        keywords=("hashdump", "lsadump", "cachedump", "mimikatz", "凭据", "sekurlsa"),
        caveat="报告与导出物都应按敏感信息处理，不要把明文凭据写进公开报告。",
    ),
    Knowledge(
        id="cmdline-offensive",
        title="命令行出现编码/混淆执行",
        symptom="cmdline 或 consoles 里出现 powershell -enc/-e、-exec bypass、"
                 "FromBase64String、DownloadString 等。",
        meaning="PowerShell 免杀执行，命令行里就是执行体本身。",
        next=("对 -enc 后内容做 Base64 解码，得到真实命令",
              "把解出的 URL/域名提取为 IOC",
              "看是否有对应文件落地（filescan）",
              "查该 PowerShell 进程的子进程树"),
        plugins=("windows.cmdline", "windows.consoles", "windows.clipboard", "windows.pstree"),
        keywords=("powershell", "-enc", "encodedcommand", "bypass", "base64", "混淆"),
    ),
    Knowledge(
        id="timestomp",
        title="时间戳互相矛盾",
        symptom="同一目录内文件时间跨度异常（有远早于同批文件的，也有远晚于的）。",
        meaning="可能存在时间戳篡改（timestomp），或文件来自复制/迁移。",
        next=("按 MFT/目录结构分组比较时间簇",
              "检查是否有大量文件时间被设为同一时刻",
              "与镜像采集时间、系统当前时间对比"),
        plugins=("windows.filescan", "windows.statistics"),
        keywords=("timestomp", "时间戳", "mft", "篡改"),
        caveat="单条时间异常不足以定性；复制与归档同样会打乱时间簇。",
    ),
    Knowledge(
        id="linux-hidden",
        title="Linux：进程在 /proc 有残留但不在 task 链表",
        symptom="linux.pslist 缺进程，但 bash / proc / elfs 插件仍能取到其痕迹。",
        meaning="Linux 侧的进程隐藏（内核模块摘链或用户态挂载伪造）。",
        next=("跑 linux.check_modules / linux.check_ftrace 等内核完整性插件",
              "检查是否有自定义内核模块",
              "核对 mounts 与真实根文件系统是否一致"),
        plugins=("linux.pslist", "linux.bash", "linux.proc", "linux.check_modules"),
        keywords=("linux", "隐藏", "modules", "ftrace", "pslist"),
    ),
    Knowledge(
        id="flag-in-memory",
        title="镜像里直接存在 flag",
        symptom="memstrings.flag 命中，decoded 列给出明文。",
        meaning="题目把答案放在内存里，通常藏在进程环境变量、命令行、剪贴板或文件内容中。",
        next=("按 offset 反查落在哪个进程/区域",
              "用 hit 的偏移去 windows.memmap 定位来源",
              "若为 UTF-16LE 命中，说明是宽字符 API（注册表/路径）写入的"),
        plugins=("memstrings.flag", "windows.memmap", "windows.filescan", "windows.envars"),
        keywords=("flag", "内存", "strings"),
    ),
)


# ------------------------------------------------------------------ 检索


class KnowledgeBase:
    """知识库检索器。"""

    def __init__(self, entries: Sequence[Knowledge] | None = None) -> None:
        self.entries: list[Knowledge] = list(entries if entries is not None else ENTRIES)
        self._index: list[tuple[Knowledge, list[re.Pattern[str]]]] = []
        for e in self.entries:
            pats = [re.compile(re.escape(k), re.IGNORECASE) for k in e.keywords]
            self._index.append((e, pats))

    def get(self, entry_id: str) -> Knowledge | None:
        for e in self.entries:
            if e.id == entry_id:
                return e
        return None

    def search(self, keyword: str) -> list[Knowledge]:
        """按关键词搜知识条目。"""
        kw = keyword.strip().lower()
        if not kw:
            return list(self.entries)
        out = []
        for e in self.entries:
            hay = f"{e.title} {e.symptom} {e.meaning} {' '.join(e.next)} {' '.join(e.keywords)}".lower()
            if kw in hay:
                out.append(e)
        return out

    def match_text(self, text: str) -> list[tuple[Knowledge, list[str]]]:
        """在一段文本里找出被命中的知识条目。"""
        if not text:
            return []
        low = text.lower()
        hits: list[tuple[Knowledge, list[str]]] = []
        for entry, pats in self._index:
            matched = [kw for kw, p in zip(entry.keywords, pats) if p.search(low)]
            if matched:
                hits.append((entry, matched))
        return hits

    def match_artifacts(self, artifacts: Sequence[dict[str, Any]]) -> list[tuple[Knowledge, list[str]]]:
        """
        根据案件里**已跑过的插件**推荐知识条目。

        这是最实用的一种用法：插件清单本身就是"你在查什么"的声明。
        """
        hay = " ".join(
            f"{a.get('plugin','')} {a.get('category','')}" for a in artifacts
        ).lower()
        return self.match_text(hay)


_kb: KnowledgeBase | None = None


def kb() -> KnowledgeBase:
    """全局单例。"""
    global _kb
    if _kb is None:
        _kb = KnowledgeBase()
    return _kb


def describe(k: Knowledge) -> str:
    """把一条知识渲染成可读文本（报告与 CLI 共用）。"""
    lines = [f"【{k.title}】", f"  征象：{k.symptom}", f"  结论：{k.meaning}"]
    if k.next:
        lines.append("  下一步：")
        lines.extend(f"    · {n}" for n in k.next)
    if k.plugins:
        lines.append(f"  相关插件：{', '.join(k.plugins)}")
    if k.caveat:
        lines.append(f"  注意：{k.caveat}")
    return "\n".join(lines)
