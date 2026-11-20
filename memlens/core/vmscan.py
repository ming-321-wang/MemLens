r"""
MemLens · 虚拟机取证扫描（VM 资产发现 + 配置取证 + 磁盘内秘密）

## 为什么需要它（内存之外的盲区）

内存镜像只覆盖"某一时刻的 RAM"。而虚拟机的**磁盘与配置**里往往躺着更硬的证据：

| 位置 | 典型证据 |
|---|---|
| `*.vmx` / `*.vbox` / `*.vmxf`（配置） | **明文口令**（VMware Tools/共享文件夹/远程）、共享目录、剪贴板/拖放开关、guestinfo 里的备忘、串口/端口转发 |
| `*.vmem` + `*.vmss/.vmsn`（内存快照+元数据） | **整机内存**，可直接喂 MemProcFS / vol3 |
| `*.vmdk/.qcow2/.vdi/.vhdx`（磁盘） | 文件系统里的 flag、凭据、浏览器/SSH 私钥、攻击者落地脚本 |
| `*.pcap` / `*.raw` / `*.dmp`（旁证） | 流量包、崩溃转储 |

实测场景（本机）：Windows 渗透测试套件 VMware VM（含 8 GB 内存快照 + 66 GB 磁盘）、
Kali 的 QEMU 镜像、`Documents\Virtual Machines\` 下的赛题 VM —— 这些**内存之外**的
证据此前完全不在 MemLens 的射程内。

## 设计原则

* **只读**：全程只读用户文件，不挂载、不改写、不解压到原目录；
* **不执行虚拟机里的任何东西**：磁盘内容只做**字节级字符串扫描**；
* **大文件分块扫**：36 GB 的 vmdk 也不爆内存（4 MB 块 + 重叠窗口防切断）；
* **结论要给下一步**：命中后直接给出"用哪个引擎/哪条命令继续查"。
"""

from __future__ import annotations

import os
import re
import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

# ---------------------------------------------------------------- 识别规则

#: 虚拟机家族 → 特征文件后缀
VM_FAMILIES: dict[str, tuple[str, ...]] = {
    "VMware": (".vmx", ".vmss", ".vmsn", ".vmem", ".vmdk"),
    "VirtualBox": (".vbox", ".vdi", ".vbox-prev"),
    "QEMU/KVM": (".qcow2", ".qcow", ".vmdk"),
    "Hyper-V": (".vhdx", ".avhdx", ".vmrs"),
    "Parallels": (".pvm", ".hdd"),
    "VMware/ESXi": (".vmx", ".vmdk"),
}

#: VM 家族 → 用来"认领"目录的标记文件
VM_MARKERS: tuple[str, ...] = (
    ".vmx", ".vbox", ".vdi", ".qcow2", ".qcow", ".vhdx", ".pvm", ".hdd",
    ".utm", ".vmem", ".vmdk",
)

#: vmx 里**高危**的键（值里可能有明文口令/凭据/共享）
VMX_SENSITIVE_KEYS = (
    "password", "passwd", "pwd", "secret", "token", "credential", "apikey",
    "api_key", "authkey", "license", "serial", "privatekey", "passphrase",
    "clipboard", "dragdrop", "sharedfolder", "isolation", "hgfs", "guestinfo",
    "annotation", "displayname", "guestos", "ethernet0", "remotedisplay",
)
#: 值看起来像"真凭据"（排除 TRUE/FALSE/空/短数字/VMware 内部路径）
_SECRET_VALUE = re.compile(r"^[^\s].{3,}$")
_FALSEY = {"true", "false", "yes", "no", "0", "1", "none", "null", "n/a"}

#: ★ flag 候选过滤：磁盘里"flag{" 的命中绝大多数是**工具手册/二进制噪音**
#:   （实测 Kali VM 磁盘：1820 处 `flag{...}` 全是 grep/ripgrep 的命令行选项名，
#:   例如 `flag{count}`、`flag{multiline}`、`flag{unrestricted}`；
#:   另有 121 处 `ctf{...}` 是文档与二进制碎片 `cTF{ocgx2.ocg.#1}`）。
#:   ⇒ 只有"长度够 + 字符集像真 flag + 不是已知工具选项词"才升级为候选。
_FLAG_BODY = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")
_TOOL_OPTION_WORDS = frozenset("""
count multiline unrestricted only-matching pre count-matches debug files-with-matches
regexp file help version quiet no-filename text binary-files line-number recursive
include ignore word regexp fixed-strings ignore-case invert match perl-regexp
null-data with-filename after-context before-context only-matching color
""".split())


def looks_like_flag(text: str) -> bool:
    """
    判断一个 `{...}` 命中是否像**真 flag**（而不是工具选项/二进制噪音）。

    收紧依据（实测 Kali VM 磁盘，两轮降噪）：
      第 1 轮：1941 处 `flag{...}` 全是 grep/ripgrep 手册里的**选项名**（count/multiline/…）；
      第 2 轮：仍有 600 处是 **Delphi/Lazarus 二进制的 RTTI 异常类名**
              （`flag{PaintBlack}`、`Flag{DivisionByZero}`、`Flag{InvalidOperation}`）。
    ⇒ 真 CTF flag 的稳定特征：**长度 ≥10 + 必含数字 + 必含小写 + 含大写或 _/-**。
    """
    m = re.search(r"\{([^{}]{1,300})\}", text or "")
    if not m:
        return False
    body = m.group(1).strip()
    if not _FLAG_BODY.match(body):
        return False
    if body.lower() in _TOOL_OPTION_WORDS:
        return False
    if len(body) < 10:
        return False
    if not re.search(r"[0-9]", body):
        return False                     # 真 flag 几乎必带数字（异常类名不带）
    if not re.search(r"[a-z]", body):
        return False
    if not (re.search(r"[A-Z]", body) or re.search(r"[_\-]", body)):
        return False
    return True


@dataclasses.dataclass
class VMFinding:
    kind: str            # config / memory / disk / sidecar
    path: str
    detail: str
    severity: str = "info"      # info / low / medium / high / critical
    value: str = ""


@dataclasses.dataclass
class VMInfo:
    root: str
    family: str
    config: str = ""
    memory: list[str] = field(default_factory=list)
    disks: list[str] = field(default_factory=list)
    findings: list[VMFinding] = field(default_factory=list)
    sidecars: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- 扫描


def _iter_files(roots: Iterable[Path], max_depth: int = 6,
                max_files: int = 200_000) -> Iterator[Path]:
    """限深遍历（避免扫全盘）。"""
    seen = 0
    for root in roots:
        if not root.exists():
            continue
        base = len(root.parts)
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            cur, depth = stack.pop()
            if depth > max_depth:
                continue
            try:
                entries = list(os.scandir(cur))
            except (OSError, PermissionError):
                continue
            for e in entries:
                try:
                    if e.is_dir(follow_symlinks=False):
                        stack.append((Path(e.path), depth + 1))
                    elif e.is_file(follow_symlinks=False):
                        seen += 1
                        if seen > max_files:
                            return
                        yield Path(e.path)
                except OSError:
                    continue


def discover(roots: Iterable[str | Path], *, max_depth: int = 6) -> list[VMInfo]:
    """发现虚拟机：按目录聚合 VM 文件，标出家族、内存快照与磁盘。"""
    vms: dict[str, VMInfo] = {}
    root_paths = [Path(r) for r in roots]
    for f in _iter_files(root_paths, max_depth=max_depth):
        suffix = f.suffix.lower()
        if suffix not in VM_MARKERS:
            continue
        # 目录 = f.parent（同一目录下的一堆文件属于同一台 VM）
        key = str(f.parent)
        info = vms.get(key)
        if info is None:
            fam = "未知"
            for name, exts in VM_FAMILIES.items():
                if suffix in exts:
                    fam = name
                    break
            info = VMInfo(root=key, family=fam)
            vms[key] = info
        if suffix in (".vmx", ".vbox", ".vxf", ".vmxf"):
            info.config = str(f)
        elif suffix == ".vmem":
            info.memory.append(str(f))
        elif suffix in (".vmdk", ".qcow2", ".vdi", ".vhdx", ".qcow", ".hdd"):
            info.disks.append(str(f))
        elif suffix in (".vmss", ".vmsn", ".vbox-prev"):
            info.sidecars.append(str(f))
    # 家族修正：目录里有 .vmem+.vmdk → VMware
    for info in vms.values():
        if info.memory and not info.disks:
            info.family = "VMware"
    return list(vms.values())


def parse_vmware_config(path: str | Path) -> list[VMFinding]:
    """解析 .vmx（INI 风格）里的高价值/高危配置项。"""
    out: list[VMFinding] = []
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [VMFinding("config", str(p), f"读取失败：{exc}", "low")]
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().strip('"')
        val = val.strip().strip('"')
        low = key.lower()
        if not any(k in low for k in VMX_SENSITIVE_KEYS):
            continue
        # ★ VMware 内部能力开关（tools.*）不是凭据 —— 早先版本把
        #   `tools.capability.verifiedSamlToken = "TRUE"` 误报成"明文口令"，已排除。
        if low.startswith("tools."):
            continue
        looks_secret = (_SECRET_VALUE.match(val) is not None
                         and val.lower() not in _FALSEY
                         and not val.lower().endswith(".exe")
                         and not val.lower().startswith("vmware"))
        cred_word = any(k in low for k in ("password", "passwd", "pwd", "secret",
                                          "apikey", "api_key", "authkey",
                                          "privatekey", "passphrase", "token"))
        sev = "info"
        detail = "配置项"
        if cred_word and looks_secret:
            sev = "critical"
            detail = "**疑似明文口令/凭据**"
        elif cred_word:
            sev = "medium"
            detail = "口令/凭据类配置项（值为空/布尔，暂未见明文）"
        elif any(k in low for k in ("clipboard", "dragdrop", "isolation", "sharedfolder",
                                   "hgfs")):
            sev = "medium"
            detail = "**攻击面**：剪贴板/拖放/共享目录等宿主机↔客户机通道"
        elif low.startswith("guestinfo"):
            sev = "low"
            detail = "客户机信息位（VMware Tools 自动写入；自定义位常被人塞口令/备注）"
        elif low == "annotation":
            sev = "medium"
            detail = "客户机备注（**人写的**，常放口令/线索）"
        out.append(VMFinding("config", str(p), f"{detail}：{key}", sev, val[:400]))
    return out


def scan_disk_for_secrets(paths: Iterable[str | Path], *,
                          patterns: tuple[tuple[str, str], ...] = (
                              (r"flag\{[^{}]{1,300}\}", "flag{...}"),
                              (r"(?i)\bctf\{[^{}]{1,300}\}", "ctf{...}"),
                              (r"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY", "私钥 BEGIN…PRIVATE KEY"),
                              (r"(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP 私钥"),
                          ),
                          chunk: int = 4 << 20,
                          overlap: int = 512,
                          max_bytes: int = 0,
                          progress: Any = None) -> list[VMFinding]:
    """
    对磁盘/镜像文件做**只读字节扫描**，找 flag 与私钥。

    * 分块读（默认 4 MB）+ 重叠窗口，避免跨块切断的字符串漏检；
    * 大文件稀疏（vmdk）会大量读零字节 —— 零块直接跳过，只在非零块里找；
    * `max_bytes=0` 表示不限；`progress(done, total)` 可回传进度。
    """
    out: list[VMFinding] = []
    # ⚠ bytes 模式**不能**配 re.IGNORECASE（那是 str 专用标志）→ 改成行内 (?i)
    # ⚠ bytes 模式的 `.pattern` 返回 **bytes**，所以 "x" in pat.pattern 会抛
    #   "a bytes-like object is required, not 'str'"（真实踩过）→ 另存一份原始 str 标签。
    pats: list[tuple[re.Pattern[bytes], str]] = []
    for p, label in patterns:
        bp = p.encode("utf-8", "ignore")
        if b"(?i)" not in bp:
            bp = b"(?i)" + bp
        pats.append((re.compile(bp), label))
    for path in paths:
        p = Path(path)
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if max_bytes and size > max_bytes:
            size = max_bytes
        read_total = 0
        try:
            with open(p, "rb") as f:
                tail = b""
                while read_total < size:
                    buf = f.read(min(chunk, size - read_total))
                    if not buf:
                        break
                    read_total += len(buf)
                    window = tail + buf
                    for pat, label in pats:
                        for m in pat.finditer(window):
                            try:
                                val = m.group(0).decode("utf-8", "replace")
                            except Exception:
                                val = repr(m.group(0)[:120])
                            label_hit = label.lower()
                            if "flag" in label_hit or "ctf" in label_hit:
                                # ★ flag 形态还要过"像不像真 flag"这一关
                                if not looks_like_flag(val):
                                    continue
                                sev = "critical"
                            else:
                                sev = "high"
                            out.append(VMFinding("disk", str(path),
                                                 f"命中 {label}", sev, val[:300]))
                    tail = window[-overlap:] if overlap else b""
                    if progress:
                        progress(read_total, size)
        except OSError as exc:
            out.append(VMFinding("disk", str(p), f"扫描失败：{exc}", "low"))
    return out


def summarize(vms: list[VMInfo], disk_hits: list[VMFinding]) -> dict[str, Any]:
    """汇总成结构化结果（供 CLI / Web / 报告使用）。"""
    return {
        "vm_count": len(vms),
        "vms": [
            {
                "目录": v.root,
                "家族": v.family,
                "配置": v.config or "—",
                "内存快照": v.memory,
                "磁盘": v.disks,
                "元数据": v.sidecars,
                "配置线索": [
                    {"级别": f.severity, "说明": f.detail, "值": f.value[:200],
                     "来源": Path(f.path).name}
                    for f in v.findings],
            } for v in vms
        ],
        "磁盘命中": [
            {"级别": f.severity, "说明": f.detail, "内容": f.value[:200],
             "文件": Path(f.path).name} for f in disk_hits
        ],
    }


def next_steps(vms: list[VMInfo], disk_hits: list[VMFinding]) -> list[str]:
    """把"发现了什么"翻译成"下一步做什么"。"""
    steps: list[str] = []
    for v in vms:
        if v.memory:
            steps.append(
                f"分析内存快照（可直接喂 MemProcFS）："
                + "；".join(f"`analyze \"{Path(m).name}\" --engine memprocfs`" for m in v.memory[:2]))
    crit = [f for f in disk_hits if f.severity == "critical"]
    if crit:
        steps.append(f"★ 磁盘里直接命中 {len(crit)} 处 flag/私钥，先看上面的「磁盘命中」，"
                     f"再用 `--engine memstrings` 在该镜像里做整盘字符串扫描")
    for v in vms:
        for f in v.findings:
            if f.severity in ("high", "critical"):
                steps.append(f"核对 VM 配置 `{Path(f.path).name}` 的 {f.detail.split('：')[0]}"
                             f"（值：{f.value[:60]}）")
                break
    # 有磁盘但没做深扫 → 明确告诉用户还有一整个磁盘没查
    if not disk_hits:
        for v in vms:
            if v.disks:
                steps.append(f"该 VM 的磁盘（{', '.join(Path(d).name for d in v.disks[:2])}）"
                             f"**还没查过**：加 `--deep` 做只读字节扫描找 flag/私钥")
                break
    if not steps:
        steps.append("未发现虚拟机资产或高危配置；可指定更深的目录再扫（--depth）")
    return steps
