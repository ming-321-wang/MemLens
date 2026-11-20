"""
MemLens · 静态样本检测器（PE 可疑性研判）

方法论：**单条特征几乎不足以定性**（Windows 满世界都是"有 CreateProcess 导入的 PE"），
所以这里用与内存检测器同一套"多特征加权 + 可解释证据"的打法：

  分数 = Σ(命中特征的权重)
  置信度 = sigmoid(分数) → 最终分级
  每条命中的特征与权重都写进 evidence，方便复核与调参

特征分组与权重（全部可调、可解释）：
  1. 加壳/保护（0.30）—— 最强信号：正常业务软件很少加壳，恶意样本几乎必加
  2. 无内嵌签名（0.08）—— 弱信号，仅作辅助（catalog 签名的系统文件会被这条误伤，
     所以权重很低，且不会单独成案）
  3. 危险 API 组合（0.25）—— 单项 API 不算，**组合**才算：
       注入三件套（VirtualAllocEx + WriteProcessMemory + CreateRemoteThread）
       键盘钩子 + 网络回连、屏幕抓取 + 网络回连 等
  4. 高价值字符串（0.10）—— 命令行痕迹/共享路径/加壳标记/调试器字符串
  5. TLS 回调（0.15）—— 恶意代码常用 TLS 反断点技巧
  6. W+X 节（0.20）—— 可写可执行节是自修改代码的典型特征
  7. 高熵 + 少节（0.10）—— 已经被 packer 启发式覆盖，这里降权防重复计分
"""

from __future__ import annotations

from typing import Any

from memlens.detectors.base import (
    Detection,
    DetectionContext,
    Detector,
    get_field,
    register,
    to_int,
    truncate,
)

# 注入链：**四项全中**才算"完整注入链"；命中 ≥2 项算"疑似"。
# （不能只用 3 项，否则大量正常程序（远程桌面、调试器、输入法）都会被误报）
INJECTION_FULL_SET = ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                      "NtUnmapViewOfSection")
HOOK_APIS = ("SetWindowsHookEx", "GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW")
NET_APIS = ("InternetOpen", "InternetConnect", "HttpSendRequest", "URLDownloadToFile",
            "WSAStartup", "connect", "send", "recv")
SCREEN_APIS = ("BitBlt", "CreateCompatibleBitmap", "GetWindowDC")
EXEC_APIS = ("CreateProcess", "ShellExecute", "WinExec", "CreateProcessAsUser")
SERVICE_APIS = ("CreateService", "OpenSCManager", "StartService")

# ---- 权重 ----
W_PACKER = 0.30
W_UNSIGNED = 0.05
W_INJECTION_TRIPLE = 0.25
W_HOOK_NET = 0.18
W_SCREEN_NET = 0.12
W_TLS = 0.15
W_WX_SECTION = 0.20
W_HIGH_ENTROPY_FEW_SECTIONS = 0.10
W_STRINGS = 0.10

# ---- Tier-2（常见信号）单项权重与总封顶 ----
W_ANTI_DEBUG_EACH = 0.05
W_FILE_WALK_EACH = 0.05
W_DYN_RESOLVE_EACH = 0.05
TIER2_CAP = 0.15

# ---- 信号分级（由真实样本对照得出，避免过拟合单个恶意样本）----
# Tier-1 = 罕见信号：良性软件极少具备，单独即可支撑评分。
# Tier-2 = 常见信号：MSVC 程序普遍具备（反调试/文件读写/无签名，
#           benign 对照实测 notepad/mmc/calc 全部命中），
#           **单独不计分，仅在与 Tier-1 互证时按 0.05/项封顶累加**。
# 这一条是本次用真实恶意样本 TestDLL.dll 与 4 个系统程序对照后修正的：
# 早期把 Tier-2 当独立权重，导致 notepad.exe 拿到 60% MEDIUM（严重误报）。
CONF_MAX = 0.97

ANTI_DEBUG_APIS = ("IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                   "NtQueryInformationProcess", "OutputDebugStringA",
                   "OutputDebugStringW", "SetUnhandledExceptionFilter",
                   "NtSetInformationThread")
FILE_WALK_APIS = ("FindFirstFile", "FindFirstFileEx", "FindNextFile",
                  "CreateFileW", "CreateFileA", "ReadFile", "WriteFile",
                  "SetEndOfFile", "SetFilePointer", "DeleteFileW", "MoveFileW")
MESSAGE_APIS = ("MessageBoxA", "MessageBoxW", "WinExec", "ShellExecute")
DYN_RESOLVE_APIS = ("GetProcAddress", "LoadLibraryEx", "LdrLoadDll")


def _norm(text: Any) -> str:
    return "" if text is None else str(text)


def _as_bool(value: Any) -> bool:
    return _norm(value).strip().lower() in ("true", "1", "yes", "是", "√")


@register
class StaticSampleDetector(Detector):
    """PE / ELF 通用可疑性研判（加权评分 + 可解释证据）。"""

    name = "static_sample_suspicious"
    display = "PE/ELF 可疑性研判"
    needs = ("%static.profile%",)
    default_severity = "medium"

    def run(self, ctx: DetectionContext) -> list[Detection]:
        # 一次 analyze 可能分析了多个文件（一个 case 挂多个 artifact），
        # 这里按"文件名"把记录分组，逐文件独立研判。
        rows = ctx.records("%static.profile%")
        # 关键：PE 与 ELF 的结构记录来自**不同** artifact（static.pe / static.elf），
        # 必须都读，否则 ELF 的"节区/头"记录根本进不了 groups（曾因此 ELF 检测完全失效）。
        pe_headers = ctx.records("%static.pe%") + ctx.records("%static.elf%")
        string_rows = ctx.records("%static.strings%")

        by_file: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for r in rows:
            f = _norm(get_field(r, "文件", "name")) or "?"
            by_file.setdefault(f, {"profile": [], "pe": [], "strings": []})["profile"].append(r)
        for r in pe_headers:
            f = _norm(get_field(r, "文件", "name")) or "?"
            if f in by_file:
                by_file[f]["pe"].append(r)
        for r in string_rows:
            f = _norm(get_field(r, "文件", "name")) or "?"
            if f in by_file:
                by_file[f]["strings"].append(r)

        findings: list[Detection] = []
        for fname, groups in by_file.items():
            profile = groups["profile"][0] if groups["profile"] else {}
            # PE 与 ELF 的头/节/导入结构都按"项"归类，这里统一取
            header = next((h for h in groups["pe"]
                           if get_field(h, "项", default="") in ("PE 头", "ELF 头")), {})
            sections = [h for h in groups["pe"]
                        if get_field(h, "项", default="") == "节区"]
            imports = [h for h in groups["pe"]
                       if get_field(h, "项", default="") in ("导入表", "导入函数（未定义符号）")]
            is_elf = "ELF 头" in (get_field(header, "项", default=""),)

            weights: dict[str, float] = {}
            conf = 0.0
            fmt_kind = "ELF" if is_elf else "PE"

            # ---------- 1. 加壳/保护 ----------
            packer = _norm(get_field(header, "加壳标记", default=""))
            packed = _as_bool(get_field(header, "加壳嫌疑", default=""))
            if packed or packer:
                weights["加壳/保护特征"] = W_PACKER
                conf += W_PACKER
            # ELF 的"静态链接 + 无 build-id + 剥离"组合：自包含且难以追踪，是恶意样本常用手法
            if is_elf:
                if _as_bool(get_field(header, "静态链接", default="")):
                    weights["静态链接（自包含、无外部依赖可观测）"] = 0.10
                    conf += 0.10
                if _as_bool(get_field(header, "已剥离符号", default="")):
                    weights["符号表已剥离"] = 0.08
                    conf += 0.08
                if _norm(get_field(header, "build-id", default="")) in ("(无)", "", None):
                    weights["无 .note.gnu.build-id"] = 0.06
                    conf += 0.06

            # ---------- 2. 签名（PE 专属；ELF 一般无 Authenticode） ----------
            if not is_elf:
                signed_raw = get_field(header, "数字签名", default="")
                signed = _as_bool(signed_raw) if signed_raw not in (None, "") else None
                if signed is False:
                    weights["无内嵌 Authenticode 证书"] = W_UNSIGNED
                    conf += W_UNSIGNED

            # ---------- 3. Tier-1：危险 API 组合（罕见，独立计分）----------
            funcs: list[str] = []
            for imp in imports:
                raw = get_field(imp, "函数", default="") or ""
                funcs.extend(x.strip() for x in _norm(raw).split(",") if x.strip())
            fset = set(funcs)
            tier1 = 0.0
            if all(a in fset for a in INJECTION_FULL_SET):
                weights["完整注入链（VirtualAllocEx+WriteProcessMemory+CreateRemoteThread+NtUnmapViewOfSection）"] = W_INJECTION_TRIPLE
                tier1 += W_INJECTION_TRIPLE
            elif sum(1 for a in INJECTION_FULL_SET if a in fset) >= 2:
                weights["疑似注入链（命中多项）"] = W_INJECTION_TRIPLE * 0.7
                tier1 += W_INJECTION_TRIPLE * 0.7
            if any(h in fset for h in HOOK_APIS) and any(n in fset for n in NET_APIS):
                weights["键盘/鼠标钩子 + 网络回连"] = W_HOOK_NET
                tier1 += W_HOOK_NET
            if any(s in fset for s in SCREEN_APIS) and any(n in fset for n in NET_APIS):
                weights["屏幕抓取 + 网络回连"] = W_SCREEN_NET
                tier1 += W_SCREEN_NET
            if any(s in fset for s in SERVICE_APIS):
                weights["操作服务（疑似持久化）"] = 0.10
                tier1 += 0.10

            # ---------- 4~7. Tier-1 结构性信号 ----------
            tls = [h for h in groups["pe"] if get_field(h, "项", default="") == "TLS 回调"]
            if tls:
                addrs = ", ".join(_norm(get_field(t, "地址", default="")) for t in tls[:4])
                weights[f"存在 TLS 回调（{addrs}）"] = W_TLS
                tier1 += W_TLS

            wx = [s for s in sections if _as_bool(get_field(s, "可写且可执行(W+X)", default=""))]
            if wx:
                names = ", ".join(_norm(get_field(s, "节名", default="")) for s in wx[:4])
                weights[f"可写可执行节：{names}"] = W_WX_SECTION
                tier1 += W_WX_SECTION

            if not packed and len(sections) <= 2:
                ent = to_int(get_field(profile, "整体熵", default="0")) or 0
                try:
                    ent_f = float(ent) / 1000.0 if ent > 8 else float(ent)
                except (TypeError, ValueError):
                    ent_f = 0.0
                if ent_f > 7.2:
                    weights[f"节数极少({len(sections)})且整体熵 {ent_f:.2f}"] = W_HIGH_ENTROPY_FEW_SECTIONS
                    tier1 += W_HIGH_ENTROPY_FEW_SECTIONS

            str_hits: list[str] = []
            for s in groups["strings"]:
                cat = _norm(get_field(s, "类别", default=""))
                val = _norm(get_field(s, "字符串", default=""))
                if cat in ("命令行痕迹", "UNC/共享路径", "加壳标记", "调试/分析工具") and val:
                    str_hits.append(f"{cat}:{truncate(val, 80)}")
            if len(str_hits) >= 2:
                weights[f"高危字符串 {len(str_hits)} 处"] = W_STRINGS
                tier1 += W_STRINGS

            conf += tier1

            # ---------- 8. Tier-2：常见信号，仅在与 Tier-1 互证时才计分 ----------
            # 这是实测修正的核心：notepad/mmc/calc 全部命中反调试+文件遍历+无签名，
            # 若独立计分会把系统程序误报成 MEDIUM。改为"必须已有 Tier-1 信号"。
            tier2 = 0.0
            if tier1 > 0:
                anti_hits = [a for a in ANTI_DEBUG_APIS if a in fset]
                walk_hits = [a for a in FILE_WALK_APIS if a in fset]
                dyn_hits = [a for a in DYN_RESOLVE_APIS if a in fset]
                if anti_hits:
                    w = min(W_ANTI_DEBUG_EACH * len(anti_hits), 0.10)
                    weights[f"反调试/反分析 API ×{len(anti_hits)}（Tier-2 互证）"] = w
                    tier2 += w
                if len(walk_hits) >= 3:
                    w = min(W_FILE_WALK_EACH * len(walk_hits), 0.10)
                    weights[f"文件遍历+逐文件读写 ×{len(walk_hits)}（Tier-2 互证）"] = w
                    tier2 += w
                if len(dyn_hits) >= 2:
                    weights[f"动态解析 API（{', '.join(dyn_hits[:2])}）（Tier-2 互证）"] = W_DYN_RESOLVE_EACH
                    tier2 += W_DYN_RESOLVE_EACH
                tier2 = min(tier2, TIER2_CAP)
                conf += tier2

            # ---------- 9. 非标准链接面（真实对照得出的弱信号）----------
            # 现代 MSVC 链接的 Windows 程序普遍通过大量 api-ms-win-* API set 间接导入；
            # 只直接依赖 kernel32/user32 少量 DLL 却导入数十上百个函数，
            # 说明工具链老旧或经过手工处理 —— 仅作弱信号，不单独支撑评分。
            if not is_elf:
                dll_names = [get_field(i, "DLL", default="") for i in imports]
                dll_names = [d for d in dll_names if d]
                api_set = [d for d in dll_names if d.lower().startswith("api-ms-win")]
                direct = [d for d in dll_names if not d.lower().startswith("api-ms-win")]
                if (direct and not api_set and len(dll_names) <= 3 and len(funcs) >= 40):
                    weights[f"直接依赖 DLL 极少（{len(dll_names)} 个：{', '.join(dll_names)}）"
                            f"却导入 {len(funcs)} 个函数，缺少 api-ms-win-* API set"
                            f"（非标准链接面）"] = 0.08
                    conf += 0.08

            conf = max(0.05, min(conf, CONF_MAX))
            if conf < 0.15:            # 基线以下不出案，避免每个系统 DLL 都报一条
                continue

            det = Detection(
                title=f"样本可疑性评分：{fname}（{conf:.0%}）",
                description=(
                    f"对 {fmt_kind} 文件按两级信号加权："
                    "**Tier-1 罕见信号**（加壳/注入链/钩子+网络/TLS 回调/W+X 节/高危字符串）"
                    "独立计分；**Tier-2 常见信号**（反调试/文件遍历/动态解析/无签名）"
                    "仅在已存在 Tier-1 信号时按 0.05/项封顶累加——因为实测中"
                    "notepad/mmc/calc 等系统程序同样命中这些 API。\n"
                    "**这是初筛而非定性结论**：低评分不代表干净。"
                    "静态元数据对未签名 MSVC 样本的区分度有限（实测恶意 DLL 与"
                    "notepad 的导入表差异很小），结论需结合代码分析/哈希情报/行为沙箱复核。"
                ),
                confidence=conf,
                sources=["static.profile", "static.pe", "static.strings"],
                evidence={
                    "文件": fname,
                    "格式": fmt_kind,
                    "文件类型": get_field(profile, "文件类型", default=""),
                    "位数/CPU": f"{get_field(header, '位数', default='')}bit "
                                f"{get_field(header, 'CPU', default='')} {get_field(header, '机器', default='')}".strip(),
                    "是否 DLL": get_field(header, "DLL", default=""),
                    "是否驱动": get_field(header, "驱动(.sys)", default=""),
                    "静态链接": get_field(header, "静态链接", default=""),
                    "已剥离": get_field(header, "已剥离符号", default=""),
                    "依赖库": len(info_needed(header)),
                    "SHA-256": truncate(get_field(profile, "SHA-256", default=""), 64),
                    "加壳标记": packer,
                    "命中权重": weights,
                    "导入函数数": len(funcs),
                    "高危字符串样例": str_hits[:5],
                },
            )
            det.severity = det.severity_from_confidence(high=0.70, medium=0.40)
            findings.append(det)

        return findings


def info_needed(header: dict) -> list:
    """从 ELF 头记录里取依赖库数量（字段在 records 里是「依赖库数」）。"""
    v = header.get("依赖库数")
    return [0] * (v if isinstance(v, int) else 0)
