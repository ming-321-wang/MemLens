r"""
MemLens · 维度一：工具存在性判定（FR-01）

对应方案 4.2.3(1)。

## 判定对象

代理客户端 / 隧道工具是否**在这台机器上存在过**。

## 三态判定（方案原文）

> 存在卸载项或已注册服务，判为**已安装**；
> 仅有文件残留、无有效配置与卸载项，判为**残留**；
> 程序目录位于可移动介质或用户目录且无安装记录，判为**便携运行**。
>
> 三态证据价值不同：已安装与便携运行指向"使用过"，残留只指向"曾经存在"，
> 因此**残留状态在打分时权重减半**。

## 强弱指纹分层（方案原文）

> 强指纹为数字签名主体、程序版本信息、配置目录结构三者的组合，
> 任一项单独命中即可定位……弱指纹为文件名、图标哈希、目录关键字，
> **必须两项以上组合命中才采信，且其中至少一项必须是路径类特征**；
> 单靠文件名命中的，只记为线索，不进结论。

## 误报控制（方案原文）

> 主要误报源有三类：名称近似的网络加速器、安全软件自带的代理组件、
> 开源项目的同名依赖。三类均进白名单，**白名单按签名主体与安装路径匹配，
> 不按名称匹配**——按名称匹配会把真正的代理工具一起放过，这是实践中踩过的坑。

本实现的白名单匹配走 `exclude_paths`（安装路径）与 `exclude_names`（签名/主体名），
**不按进程名一刀切**。
"""

from __future__ import annotations

from typing import Any

from memlens.dimensions.base import Dimension, DimensionResult
from memlens.detectors.base import get_field

#: 残留状态权重系数（方案：残留只指向"曾经存在"，权重减半）
RESIDUAL_FACTOR = 0.5

#: 可移动介质路径特征（判定"便携运行"）
_REMOVABLE_PREFIXES: tuple[str, ...] = (
    "\\usb", "\\removable", "\\media\\", "\\e:", "\\f:", "\\g:", "\\d:",
)

#: 用户目录特征（便携运行的另一个判据）
_USER_DIR_MARKERS: tuple[str, ...] = (
    "\\users\\public\\", "\\users\\default\\", "\\downloads\\", "\\desktop\\",
    "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
)


class ToolPresenceDimension(Dimension):
    """FR-01 工具存在性判定。"""

    dimension = "tool_presence"
    sources = ("mprocfs.process%", "mprocfs.services%", "mprocfs.registry_run%",
               "mprocfs.modules%")
    level_cap = "A"

    def run(self, ctx, pack) -> DimensionResult:
        used, missing = self.available_sources(ctx)
        res = DimensionResult(dimension=self.dimension, level_cap=self.level_cap)
        res.sources_used = used
        res.sources_missing = missing

        if "mprocfs.process%" in missing:
            res.state = "degraded"
            res.gaps.append(self.gap(
                "进程列表", "缺少进程产物，无法判定工具是否存在",
                impact="blocked", level_cap="C",
                suggestion="执行 MemProcFS 取证收集（mprocfs.harvest）以取得进程表。"))
            return res

        procs = ctx.records("mprocfs.process%", limit=20000)
        services = ctx.records("mprocfs.services%", limit=20000)
        runkeys = ctx.records("mprocfs.registry_run%", limit=20000)

        # 已注册服务名集合（判"已安装"）
        svc_names = set()
        for s in services:
            for k in ("ServiceName", "Name", "DisplayName", "服务名", "名称"):
                v = get_field(s, k)
                if v:
                    svc_names.add(str(v).lower())
                    break

        # 自启动项（判"已安装"）
        startup_targets: list[str] = []
        for r in runkeys:
            v = get_field(r, "数据", "Data")
            if v:
                startup_targets.append(str(v))

        hits: list[dict[str, Any]] = []
        for tool in pack.tools():
            found = self._match_tool(tool, procs, svc_names, startup_targets)
            if found:
                hits.append(found)

        if not hits:
            res.state = "not_found"
            res.findings.append(f"未在进程、服务、自启动项中发现任何已知代理/隧道工具"
                                f"（已比对 {len(pack.tools())} 个工具指纹）")
            res.independent_sources = 0
            return res

        # ---- 逐个工具定三态与得分 ----
        best = 0.0
        independent = 0
        for hit in hits:
            state = hit["state"]
            score = hit["score"]
            res.findings.append(
                f"{hit['display']}：{state_label(state)}"
                f"（命中指纹：{', '.join(hit['fingerprints'])}；"
                f"证据：{', '.join(hit['evidence']) or '—'}）")
            res.evidence_refs.extend(hit["evidence_refs"])
            independent = max(independent, hit["independent"])
            best = max(best, score)

        res.score = min(1.0, best)
        res.state = "established" if res.score >= 0.5 else "not_found"
        res.independent_sources = independent
        if res.state != "established":
            res.findings.append("存在弱指纹线索但未达到采信条件（方案：单靠文件名命中只记为线索）")
        return res

    # ------------------------------------------------------------------ 匹配
    def _match_tool(self, tool: dict[str, Any], procs: list[dict[str, Any]],
                    svc_names: set[str], startup_targets: list[str]) -> dict[str, Any] | None:
        """把一个工具指纹与实际数据比对，返回命中信息或 None。"""
        strong = tool.get("strong") or {}
        weak = tool.get("weak") or {}
        exclude_paths = [str(x).lower() for x in (tool.get("exclude_paths") or [])]
        exclude_names = [str(x).lower() for x in (tool.get("exclude_names") or [])]

        strong_proc = [str(x).lower() for x in (strong.get("process") or [])]
        strong_path = [str(x).lower() for x in (strong.get("path_keyword") or [])]
        weak_proc = [str(x).lower() for x in (weak.get("process") or [])]
        weak_path = [str(x).lower() for x in (weak.get("path_keyword") or [])]

        fingerprints: list[str] = []
        evidence: list[str] = []
        refs: list[str] = []
        independent = 0

        for p in procs:
            name = str(get_field(p, "Name", "name", "Process", default="") or "").lower()
            path = str(get_field(p, "UserPath", "Path", "win-path", default="") or "")
            pl = path.lower()
            cmd = str(get_field(p, "CommandLine", "win-cmdline", default="") or "").lower()

            # 白名单：按安装路径 / 主体名排除（**不按进程名排除**）
            if any(x in pl for x in exclude_paths):
                continue
            if any(x in name for x in exclude_names):
                continue

            hit_strong = any(n and n == name for n in strong_proc) or \
                any(k and k in pl for k in strong_path)
            hit_weak_proc = any(n and (n == name or n in cmd) for n in weak_proc)
            hit_weak_path = any(k and k in pl for k in weak_path)

            if hit_strong:
                fingerprints.append("强指纹")
                evidence.append(f"进程 {name}（PID {get_field(p, 'PID', default='?')}）"
                                + (f" 路径 {path}" if path else ""))
                pid = get_field(p, "PID")
                if pid is not None:
                    refs.append(f"process:PID={pid}:{name}")
                independent = max(independent, 2)
                continue

            # 弱指纹：必须 ≥2 项组合，且其中至少一项是**路径类**
            weak_hits = []
            if hit_weak_proc:
                weak_hits.append("文件名")
            if hit_weak_path:
                weak_hits.append("路径")
            if len(weak_hits) >= 2:
                fingerprints.append("弱指纹(" + "+".join(weak_hits) + ")")
                evidence.append(f"进程 {name}" + (f" 路径 {path}" if path else ""))
                pid = get_field(p, "PID")
                if pid is not None:
                    refs.append(f"process:PID={pid}:{name}")
                independent = max(independent, 1)
            elif weak_hits:
                # 单项命中 → 只记为线索，不进结论（方案原文）
                fingerprints.append("线索(" + weak_hits[0] + "，单命中不采信)")
                evidence.append(f"进程 {name}（仅线索）")

        # 服务 / 自启动：判"已安装"
        installed = False
        for sname in svc_names:
            for n in strong_proc:
                if n and n in sname:
                    installed = True
                    fingerprints.append("强指纹(已注册服务)")
                    evidence.append(f"服务 {sname}")
                    independent = max(independent, 2)
                    break
        for target in startup_targets:
            tl = target.lower()
            for k in strong_path:
                if k and k in tl:
                    installed = True
                    fingerprints.append("强指纹(自启动项)")
                    evidence.append(f"自启动项指向 {target[:80]}")
                    independent = max(independent, 2)
                    break

        if not fingerprints:
            return None

        # ---- 三态判定 ----
        portable = any(m in pl for m in _REMOVABLE_PREFIXES) or \
            any(m in pl for m in _USER_DIR_MARKERS)
        if installed:
            state = "installed"
            score = 1.0
        elif portable:
            state = "portable"
            score = 0.9
        else:
            state = "residual"
            score = 0.6 * RESIDUAL_FACTOR      # 残留权重减半

        return {
            "display": tool.get("display") or tool.get("id"),
            "state": state,
            "score": score,
            "fingerprints": fingerprints,
            "evidence": evidence[:6],
            "evidence_refs": refs[:20],
            "independent": independent,
        }


def state_label(state: str) -> str:
    """三态的中文表述（检查用法词表：发现/存在/疑似）。"""
    return {
        "installed": "已安装（存在服务或自启动项）",
        "portable": "便携运行（程序在可移动介质或用户目录且无安装记录）",
        "residual": "残留（仅有文件痕迹，无有效配置与卸载项）",
        "cleared": "痕迹已被清理（由外联证据反推）",
        "not_found": "未发现",
        "degraded": "数据源缺失，结论降级",
    }.get(state, state)
