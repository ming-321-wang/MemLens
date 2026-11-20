r"""
MemLens · 维度三：运行痕迹核验（FR-03）

对应方案 4.2.3(3)。

## 五源交叉（方案原文）

> 五个数据源提供不同侧面：**预取文件**给执行次数与末次运行时间，
> **程序兼容性数据库**给首次出现时间、路径与文件哈希，
> **用户辅助记录**给图形界面启动次数与时间，
> **系统资源使用统计**给按进程的网络字节数与时长，
> **服务安装事件**给服务创建时间与路径。
> 五源做时间交叉，取首次运行时间的交集区间；单源缺失时按表 12 降级，不中断流程。

## 权重差异（方案原文）

> 五源中，**系统资源使用统计优先级最高**——它是主机侧唯一能证明"确实传输过数据"的证据，
> 其余四源只能证明"运行过"。因此在打分时，**系统资源使用统计的证据权重单独提高一档**；
> 反过来，若只有预取与用户辅助记录，**结论上限只能到 B 级**，
> 因为"启动过"不等于"用过"。

## 现实（内存镜像的边界）

内存镜像里**没有**磁盘上的 Prefetch / AmCache / SRUM 文件（那要读磁盘）。
因此：

| 源 | 内存镜像可得性 | 本实现取值 |
|---|---|---|
| 预取文件 | ✗（磁盘） | **缺失即降级** |
| 程序兼容性数据库(AmCache) | ✗（磁盘） | **缺失即降级** |
| 用户辅助记录(UserAssist) | ✓ 注册表 | `vol3 windows.registry.userassist` |
| 系统资源使用统计(SRUM) | ✗（磁盘） | **缺失即降级** |
| 服务安装事件 | ✓ 服务表 | `mprocfs.services` / `mprocfs.registry_run` |

另有**内存侧的补充源**：进程创建时间与命令行（`mprocfs.process` / `mprocfs.cmdlines`）——
它能证明"进程确实在跑"，是内存域特有的强证据，本实现把它计入独立来源数。

> **降级是常态**：方案表 12 明确"单源结论上限 C 级"。本维度在只有一源时
> 自动把上限压到 C/B，并在缺口清单里写明"建议补证"（方案 4.2.3 表 12）。
"""

from __future__ import annotations

import re
from typing import Any

from memlens.dimensions.base import Dimension, DimensionResult
from memlens.detectors.base import get_field

#: 五源的标识与其中文名
TRACE_SOURCES: tuple[tuple[str, str], ...] = (
    ("prefetch", "预取文件（Prefetch）"),
    ("amcache", "程序兼容性数据库（AmCache）"),
    ("userassist", "用户辅助记录（UserAssist）"),
    ("srum", "系统资源使用统计（SRUM）"),
    ("service_event", "服务安装事件"),
    # 内存侧补充源（不属于方案五源，但同样是"运行过"的证据）
    ("process", "进程创建时间与命令行（内存侧）"),
)

#: 各源的最大可贡献分（SRUM 最高，方案 4.2.3(3)）
SOURCE_WEIGHT: dict[str, float] = {
    "srum": 0.95,
    "process": 0.80,
    "userassist": 0.60,
    "service_event": 0.55,
    "amcache": 0.50,
    "prefetch": 0.50,
}

#: 时间解析：把各种格式拉成可比较的字符串（YYYY-MM-DD HH:MM:SS）
#: ⚠ 这里**必须是一个编译好的单个正则**——早先写成元组却在下面 `.search()`，
#:   运行到第一行数据就抛 `AttributeError: 'tuple' object has no attribute 'search'`
#:   （专项测试抓到的）。
_TIME_PATTERN = re.compile(
    r"(\d{4})[-/](\d{1,2})[-/](\d{1,2})[ T]?(\d{1,2})?:?(\d{2})?:?(\d{2})?"
)


def _norm_time(value: Any) -> str:
    """把时间值规整成 `YYYY-MM-DD HH:MM:SS`（取不到就返回空）。"""
    if value in (None, ""):
        return ""
    m = _TIME_PATTERN.search(str(value))
    if not m:
        return ""
    y, mo, d, h, mi, s = m.groups()
    try:
        return f"{int(y):04d}-{int(mo):02d}-{int(d):02d} {int(h or 0):02d}:{int(mi or 0):02d}:{int(s or 0):02d}"
    except (TypeError, ValueError):
        return ""


class ExecutionTraceDimension(Dimension):
    """FR-03 运行痕迹核验。"""

    dimension = "execution_trace"
    sources = ("mprocfs.process%", "mprocfs.services%", "mprocfs.cmdlines%",
               "windows.registry.userassist%")
    level_cap = "A"

    def run(self, ctx, pack) -> DimensionResult:
        used, missing = self.available_sources(ctx)
        res = DimensionResult(dimension=self.dimension, level_cap=self.level_cap)
        res.sources_used = used
        res.sources_missing = missing

        # ---- 各源独立取证 ----
        per_source: dict[str, list[dict[str, Any]]] = {}
        times: dict[str, list[str]] = {}

        # ① 进程（内存侧）：进程在跑 = 确实运行过
        procs = ctx.records("mprocfs.process%", limit=20000)
        proc_rows: list[dict[str, Any]] = []
        for p in procs:
            name = str(get_field(p, "Name", default="") or "")
            if not name:
                continue
            # 只取有"工具特征"名字的进程（否则全部系统进程都会被算进来）
            if not _looks_like_tool(name, pack):
                continue
            ct = _norm_time(get_field(p, "CreateTime"))
            proc_rows.append({"name": name, "pid": get_field(p, "PID"),
                              "path": str(get_field(p, "UserPath", default="") or ""),
                              "user": str(get_field(p, "User", default="") or ""),
                              "create_time": ct})
            if ct:
                times.setdefault("process", []).append(ct)
        if proc_rows:
            per_source["process"] = proc_rows

        # ② 服务安装事件
        svc_rows: list[dict[str, Any]] = []
        for s in ctx.records("mprocfs.services%", limit=20000):
            name = str(get_field(s, "ServiceName", "Name", "DisplayName", default="") or "")
            if name and _looks_like_tool(name, pack):
                svc_rows.append({"name": name,
                                 "path": str(get_field(s, "Path", "ImagePath", default="") or "")})
        if svc_rows:
            per_source["service_event"] = svc_rows

        # ③ 用户辅助记录（注册表）
        ua_rows = ctx.records("windows.registry.userassist%", limit=20000)
        ua: list[dict[str, Any]] = []
        for r in ua_rows:
            blob = str(get_field(r, "Value", "Data", default="") or "")
            # UserAssist 的值是 ROT13 编码的程序路径
            for cand in (blob, _rot13(blob)):
                if _looks_like_tool(cand, pack):
                    ua.append({"raw": blob[:120], "decoded": cand[:120]})
                    break
        if ua:
            per_source["userassist"] = ua

        # ④ 磁盘侧三源在内存镜像中不可得 —— 记为缺口
        for sid, sname in (("prefetch", "预取文件"), ("amcache", "程序兼容性数据库"),
                           ("srum", "系统资源使用统计")):
            res.gaps.append(self.gap(
                sname, f"{sname}位于磁盘，内存镜像中不存在，无法采集",
                impact="downgrade", level_cap="B",
                suggestion="如需该源，请对目标磁盘做只读镜像后从磁盘侧解析；"
                           "当前结论已按缺源折算。"))

        # ---- 汇总 ----
        if not per_source:
            res.state = "not_found"
            res.findings.append("未发现任何工具运行痕迹（进程、服务、UserAssist 均无命中）")
            res.independent_sources = 0
            res.score = 0.0
            return res

        # 得分：取各源贡献的最大值（不是累加——多源印证提升的是**等级**不是分数）
        best = 0.0
        best_src = ""
        for sid, rows in per_source.items():
            w = SOURCE_WEIGHT.get(sid, 0.4)
            v = w if rows else 0.0
            if v > best:
                best, best_src = v, sid
        res.score = min(1.0, best)
        res.independent_sources = len(per_source)

        for sid, sname in TRACE_SOURCES:
            rows = per_source.get(sid) or []
            if not rows:
                continue
            sample = rows[0]
            detail = ""
            if sid == "process":
                detail = (f"{sample['name']}（PID {sample['pid']}，用户 {sample['user']}，"
                          f"创建 {sample['create_time'] or '未知'}）")
            elif sid == "service_event":
                detail = f"服务 {sample['name']}"
            elif sid == "userassist":
                detail = f"UserAssist 记录 {sample['decoded']}"
            res.findings.append(f"命中 {sname}：{detail}")
            res.evidence_refs.append(f"trace:{sid}:{sample.get('name', '')}")

        # ---- 等级上限：只有预取 + UserAssist 时上限只能 B（方案 4.2.3(3)）----
        have = set(per_source.keys())
        # ★ 缺系统资源使用统计 ⇒ "启动过"不等于"用过" ⇒ 上限只能到 B
        #   （方案 4.2.3(3) 原文）。这不只针对"只有预取与 UserAssist"，
        #   任何缺 SRUM 的情形都适用——SRUM 是主机侧唯一能证明
        #   "确实传输过数据"的源，缺它就没有这条证据。
        if "srum" not in have:
            res.level_cap = "B"
        if have <= {"prefetch", "userassist"}:
            res.level_cap = "B"
            res.gaps.append(self.gap(
                "运行痕迹独立性", "仅有预取与用户辅助记录，'启动过'不等于'用过'",
                impact="downgrade", level_cap="B",
                suggestion="补充系统资源使用统计（证明确实传输过数据）后方可提高等级。"))
        if "srum" not in have:
            res.gaps.append(self.gap(
                "传输量证据", "缺系统资源使用统计，无法证明主机侧确实传输过数据",
                impact="downgrade", level_cap="B",
                suggestion="从目标磁盘提取 SRUM 数据库（需只读镜像）。"))

        res.state = "established" if res.score >= 0.5 else "not_found"
        return res


# ------------------------------------------------------------------ 工具

def _looks_like_tool(name: str, pack) -> bool:
    r"""
    进程/服务名或**路径**是否命中工具指纹库。

    ⚠ 必须同时检查 **basename** 与 **路径关键字**：
      UserAssist 里存的是 ROT13 编码的**完整路径**（`C:\Tools\v2ray\v2ray.exe`），
      只按进程名比较会漏掉（实测踩过：ROT13 还原了却仍判"未命中"）。
    """
    low = str(name or "").lower()
    if not low:
        return False
    base = low.replace("/", "\\").split("\\")[-1]
    for tool in pack.tools():
        for key in ("strong", "weak"):
            spec = tool.get(key) or {}
            for n in spec.get("process") or []:
                n = str(n).lower()
                if not n:
                    continue
                if n == low or n == base or low.startswith(n) or base.startswith(n):
                    return True
            for k in spec.get("path_keyword") or []:
                k = str(k).lower()
                if k and k in low:
                    return True
    return False


def _rot13(text: str) -> str:
    """ROT13 —— UserAssist 的值用它编码程序路径。"""
    out = []
    for ch in str(text or ""):
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)
