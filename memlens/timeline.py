r"""
MemLens · 时间线

把所有产物里带时间的记录汇成一条时间线，按时间排序去重。

为什么需要它：
    内存取证的核心问题不是"有什么"，而是"**什么时候发生了什么**"。
    攻击链只有放到时间轴上才成立——先建账号、再落地文件、后建立外联，
    单看任何一个插件的结果都看不出这是一次入侵。

时间字段是异构的（Unix 时间戳 / ISO 串 / Windows FILETIME / 事件时间），
统一在这里做归一化，解析不出来就保留原值并标注，不丢数据。

## ★ 时间基准（v1.3 合规改造）

方案《计算机系统数字取证工作台开发方案》5.3 要求：
**所有时间以协调世界时存储，同时保留原始时区与偏移量，报告呈现时再换算。**

本模块原先用 `dt.datetime.fromtimestamp(n)`（**naive 本地时间**），
这正是方案点名的雷区——同一份镜像换台作业机跑，时间线整体平移。

现在所有时间归一走 `core/timebase.py`（单一入口），并保留：
`ts_utc`（UTC ISO 串）、`ts_raw`（原始表示）、`tz_offset`（偏移秒数）、
`tz_name`（原时区标识）、`tz_assumption`（采用的假设）、`tz_note`（换算留痕）。
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
# ⚠ 真实踩过的坑（v1.0 修）：本模块原来只 `import datetime as _dt`，
#   但函数体与类型标注里用的是 `dt.` —— **模块一被调用就 NameError**。
#   症状极具迷惑性：
#     * `from __future__ import annotations` 让**标注**变成字符串，
#       所以 `import memlens.timeline` 不会报错、一切看着正常；
#     * 真正崩在 `normalize_time()` 第一次被调用时：
#       `NameError: name 'dt' is not defined`；
#     * 而 `normalize_time` 只在"从记录里抽时间"时被调用 ——
#       于是时间线功能从 v0.10 起就是**坏的**，只有当记录里恰好没有可解析时间时才不崩。
#   之前一直没暴露，是因为没有一次运行真的把时间线跑到底。
import datetime as dt
import re
from typing import Any, Iterable, Sequence

from memlens.core import timebase
from memlens.core.timebase import TimeValue

# 记录里可能承载时间的字段名（归一化后比较）
TIME_KEYS: tuple[str, ...] = (
    "createtime", "created", "starttime", "time", "timestamp", "lastwritetime",
    "modified", "date", "exitTime", "eventtime", "when", "epoch", "unixtime",
    "lastwrite", "creationtime", "access", "write", "run",
)

# 纪元声明：不同来源需要不同纪元，不猜
#: 字段名（归一化后）→ 纪元（None = 自动按量级判定）
FIELD_EPOCH: dict[str, str] = {
    "visittime": "webkit",        # Chromium visits.visit_time
    "lastvisittime": "webkit",    # Chromium urls.last_visit_time
    "visitdate": "unix_us",       # Firefox moz_historyvisits.visit_date
    "filetime": "filetime",
}

def _norm(key: str) -> str:
    return "".join(c for c in str(key).lower() if c.isalnum())


def _epoch_for(key: str) -> str | None:
    return FIELD_EPOCH.get(_norm(key))

def normalize_time(value: Any, *, assume: str = "local",
                   epoch: str | None = None) -> tuple[dt.datetime | None, str]:
    """
    把各种时间表达归一化为 **UTC aware datetime**。

    ⚠ v1.3 行为变更：返回值从 naive 本地时间改为 **aware UTC**。
    旧调用方若直接 `.strftime()` 会显示 UTC 而不是本地时间——
    这是**故意的**（方案要求统一 UTC 存储），报告呈现请用
    `memlens.core.timebase.to_local()` 按记录的偏移还原。

    Returns:
        (解析结果, 原始表示)。解析不了时返回 (None, 字符串) 以便报告里如实展示。
    """
    tv = timebase.normalize(value, assume=assume, epoch=epoch)
    return tv.utc, tv.raw

@dataclasses.dataclass
class Event:
    """
    一个时间线事件。

    ★ v1.3：`ts` 一律是 **aware UTC**；原始表示、偏移量与换算假设随事件一起留存，
    满足方案 5.3「统一 UTC 存储 + 保留原始时区与偏移量 + 换算留痕」三件要求。
    """

    ts: dt.datetime | None
    raw_time: str
    source_plugin: str
    title: str
    detail: str = ""
    severity: str = "info"
    #: 原始时区偏移（秒）。东八区 = 28800；无时区信息且按 local 假设时为作业机偏移
    tz_offset: int | None = None
    #: 原始时区标识（如 `UTC+08:00`、`UTC`）
    tz_name: str = ""
    #: 采用的假设：utc / local / explicit_offset / explicit_tz / epoch_known
    tz_assumption: str = ""
    #: 换算过程说明（留痕）
    tz_note: str = ""

    @property
    def ts_utc(self) -> str:
        """UTC ISO 串（入库用）。"""
        return timebase.to_utc_iso_dt(self.ts)

    def to_local(self) -> str:
        """按记录的偏移还原目标机本地时间（报告呈现用）。"""
        return timebase.to_local(self.ts, self.tz_offset)

    def to_record(self) -> dict[str, Any]:
        return {
            "time": self.ts.isoformat(sep=" ") if self.ts else "",
            "ts_utc": self.ts_utc,
            "ts_local": self.to_local(),
            "raw_time": self.raw_time,
            "ts_raw": self.raw_time,        # 与存储层 records.ts_raw 同名
            "tz_offset": self.tz_offset,
            "tz_name": self.tz_name,
            "tz_assumption": self.tz_assumption,
            "tz_note": self.tz_note,
            "source_plugin": self.source_plugin,
            "title": self.title[:300],
            "detail": self.detail[:500],
            "severity": self.severity,
            "time_parsed": "1" if self.ts else "0",
        }


def _pick_time(record: dict[str, Any]) -> TimeValue:
    """
    挑一个最合适的时间字段，返回完整的 TimeValue（含偏移量与换算留痕）。

    ★ 纪元按字段名声明（浏览器 / FILETIME 等），不靠量级猜。
    """
    fallback = TimeValue(None)
    for key, val in record.items():
        nk = _norm(key)
        if nk not in TIME_KEYS:
            continue
        tv = timebase.normalize(val, epoch=_epoch_for(key))
        if tv.ok:
            return tv
        if not fallback.raw:
            fallback = tv
    return fallback


def _describe(record: dict[str, Any], plugin: str) -> tuple[str, str]:
    """给一条记录生成人能读的标题与细节。"""
    keys = list(record.keys())
    name = ""
    for cand in ("name", "process", "imagefilename", "imagename", "filename",
                 "service", "module", "comm", "key", "filenameoffset", "value"):
        for k in keys:
            if _norm(k) == cand and record.get(k):
                name = str(record[k])[:120]
                break
        if name:
            break
    title = f"[{plugin}] {name}" if name else f"[{plugin}] 记录"
    shown = [f"{k}={str(v)[:80]}" for k, v in list(record.items())[:6] if v not in (None, "")]
    return title, " | ".join(shown)


def build_timeline(
    records: Iterable[tuple[dict[str, Any], str]],
    *,
    limit: int = 20_000,
    include_untimed: bool = False,
    dedupe: bool = True,
) -> list[Event]:
    """
    从 (记录, 插件名) 序列构建时间线。

    Args:
        include_untimed: 是否保留解析不出时间的记录（排在末尾）。
        dedupe: 按 (时间, 插件, 标题) 去重，避免同一条被多个来源重复计入。
    """
    events: list[Event] = []
    seen: set[tuple[Any, str, str]] = set()
    for record, plugin in records:
        if not isinstance(record, dict):
            continue
        tv = _pick_time(record)
        ts, raw = tv.utc, tv.raw
        if ts is None and not include_untimed:
            continue
        title, detail = _describe(record, plugin)
        sev = str(record.get("severity") or "info")
        key = (ts.isoformat() if ts else raw, plugin, title)
        if dedupe and key in seen:
            continue
        seen.add(key)
        events.append(Event(ts=ts, raw_time=raw, source_plugin=plugin,
                            title=title, detail=detail, severity=sev,
                            tz_offset=tv.offset, tz_name=tv.tz_name,
                            tz_assumption=tv.assumption, tz_note=tv.note))
        if len(events) >= limit:
            break
    # ⚠ 排序键必须用 **aware** 时间比较：naive 与 aware 混排会抛 TypeError。
    #   现在所有 ts 都是 aware UTC，因此直接排序即可（UTC 序 = 真实序）。
    events.sort(key=lambda e: (e.ts is None, e.ts or _dt.datetime.max.replace(tzinfo=dt.timezone.utc),
                                e.source_plugin))
    return events


def to_csv(events: Sequence[Event], path: str) -> int:
    """导出时间线 CSV（含 BOM，Excel 直接打开不乱码）。"""
    import csv

    if not events:
        return 0
    cols = ["ts_utc", "ts_local", "raw_time", "tz_offset", "tz_name",
            "tz_assumption", "source_plugin", "title", "detail", "severity"]
    with open(path, "w", newline="", encoding="utf-8-sig") as fp:
        w = csv.writer(fp, escapechar="\\")
        w.writerow(cols)
        for e in events:
            r = e.to_record()
            w.writerow([" ".join(str(r.get(c, "")).split()) for c in cols])
    return len(events)


def to_markdown(events: Sequence[Event], *, max_rows: int = 200) -> str:
    """渲染成 Markdown 表格（报告里直接嵌）。"""
    if not events:
        return "_本次分析未提取到带时间戳的记录。_\n"
    out = ["| 时间(UTC) | 本地时间 | 来源 | 事件 |", "|---|---|---|---|"]
    for e in events[:max_rows]:
        t = e.ts_utc or (e.raw_time or "—")
        loc = e.to_local() or "—"
        out.append(f"| {t} | {loc} | `{e.source_plugin}` | {_md_cell(e.title)} |")
    if len(events) > max_rows:
        out.append(f"| … | | | 另有 {len(events) - max_rows} 条（见 CSV 导出） |")
    return "\n".join(out) + "\n"


def _md_cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")[:160]
