"""
MemLens · 情报扫描（案例级）

把 intel 层的结果**写回统一证据模型**，因此情报和 vol3 产物在 GUI / CLI / 导出里
是同一种东西，可以互相 JOIN、一起出报告。

聚合策略（关键设计）：
    一个 IOC 往往在几百条记录里重复出现（每条 netscan 行都带同一个外网 IP）。
    若逐条命中各存一行，证据表会被淹没，真正的线索反而看不见。
    因此这里按 **(类型, 值)** 聚合为一行，并记录：
        sources   —— 出现在哪些插件的产物里（多源印证）
        count     —— 出现次数
        sample    —— 一条原始上下文，供人工复核

这样产出的是"线索清单"，而不是"匹配流水账"。
"""

from __future__ import annotations

import dataclasses
from typing import Any, Callable, Iterable, Sequence

from memlens.intel import builtin, ioc as ioc_mod
from memlens.intel.dictionary import Dictionary, DictionaryScanner, Hit

ENGINE_NAME = "intel"
IOC_PLUGIN = "intel.ioc"


@dataclasses.dataclass
class ScanReport:
    """一次情报扫描的产出。"""

    case_id: str
    ioc_records: int = 0
    dict_records: int = 0
    scanned_records: int = 0
    notes: list[str] = dataclasses.field(default_factory=list)
    #: (plugin_key, row_count) 列表，用于登记 artifacts
    artifacts: list[dict[str, Any]] = dataclasses.field(default_factory=list)

    @property
    def total(self) -> int:
        return self.ioc_records + self.dict_records

    def summary(self) -> str:
        if not self.scanned_records:
            return "没有可扫描的记录（先跑内存/静态引擎产出结果）"
        bits = [f"扫描 {self.scanned_records} 条记录"]
        if self.ioc_records:
            bits.append(f"IOC {self.ioc_records} 项")
        if self.dict_records:
            bits.append(f"词典命中 {self.dict_records} 项")
        return "，".join(bits)


# ------------------------------------------------------------------ 聚合器


class _Agg:
    """按 key 聚合命中，保留出处与样例。"""

    __slots__ = ("value", "count", "sources", "sample", "payload")

    def __init__(self, value: str, payload: dict[str, Any], sample: str, source: str) -> None:
        self.value = value
        self.count = 1
        self.sources: dict[str, int] = {source: 1}
        self.sample = sample[:300]
        self.payload = payload

    def add(self, sample: str, source: str) -> None:
        self.count += 1
        self.sources[source] = self.sources.get(source, 0) + 1
        if len(self.sample) < 40 and sample:
            self.sample = sample[:300]


#: 这些字段是 MemLens 自己**派生**出来的元数据/上下文，不是原始证据内容。
#: 再扫一遍它们会制造大量假象：
#:   · ctx_ascii 是 hexdump 渲染（不可打印字节被替换成 `.`），扫它会产出
#:     `http://evil.top/g.php........` 这种被句点污染的畸形 URL；
#:   · 它还会把同一偏移前后两处内容黏在一起，产出 `g.phttp://c2.evil.t` 这类拼接垃圾；
#:   · sources/sample 是上一次扫描的结论，再扫就是"情报套情报"。
DERIVED_FIELDS: frozenset[str] = frozenset({
    "ctx_ascii", "ctx_hex", "sample", "sources", "source_plugin", "source_count",
    "ioc_type", "scope", "offset", "offset_hex", "encoding", "length",
    "severity", "tags", "note", "advice", "dict", "entry", "enrich_error",
})


def _string_fields(record: dict[str, Any], *, max_len: int = 20_000) -> list[tuple[str, str]]:
    """挑出记录里值得扫描的字符串字段（跳过超长的二进制样式字段与派生字段）。"""
    out: list[tuple[str, str]] = []
    for key, val in record.items():
        k = str(key).strip().lower()
        if k in DERIVED_FIELDS:
            continue
        if isinstance(val, str):
            if len(val) < 4:
                continue
            out.append((str(key), val[:max_len]))
        elif isinstance(val, (list, tuple)):
            for i, item in enumerate(val[:200]):
                if isinstance(item, str) and len(item) >= 4:
                    out.append((f"{key}[{i}]", item[:max_len]))
    return out


# ------------------------------------------------------------------ 主流程


def scan_case(
    store,
    case_id: str,
    *,
    dict_ids: Sequence[str] | None = None,
    extra_dicts: Sequence[Dictionary] | None = None,
    do_ioc: bool = True,
    ioc_kinds: Sequence[str] | None = None,
    max_records: int = 400_000,
    on_progress: Callable[[str], None] | None = None,
    cancel: Callable[[], bool] | None = None,
) -> ScanReport:
    """
    扫描一个案件的全部产物，产出情报。

    Args:
        store: DataStore 实例。
        case_id: 案件 ID。
        dict_ids: 只跑指定的内置词典；None 表示全跑。
        extra_dicts: 额外词典（用户自定义）。
        do_ioc: 是否做 IOC 自动提取。
        max_records: 最多扫描多少条记录（防止超大案件卡死）。
    """
    report = ScanReport(case_id=case_id)

    # ---- 选择词典 ----
    if dict_ids is None:
        chosen = list(builtin.ALL_DICTIONARIES)
    else:
        chosen = [d for d in (builtin.get(i) for i in dict_ids) if d is not None]
        unknown = set(dict_ids) - {d.id for d in chosen}
        if unknown:
            report.notes.append(f"未知词典已跳过：{', '.join(sorted(unknown))}")
    chosen.extend(extra_dicts or [])

    scanners: list[DictionaryScanner] = []
    for d in chosen:
        try:
            sc = DictionaryScanner(d)
            scanners.append(sc)
            for err in sc.errors:
                report.notes.append(f"[{d.name}] {err}")
        except Exception as exc:
            report.notes.append(f"[{d.name}] 编译失败：{exc}")

    # ---- 取记录 ----
    # ⚠ 必须排除 intel 自己的产物，否则第二次扫描会把上一次的扫描结果
    #   再当成输入扫描一遍（情报套情报，结果无意义且越来越慢）。
    rows = store.records_with_source(case_id, limit=max_records, skip_plugins=("intel.",))
    report.scanned_records = len(rows)
    seen_plugins = sorted({p for _rec, p in rows})
    if not rows:
        report.notes.append("该案件暂无成功产物记录")
        return report

    # ---- 聚合 ----
    ioc_agg: dict[tuple[str, str], _Agg] = {}
    dict_agg: dict[tuple[str, str, str], _Agg] = {}

    for idx, (record, plugin) in enumerate(rows):
        if cancel is not None and cancel():
            report.notes.append("扫描被取消")
            break
        if not isinstance(record, dict):
            continue
        for field, text in _string_fields(record):
            # ---- IOC ----
            if do_ioc:
                for item in ioc_mod.scan_text(text, kinds=ioc_kinds, limit_per_kind=64):
                    key = (item.kind, item.value)
                    payload = {"ioc_type": item.kind, "value": item.value}
                    payload.update({k: v for k, v in item.extra.items() if k != "note"})
                    snippet = text[max(0, item.span[0] - 40): (item.span[1] + 40)] if item.span else text[:120]
                    cur = ioc_agg.get(key)
                    if cur is None:
                        ioc_agg[key] = _Agg(item.value, payload, snippet, plugin)
                    else:
                        cur.add(snippet, plugin)
            # ---- 词典 ----
            for sc in scanners:
                for hit in sc.scan_text(text, filename=plugin, source_plugin=plugin,
                                        context_chars=50, max_hits=64):
                    key = (hit.dict_id, hit.entry_name, hit.value)
                    payload = {
                        "dict": hit.dict_name,
                        "entry": hit.entry_name,
                        "match": hit.value,
                        "severity": hit.severity,
                    }
                    if hit.tags:
                        payload["tags"] = ",".join(hit.tags)
                    if hit.note:
                        payload["note"] = hit.note
                    if hit.advice:
                        payload["advice"] = hit.advice
                    cur = dict_agg.get(key)
                    if cur is None:
                        dict_agg[key] = _Agg(hit.value, payload, hit.context, plugin)
                    else:
                        cur.add(hit.context, plugin)
        if on_progress and idx % 2000 == 0:
            on_progress(f"情报扫描 {idx}/{len(rows)}")

    # ---- 落库 ----
    if ioc_agg:
        rows_out = [_ioc_row(k, v) for k, v in sorted(
            ioc_agg.items(),
            key=lambda kv: (-_severity_rank(kv[1].payload), -kv[1].count, kv[0][1]),
        )]
        aid = store.start_artifact(case_id, ENGINE_NAME, IOC_PLUGIN,
                                   category="情报", kind="table", params={}, argv=["<intel-scan>"])
        n = store.add_records(aid, rows_out)
        store.finish_artifact(aid, status="ok", row_count=n, duration_ms=0)
        report.ioc_records = n
        report.artifacts.append({"plugin": IOC_PLUGIN, "rows": n})

    for sc in scanners:
        items = {k: v for k, v in dict_agg.items() if k[0] == sc.dict.id}
        if not items:
            # 区分"被 file_globs 路由整个挡掉了"和"扫了但没命中"——
            # 两者对使用者的含义完全不同，混为一谈会让人以为词典坏了。
            if not any(sc.dict.applies_to(p) for p in seen_plugins):
                report.notes.append(
                    f"[{sc.dict.name}] 未扫描任何产物：file_globs="
                    f"{','.join(sc.dict.file_globs) or '(不限)'} 与本次产物名不匹配"
                )
            else:
                report.notes.append(
                    f"[{sc.dict.name}] 已执行：未产生发现项（当前证据集不满足触发条件）")
            continue
        plugin_name = f"intel.dict.{sc.dict.id}"
        rows_out = [_dict_row(k, v) for k, v in sorted(
            items.items(),
            key=lambda kv: (-_severity_rank(kv[1].payload), -kv[1].count, kv[0][2]),
        )]
        aid = store.start_artifact(case_id, ENGINE_NAME, plugin_name,
                                   category="情报", kind="table",
                                   params={"dictionary": sc.dict.id}, argv=["<intel-scan>"])
        n = store.add_records(aid, rows_out)
        store.finish_artifact(aid, status="ok", row_count=n, duration_ms=0)
        report.dict_records += n
        report.artifacts.append({"plugin": plugin_name, "rows": n})

    report.notes.append(f"完成：{report.summary()}")
    return report


def _severity_rank(payload: dict[str, Any]) -> int:
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return order.get(str(payload.get("severity", "low")), 0)


def _ioc_row(key: tuple[str, str], agg: _Agg) -> dict[str, Any]:
    row = dict(agg.payload)
    row["count"] = agg.count
    row["sources"] = ", ".join(f"{k}×{v}" for k, v in
                               sorted(agg.sources.items(), key=lambda kv: -kv[1]))
    row["source_count"] = len(agg.sources)
    row["sample"] = agg.sample
    return row


def _dict_row(key: tuple[str, str, str], agg: _Agg) -> dict[str, Any]:
    row = dict(agg.payload)
    row["count"] = agg.count
    row["sources"] = ", ".join(f"{k}×{v}" for k, v in
                               sorted(agg.sources.items(), key=lambda kv: -kv[1]))
    row["source_count"] = len(agg.sources)
    row["sample"] = agg.sample
    return row


# ------------------------------------------------------------------ 辅助


def public_iocs(store, case_id: str, limit: int = 500) -> list[dict[str, Any]]:
    """便捷查询：取该案件的公网 IPv4 线索（出网行为的骨架）。"""
    rows = store.records_of_plugin(case_id, f"{IOC_PLUGIN}", limit=limit * 4)
    out = [r for r in rows if r.get("ioc_type") == "ipv4" and r.get("scope") == "公网"]
    return out[:limit]


def high_risk_records(store, case_id: str, limit: int = 500) -> list[dict[str, Any]]:
    """便捷查询：取全部高危以上的情报记录。"""
    out: list[dict[str, Any]] = []
    for plugin in [IOC_PLUGIN] + [f"intel.dict.{i}" for i in builtin.all_ids()]:
        for rec in store.records_of_plugin(case_id, plugin, limit=limit):
            sev = str(rec.get("severity", ""))
            if sev in ("high", "critical"):
                out.append({**rec, "_plugin": plugin})
    out.sort(key=lambda r: (r.get("severity") != "critical", -(int(r.get("count") or 1))))
    return out[:limit]
