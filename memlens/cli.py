"""
MemLens · 命令行入口

存在的意义：**让核心链路（探测 → 执行 → 入库 → 检测 → 导出）在没有 GUI 的情况下也能完整验证**。
GUI 只是这套能力的另一个前端；比赛时也可以用它做批量脚本化处理。

用法示例：
    python -m memlens.cli engines
    python -m memlens.cli probe  D:\\samples\\mem.raw
    python -m memlens.cli plugins --search 进程
    python -m memlens.cli analyze D:\\samples\\mem.raw --preset windows-basic
    python -m memlens.cli findings <case_id>
    python -m memlens.cli records  <case_id> --plugin psscan --limit 20
    python -m memlens.cli export   <case_id> --plugin psscan --out psscan.csv

    python -m memlens.cli analyze D:\\samples\\mem.raw --engine memstrings --plugins memstrings-full
    python -m memlens.cli intel    <case_id>
    python -m memlens.cli dict
    python -m memlens.cli timeline <case_id> --out timeline.csv
    python -m memlens.cli report   <case_id> --format html
    python -m memlens.cli knowledge --case <case_id>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# 允许 `python memlens/cli.py` 直接跑
if __package__ in (None, ""):  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from memlens.core.image_probe import (ContainerFormat, can_analyze, describe,
                                      probe_image)
from memlens.detectors.base import DetectionContext, run_all
from memlens.engines import registry
from memlens.storage.db import DataStore
from memlens.tasks.runner import TaskRunner

# ★ 打包后 __file__ 在 _internal 里，必须指向 exe 同级（与 web 的 STATE.workdir 一致），
#   否则 CLI 的 --json/--report 会导进 PyInstaller 解包目录（不稳定/易被清理）。
if getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).resolve().parent
else:
    PROJECT_ROOT = Path(__file__).resolve().parents[1]   # 即 MemLens/ 目录
DEFAULT_WORKDIR = PROJECT_ROOT / "work"
DEFAULT_DB = DEFAULT_WORKDIR / "memlens.db"

# ---------------------------------------------------------------------------
# 预设：一组常用插件（按"先易后难、先快后慢"排序，符合真实排查顺序）
# ---------------------------------------------------------------------------
PRESETS: dict[str, list[str]] = {
    # ---- MemProcFS（虚拟盘取证：一次收集 → 几十个产物，最快出结果）----
    "mprocfs-quick": [
        "mprocfs.harvest", "mprocfs.sysinfo", "mprocfs.process", "mprocfs.net",
        "mprocfs.netdns", "mprocfs.findevil", "mprocfs.registry_run", "mprocfs.users",
        "mprocfs.cmdlines", "mprocfs.envs", "mprocfs.flag_hits",
    ],
    "mprocfs-basic": [
        "mprocfs.harvest", "mprocfs.sysinfo", "mprocfs.process", "mprocfs.threads",
        "mprocfs.modules", "mprocfs.unloaded_modules", "mprocfs.net", "mprocfs.netdns",
        "mprocfs.findevil", "mprocfs.yara", "mprocfs.services", "mprocfs.drivers",
        "mprocfs.files", "mprocfs.registry_run", "mprocfs.registry_hives",
        "mprocfs.eventlog", "mprocfs.users", "mprocfs.timeline_process",
        "mprocfs.timeline_net",
    ],
    "mprocfs-deep": [
        "mprocfs.harvest", "mprocfs.sysinfo", "mprocfs.process", "mprocfs.threads",
        "mprocfs.modules", "mprocfs.unloaded_modules", "mprocfs.handles",
        "mprocfs.net", "mprocfs.netdns", "mprocfs.findevil", "mprocfs.yara",
        "mprocfs.services", "mprocfs.drivers", "mprocfs.devices",
        "mprocfs.virtualmachines", "mprocfs.files", "mprocfs.registry_run",
        "mprocfs.registry_hives", "mprocfs.eventlog", "mprocfs.bitlocker",
        "mprocfs.users", "mprocfs.procinfo", "mprocfs.timeline_process",
        "mprocfs.timeline_net", "mprocfs.timeline_thread", "mprocfs.timeline_ntfs",
        "mprocfs.timeline_registry", "mprocfs.timeline_kernelobject",
        "mprocfs.timeline_all",
    ],
    # ---- Volatility3（内存镜像）----
    "windows-quick": [
        "banners", "windows.info", "windows.pslist", "windows.psscan",
        "windows.netscan", "windows.cmdline",
    ],
    "windows-basic": [
        "banners", "windows.info", "windows.pslist", "windows.psscan", "windows.pstree",
        "windows.cmdline", "windows.dlllist", "windows.netscan", "windows.malfind",
        "windows.modules", "windows.svclist",
    ],
    "windows-deep": [
        "banners", "windows.info", "windows.pslist", "windows.psscan", "windows.pstree",
        "windows.psxview", "windows.cmdline", "windows.envars", "windows.privileges",
        "windows.dlllist", "windows.ldrmodules", "windows.handles", "windows.vadinfo",
        "windows.netscan", "windows.netstat", "windows.malfind", "windows.modules",
        "windows.modscan", "windows.driverscan", "windows.callbacks", "windows.ssdt",
        "windows.svclist", "windows.svcdiff", "windows.filescan",
        "windows.registry.hivelist", "windows.registry.hivescan",
        "windows.registry.userassist",
    ],
    # ---- 静态样本分析（PE / 未知二进制）----
    "static-full": [
        "static.profile", "static.pe", "static.strings", "static.packer",
    ],
    "static-quick": ["static.profile", "static.packer"],
    # ---- 镜像字节级扫描（不依赖 Volatility，任何容器都能跑）----
    "memstrings-quick": ["memstrings.flag", "memstrings.ioc"],
    "memstrings-full": ["memstrings.flag", "memstrings.ioc",
                        "memstrings.ascii", "memstrings.utf16"],
}

# 每个引擎的默认插件集（--plugins 留空时用它）
ENGINE_DEFAULT_PLUGINS: dict[str, str] = {
    "memprocfs": "mprocfs-basic",
    "vol3": "windows-basic",
    "static": "static-full",
    "memstrings": "memstrings-quick",
}

# 静态域"维度 ↔ 适用文件类型"映射。
# 背景：141 个真实样本批量分析时发现，每个文本/图片文件都跑全部 9 个维度，
# 产出 6 条"非 PE 文件"/"非流量包"式的废话记录，把真正的结论淹了。
# 这里按 file_type 过滤，让每个文件只跑**适用**的维度。
PLUGIN_APPLICABLE_TYPES: dict[str, frozenset[str]] = {
    "static.profile": frozenset({"__all__"}),          # 通用，永远适用
    "static.pe": frozenset({"pe"}),
    "static.elf": frozenset({"elf"}),
    "static.strings": frozenset({"__all__"}),
    "static.packer": frozenset({"pe", "elf"}),
    "static.deps": frozenset({"pe", "elf"}),
    "static.pcap": frozenset({"pcap", "pcapng"}),
    "static.archive": frozenset({"archive", "apk", "jar", "zip"}),
}


def _filter_by_type(engine, plugins, image: str):
    """按文件类型过滤不适用的维度（返回 (适用列表, 跳过原因列表)）。"""
    try:
        from memlens.engines.static import profile_file
        ftype = profile_file(image).file_type
    except Exception:
        return plugins, []
    keep, skipped = [], []
    for p in plugins:
        allow = PLUGIN_APPLICABLE_TYPES.get(p.name)
        if allow is None or "__all__" in allow or ftype in allow:
            keep.append(p)
        else:
            skipped.append(f"{p.name}(不适用于 {ftype})")
    return keep, skipped


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------
def _store(args) -> DataStore:
    db = Path(args.db) if getattr(args, "db", None) else DEFAULT_DB
    return DataStore(db)


def _engine(args):
    name = getattr(args, "engine", "vol3") or "vol3"
    engine = registry.get(name)
    # 与 GUI 同一套环境策略：缓存/符号表固定在工作目录下（必然可写、可移植、可离线复用）
    if name == "vol3":
        try:
            from memlens.core.vol3_env import Vol3Env
            workdir = Path(args.db).parent if getattr(args, "db", None) else DEFAULT_WORKDIR
            Vol3Env(workdir).apply(engine)
        except Exception:
            pass
    return engine


def _resolve_plugins(engine, spec: str) -> list:
    """
    把用户输入解析成插件清单。

    支持三种写法：
      * 预设名（preset）：windows-quick / windows-basic / windows-deep
      * 逗号分隔的简名：pslist,psscan,netscan
      * 完整插件名：windows.registry.hivelist
    """
    if spec in PRESETS:
        names = PRESETS[spec]
    else:
        names = [s.strip() for s in spec.split(",") if s.strip()]

    available = {p.name: p for p in engine.list_plugins()}
    # 建索引：全名 / 惯用简名 / 裸类名 → meta
    index: dict[str, object] = {}
    for full, meta in available.items():
        index[full] = meta
        parts = full.split(".")
        if len(parts) >= 2 and parts[-1][:1].isupper():
            index[".".join(parts[:-1])] = meta      # windows.pslist / banners
            index[parts[-1]] = meta                 # PsList / Banners
        else:
            index[parts[-1]] = meta                 # pslist

    resolved, missing = [], []
    for want in names:
        meta = index.get(want)
        if meta is None:
            # 兜底：后缀唯一匹配（用户可能只写 "pslist"）
            cands = {m.name: m for k, m in index.items()
                     if k == want or k.endswith("." + want)}
            meta = next(iter(cands.values())) if len(cands) == 1 else None
        if meta is None:
            missing.append(want)
        elif meta not in resolved:
            resolved.append(meta)
    if missing:
        print(f"⚠ 以下插件未找到（已跳过）：{', '.join(missing)}")
        print("  提示：用 `plugins --search <关键词>` 查看可用的插件名")
    return resolved


def _fmt_table(rows: list[dict], columns: list[str], limit: int = 20) -> str:
    if not rows:
        return "(无数据)"
    widths = {c: len(c) for c in columns}
    for r in rows[:limit]:
        for c in columns:
            widths[c] = max(widths[c], len(str(r.get(c, ""))[:40]))
    head = "  ".join(c.ljust(widths[c]) for c in columns)
    lines = [head, "-" * len(head)]
    for r in rows[:limit]:
        lines.append("  ".join(str(r.get(c, ""))[:40].ljust(widths[c]) for c in columns))
    if len(rows) > limit:
        lines.append(f"...（共 {len(rows)} 行，仅显示前 {limit} 行）")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 子命令实现
# ---------------------------------------------------------------------------
def cmd_engines(args) -> int:
    print("已注册引擎：", ", ".join(registry.installed()))
    print("-" * 60)
    for engine, ok, why in registry.iter_available():
        name = engine.display if engine else "(构造失败)"
        print(f"{'✅' if ok else '❌'} {name}：{why}")
    return 0


def cmd_probe(args) -> int:
    res = probe_image(args.image, deep=not args.fast, for_engine=args.engine)
    print(describe(res))
    if args.json:
        import dataclasses
        payload = dataclasses.asdict(res)
        payload["container"] = res.container.value
        payload["os_type"] = res.os_type.value
        payload["evidence"] = [dataclasses.asdict(e) for e in res.evidence]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_plugins(args) -> int:
    engine = _engine(args)
    ok, why = engine.available()
    if not ok:
        print(f"❌ 引擎不可用：{why}")
        return 2
    plugins = engine.list_plugins(refresh=args.refresh)
    if args.search:
        plugins = engine.search_plugins(args.search, plugins)
    print(f"{engine.display}：共 {len(plugins)} 个插件（过滤后显示）")
    print("-" * 78)
    cat = None
    for p in plugins:
        if p.category != cat:
            cat = p.category
            print(f"\n【{cat}】")
        print(f"  {p.name:<44} {p.display}")
    return 0


def _plugin_params(args) -> dict:
    """
    组装传给引擎的参数。

    ⚠ 只把**显式开启**的开关放进来：这些参数会参与产物缓存键，
    无脑塞一堆默认 False 会让历史缓存全部失效（"明明没改参数却要重跑一遍"）。
    """
    params: dict = {"renderer": getattr(args, "renderer", "jsonl")}
    if getattr(args, "offline", False):
        params["offline"] = True
    # `--param k=v` 供需要额外参数的产物使用：pid=1456（单进程视图/内存 dump）、
    # key=HKLM\...（读任意注册表键）。配合 --no-cache 避免命中旧参数的结果。
    for raw in (getattr(args, "param", None) or []):
        if "=" not in str(raw):
            continue
        k, v = str(raw).split("=", 1)
        k, v = k.strip(), v.strip()
        if k:
            params[k] = int(v) if v.isdigit() else v
    return params


def cmd_analyze(args) -> int:
    engine = _engine(args)
    ok, why = engine.available()
    if not ok:
        print(f"❌ 引擎不可用：{why}")
        return 2

    print(f"[1/5] 探测镜像：{args.image}")
    probe = probe_image(args.image, deep=not args.fast, for_engine=args.engine)
    print("      " + probe.summary())
    for w in probe.warnings:
        print(f"      ⚠ {w}")
    # 统一可分析性判断（与 GUI 按钮状态、worker 共用同一份逻辑，避免逻辑漂移）
    ok_analyze, why_not = can_analyze(probe, args.engine)
    if not ok_analyze and not args.force:
        print(f"\n❌ {why_not}")
        print("如需强制尝试请加 --force")
        if probe.container is ContainerFormat.EXECUTABLE:
            print("提示：这是 PE 样本，试试 --engine static")
        elif probe.container is ContainerFormat.ELF_BIN:
            print("提示：这是 ELF 样本，试试 --engine static")
        return 3

    # 插件集：显式指定 > 引擎默认
    spec = args.plugins or ENGINE_DEFAULT_PLUGINS.get(args.engine, "")

    store = _store(args)
    print(f"[2/5] 建立案件（计算镜像哈希…）")
    case_id = store.create_case(
        args.case_name or Path(args.image).stem,
        args.image,
        container=probe.container.value,
        os_type=probe.os_type.value,
        os_confidence=probe.os_confidence,
        notes=f"probe: {probe.container.value}/{probe.os_type.value}",
        hash_limit=64 << 20 if args.fast_hash else None,
    )
    print(f"      案件 ID：{case_id}")

    print(f"[3/5] 解析插件清单并执行")
    plugins = _resolve_plugins(engine, spec)
    if not plugins:
        print("❌ 没有可执行的插件")
        return 4
    if engine.name == "static":
        plugins, skipped = _filter_by_type(engine, plugins, args.image)
        if skipped:
            print(f"      按文件类型跳过 {len(skipped)} 个不适用维度："
                  + ", ".join(skipped[:4]) + ("…" if len(skipped) > 4 else ""))
    if not plugins:
        print("❌ 该文件类型没有适用的分析维度")
        return 4
    print(f"      将执行 {len(plugins)} 个插件："
          + ", ".join(p.name for p in plugins[:6]) + ("…" if len(plugins) > 6 else ""))

    runner = TaskRunner(store, engine, workdir=DEFAULT_WORKDIR / "artifacts")
    def on_line(line: str) -> None:
        if line.strip():
            print(f"      | {line[:150]}")

    results = []
    for i, p in enumerate(plugins, 1):
        print(f"      ({i}/{len(plugins)}) {p.display} [{p.name}] …", flush=True)
        res = runner.run_plugin(
            case_id, p,
            _plugin_params(args),
            on_line=on_line if args.verbose else None,
            timeout=args.timeout,
            cache=not args.no_cache,
        )
        mark = {"ok": "✔", "partial": "△", "failed": "✘", "cancelled": "⊘"}.get(res.status, "?")
        print(f"        {mark} {res.status}  行数={res.rows}  耗时={res.duration_ms}ms"
              + (f"  错误：{res.error}" if res.error else ""))
        results.append(res)

    print(f"[4/5] 运行检测器")
    ctx = DetectionContext(store, case_id)
    findings, notes = run_all(ctx)
    store.clear_findings(case_id)
    for d in findings:
        store.add_finding(
            case_id, title=d.title, detector=d.detector, rule_id=d.rule_id,
            description=d.description, severity=d.severity, confidence=d.confidence,
            sources=d.sources, evidence=d.evidence,
        )
    for n in notes:
        print(f"      · {n}")
    print(f"      共 {len(findings)} 条发现项")
    for d in findings[:10]:
        print(f"      [{d.severity.upper():^8}] {d.confidence:.0%}  {d.title}")
    if len(findings) > 10:
        print(f"      …（还有 {len(findings) - 10} 条，用 findings {case_id} 查看）")

    print(f"[5/5] 汇总")
    st = store.stats(case_id)
    print(f"      案件 {case_id}：{st['artifacts']} 个产物 / {st['records']} 条记录 / "
          f"{st['findings']} 条发现项 {st['findings_by_severity']}")
    store.close()

    if any(r.status == "failed" for r in results):
        print("\n⚠ 有插件执行失败，详情用 `case %s` 查看" % case_id)
    return 0


def cmd_cases(args) -> int:
    store = _store(args)
    cases = store.list_cases()
    if not cases:
        print("（还没有案件）")
        return 0
    for c in cases:
        st = store.stats(c["case_id"])
        print(f"{c['case_id']}  {c['name'][:28]:<28} {c['container'] or '-':<7} "
              f"{c['os_type'] or '-':<8} {st['records']:>7} 记录  {st['findings']:>3} 发现  "
              f"{c['created_at']}")
    store.close()
    return 0


def cmd_case(args) -> int:
    store = _store(args)
    case = store.get_case(args.case_id)
    if not case:
        print(f"案件不存在：{args.case_id}")
        return 1
    print("=" * 70)
    for k in ("case_id", "name", "image_path", "image_size", "image_sha256",
              "container", "os_type", "os_confidence", "created_at"):
        print(f"{k:<15}: {case.get(k)}")
    print("=" * 70)
    print("产物清单：")
    for a in store.list_artifacts(args.case_id):
        mark = {"ok": "✔", "partial": "△", "failed": "✘", "running": "…"}.get(a["status"], "?")
        print(f"  {mark} {a['plugin']:<42} {a['status']:<8} {a['row_count']:>6} 行 "
              f"{a['duration_ms'] or 0:>7}ms")
        if a["error"]:
            print(f"      └ {str(a['error'])[:150]}")
    st = store.stats(args.case_id)
    print(f"\n统计：{st}")
    store.close()
    return 0


def cmd_findings(args) -> int:
    store = _store(args)
    findings = store.list_findings(args.case_id, severity=args.severity)
    if not findings:
        print("（没有发现项）")
        return 0
    for f in findings:
        print("=" * 70)
        print(f"[{f['severity'].upper()}] 置信度 {f['confidence']:.0%}  {f['title']}")
        print(f"检测器：{f['detector']}   证据源：{', '.join(f['sources'])}")
        if args.verbose and f["description"]:
            print(f"说明：{f['description']}")
        if args.verbose and f["evidence"]:
            print("证据：" + json.dumps(f["evidence"], ensure_ascii=False, indent=2)[:1500])
    store.close()
    return 0


def cmd_records(args) -> int:
    store = _store(args)
    if args.plugin:
        rows = store.records_of_plugin(args.case_id, f"%{args.plugin}%", limit=args.limit)
        rows = [{**r} for r in rows]
    else:
        rows = [r["parsed"] for r in store.query_records(case_id=args.case_id, limit=args.limit,
                                                          keyword=args.keyword)]
    if args.keyword:
        kw = args.keyword.lower()
        rows = [r for r in rows if kw in json.dumps(r, ensure_ascii=False).lower()]
    if not rows:
        print("（无记录）")
        return 0
    cols = list(rows[0].keys())[:args.cols]
    print(_fmt_table(rows, cols, limit=args.limit))
    store.close()
    return 0


def cmd_export(args) -> int:
    store = _store(args)
    if args.plugin:
        # 插件名可能不完整（用户常写简名），做模糊查找
        arts = [a for a in store.list_artifacts(args.case_id) if args.plugin in a["plugin"]]
        if not arts:
            print(f"找不到插件产物：{args.plugin}")
            return 1
        n = store.export_records_csv(args.out, artifact_id=arts[0]["artifact_id"])
    else:
        n = store.export_records_csv(args.out, case_id=args.case_id)
    print(f"已导出 {n} 行 → {args.out}")
    store.close()
    return 0


# ---------------------------------------------------------------------------
def cmd_intel(args) -> int:
    """对已有案件跑情报扫描（IOC 提取 + 词典匹配），结果入库可继续查询。"""
    from memlens.intel import builtin, scan

    store = _store(args)
    if store.get_case(args.case_id) is None:
        print(f"❌ 案件不存在：{args.case_id}")
        return 1

    dict_ids = [d.strip() for d in args.dicts.split(",") if d.strip()] if args.dicts else None
    if dict_ids:
        unknown = [d for d in dict_ids if builtin.get(d) is None]
        if unknown:
            print(f"❌ 未知词典：{', '.join(unknown)}")
            print(f"   可用：{', '.join(builtin.all_ids())}")
            return 2

    rep = scan.scan_case(store, args.case_id, dict_ids=dict_ids,
                         do_ioc=not args.no_ioc)
    print(f"情报扫描：{rep.summary()}")
    for n in rep.notes:
        print(f"  · {n}")

    rows = store.records_of_plugin(args.case_id, scan.IOC_PLUGIN, limit=args.limit)
    if rows and args.show_ioc:
        print("\n【IOC】")
        print(_fmt_table(rows, ["ioc_type", "value", "scope", "count", "sources"], limit=args.limit))

    for did in (dict_ids or builtin.all_ids()):
        drows = store.records_of_plugin(args.case_id, f"intel.dict.{did}", limit=args.limit)
        if drows:
            print(f"\n【{builtin.get(did).name if builtin.get(did) else did}】")
            print(_fmt_table(drows, ["entry", "match", "severity", "count", "advice"], limit=args.limit))
    store.close()
    return 0


def cmd_dict(args) -> int:
    """查看内置词典清单或某个词典的条目。"""
    from memlens.intel import builtin

    if args.id:
        d = builtin.get(args.id)
        if d is None:
            print(f"❌ 未知词典：{args.id}")
            print(f"   可用：{', '.join(builtin.all_ids())}")
            return 2
        print(f"{d.name}（{d.id}）  条目 {len(d)}  file_globs={','.join(d.file_globs) or '不限'}")
        print(d.description)
        for e in d.entries:
            print(f"\n  · {e.name}  [severity={e.severity}]")
            if e.note:
                print(f"    说明：{e.note}")
            if e.advice:
                print(f"    建议：{e.advice}")
            for p in e.patterns[:8]:
                print(f"      模式：{p}")
            if len(e.patterns) > 8:
                print(f"      …… 另有 {len(e.patterns) - 8} 条")
        return 0

    print("内置词典：")
    print("-" * 70)
    for d in builtin.ALL_DICTIONARIES:
        route = ",".join(d.file_globs) or "不限"
        print(f"  {d.id:<22} {d.name:<12} 条目 {len(d):<3} 路由={route}")
        print(f"      {d.description}")
    return 0


def cmd_timeline(args) -> int:
    """导出案件时间线。"""
    from memlens import timeline as tl

    store = _store(args)
    if store.get_case(args.case_id) is None:
        print(f"❌ 案件不存在：{args.case_id}")
        return 1
    rows = store.records_with_source(args.case_id, skip_plugins=("intel.",))
    events = tl.build_timeline(rows, limit=args.limit, include_untimed=args.include_untimed)
    if not events:
        print("（未提取到带时间戳的记录）")
        store.close()
        return 0
    if args.out:
        n = tl.to_csv(events, args.out)
        print(f"已导出时间线 {n} 条 → {args.out}")
    else:
        print(f"共 {len(events)} 条事件：")
        for e in events[:args.limit]:
            t = e.ts.strftime("%Y-%m-%d %H:%M:%S") if e.ts else (e.raw_time or "—")
            print(f"  {t:<20} {e.source_plugin:<32} {e.title[:90]}")
    store.close()
    return 0


def cmd_report(args) -> int:
    """生成分析报告（Markdown / HTML）。"""
    from memlens import report as rp

    store = _store(args)
    if store.get_case(args.case_id) is None:
        print(f"❌ 案件不存在：{args.case_id}")
        return 1
    out = args.out or str(DEFAULT_WORKDIR / f"report_{args.case_id}.{args.format}")
    path = rp.export(store, args.case_id, out, fmt=args.format,
                     max_timeline=args.max_timeline)
    size = os.path.getsize(path)
    print(f"报告已生成：{path}（{size:,} 字节）")
    store.close()
    return 0


def cmd_knowledge(args) -> int:
    """查询取证知识库：不给关键词则按本案已跑插件推荐。"""
    from memlens.intel import knowledge

    kbp = knowledge.kb()
    if args.keyword:
        hits = kbp.search(args.keyword)
        if not hits:
            print(f"（没有匹配「{args.keyword}」的条目）")
            return 0
        for k in hits:
            print(knowledge.describe(k))
            print()
        return 0

    store = _store(args)
    if args.case_id:
        arts = store.list_artifacts(args.case_id)
        hits = kbp.match_artifacts(arts)
        print(f"依据案件 {args.case_id} 已运行的 {len(arts)} 项产物，推荐 {len(hits)} 条要点：\n")
    else:
        hits = [(k, k.keywords) for k in kbp.entries]
        print(f"知识库共 {len(hits)} 条：\n")
    for k, kw in hits:
        print(knowledge.describe(k))
        print(f"  命中关键词：{', '.join(kw)}\n")
    store.close()
    return 0


# ---------------------------------------------------------------------------
def cmd_browser_history(args) -> int:
    """
    本机浏览器历史采集（**按需触发**：不调用这条命令就不会读任何浏览器数据）。

    只读副本 + 不联网；支持 Edge/Chrome/Brave/Vivaldi/360/QQ浏览器 与 Firefox。
    """
    from memlens.core import browser_history as bh

    all_drives = bool(getattr(args, "all_drives", False))
    appdata = str(getattr(args, "appdata", "") or "").strip()
    src = (bh.discover_in_appdata(appdata) if appdata
           else bh.sources_report(all_drives=all_drives))
    if args.sources:
        print(f"发现 {len(src)} 个浏览器历史库"
              + ("（全盘扫描）" if all_drives else "")
              + (f"（AppData: {appdata}）" if appdata else "") + "：")
        for s in src:
            extra = f" [{s.get('drive','')}]" if s.get("drive") else ""
            print(f"  {s['browser']:<10} {s['profile']:<22} {s['size_mb']:>7.2f} MB{extra}  {s['path']}")
        if not src:
            print("  （未发现；可能没装这些浏览器，或历史库被清理过）")
        return 0

    if not src:
        print("❌ 未发现任何浏览器历史库")
        print("   可用 --sources 查看探测详情；--all-drives 做全盘扫描；Edge/Chrome 需至少用过一次")
        return 1

    print(f"[1/3] 探测到 {len(src)} 个历史库，开始采集"
          + ("（全盘扫描，只读副本，不上传）…" if all_drives else
             (f"（AppData: {appdata}）…" if appdata else "（只读副本，不上传）…")))
    visits = bh.collect(browser=args.browser, profile=args.profile,
                        since=args.since, until=args.until,
                        keyword=args.keyword, limit=args.limit,
                        all_drives=all_drives,
                        appdata=appdata or None)
    if not visits:
        print("⚠ 没有匹配的访问记录（检查 --browser/--since/--keyword）")
        return 0

    s = bh.summarize(visits)
    print(f"[2/3] 采集到 {s['total']:,} 条访问（{s['first']} → {s['last']}）")
    print(f"      按浏览器：{' / '.join(f'{k} {v:,}' for k, v in s['by_browser'].items())}")

    # ★ 境外 IP + 风险分级（--risk / --report）
    if getattr(args, "risk", False) or getattr(args, "report", ""):
        from memlens.core import browser_report as br
        ip_map = {}
        if getattr(args, "ip_map", ""):
            with open(args.ip_map, encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        ip_map[parts[0].lower()] = parts[1]
        report = br.build_report(visits, ip_map=ip_map)
        ssum = report["summary"]
        print(f"\n[★ 境外 IP 风险] 总访问 {ssum['total']:,} 条，"
              f"境外（疑似）{ssum['overseas_count']} 条，"
              f"风险 高{ssum['by_risk']['高']} / 中{ssum['by_risk']['中']} / 低{ssum['by_risk']['低']}")
        if getattr(args, "risk", False):
            for o in report["overseas_access"][:args.show]:
                print(f"  [{o['risk']}] {o['visited_at']} {o['browser']:<6} {o['host']} "
                      f"ip={o['ip'] or '-'} {o['country']} {'；'.join(o['reasons'][:3])}")
        rep = getattr(args, "report", "")
        if rep:
            if rep.endswith(".json"):
                br.export_json(report, rep)
                print(f"✔ 报告 JSON：{rep}")
            elif rep.endswith(".csv"):
                n = br.export_csv(report, rep)
                print(f"✔ 报告 CSV：{rep}（{n} 行）")
            else:
                Path(rep).parent.mkdir(parents=True, exist_ok=True)
                Path(rep).write_text(br.export_markdown(report), encoding="utf-8")
                print(f"✔ 报告 Markdown：{rep}")

    print("      Top 域名：")
    for d in s["top_domains"][:args.top]:
        print(f"        {d['域名']:<38} {d['次数']:>6}")

    print(f"\n[3/3] 最近 {min(args.show, len(visits))} 条：")
    for v in visits[:args.show]:
        title = (v.title or "")[:40]
        print(f"  {v.visited_at}  {v.browser:<6} {title:<40} {v.url[:80]}")

    out = args.out
    if out:
        n = bh.export_csv(visits, out)
        print(f"\n✔ 全量 CSV 已导出：{out}（{n:,} 行）")
    elif args.json:
        out = str(DEFAULT_WORKDIR / "browser_history.json")
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(
            {"summary": s, "visits": [v.as_dict() for v in visits]},
            ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n✔ JSON 已导出：{out}")
    else:
        print("\n提示：加 `--out 路径.csv` 导出全量，或 `--json` 导出 JSON")
    return 0


def cmd_url_analyze(args) -> int:
    """
    URL / 境外 IP 分析：解析 URL → 域名 / IP / 境外识别 / 风险等级。

    纯本地不联网（除非 --resolve 做 DNS）。境外识别用内置中国网段
    （离线、保守：未命中公有 IP 判"境外（疑似）"）；--ip-map 提供 域名=IP
    映射（从 pcap/流量提取）可避免误判。
    """
    from memlens.core import url_analyze as ua

    # ★ 扫描器 result.txt 解析（WP 0x05 内网扫描输出：[url]/[title]/[finger]/[icmp]）
    if getattr(args, "scanner", ""):
        with open(args.scanner, encoding="utf-8-sig", errors="ignore") as f:
            txt = f.read()
        r = ua.parse_scanner_output(txt)
        print(f"扫描器输出解析：{len(r['items'])} 个 URL，{len(r['icmp_hosts'])} 个 ICMP 存活主机")
        print(f"{'风险':<4} {'归属':<6} {'URL':<44} {'端口':<6} {'title/指纹':<30}")
        for it in r["items"]:
            flag = ("境外" if it["country"] == "境外（疑似）"
                    else "内网" if it["country"] == "内网"
                    else "境内" if it["ip"] else "待解析")
            meta = (it.get("title") or it.get("fingerprint") or "")[:30]
            print(f"{it['risk']:<4} {flag:<6} {it['url'][:44]:<44} {it['port'] or '-':<6} {meta}")
        print(f"\n汇总：高{r['stats']['by_risk']['高']} / 中{r['stats']['by_risk']['中']} / "
              f"低{r['stats']['by_risk']['低']}，境外（疑似）{r['stats']['overseas']}")
        if getattr(args, "json", False):
            out = str(DEFAULT_WORKDIR / "scanner_parse.json")
            Path(out).parent.mkdir(parents=True, exist_ok=True)
            Path(out).write_text(json.dumps(r, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
            print(f"✔ JSON 已导出：{out}")
        return 0

    urls = list(getattr(args, "urls", []) or [])
    if getattr(args, "file", ""):
        with open(args.file, encoding="utf-8") as f:
            urls.extend(line.strip() for line in f
                        if line.strip() and not line.startswith("#"))
    if not urls:
        print("用法：MemLens.exe url-analyze <url...> [--file 列表] [--resolve] [--ip-map 文件]")
        return 1

    ip_map = {}
    if getattr(args, "ip_map", ""):
        with open(args.ip_map, encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    ip_map[parts[0].lower()] = parts[1]

    items = ua.analyze_urls(urls, resolve=getattr(args, "resolve", False),
                            ip_map=ip_map)
    print(f"分析 {len(items)} 个 URL"
          + ("（DNS 解析）" if getattr(args, "resolve", False) else "（离线；--resolve 可解析域名）"))
    print(f"{'风险':<4} {'归属':<6} {'域名':<34} {'IP':<16} 原因")
    for it in items:
        if it.country == "境外（疑似）":
            flag = "境外"
        elif it.country == "内网":
            flag = "内网"
        elif it.ip:
            flag = "境内"
        else:
            flag = "待解析"
        print(f"{it.risk:<4} {flag:<6} {it.host[:34]:<34} {(it.ip or '-')[:16]:<16} "
              f"{'；'.join(it.reasons[:4])}")
    st = ua.risk_stats(items)
    print(f"\n汇总：高{st['by_risk']['高']} / 中{st['by_risk']['中']} / 低{st['by_risk']['低']}，"
          f"境外（疑似）{st['overseas']} 条")
    if getattr(args, "json", False):
        out = str(DEFAULT_WORKDIR / "url_analyze.json")
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps([it.as_dict() for it in items],
                                        ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"✔ JSON 已导出：{out}")
    return 0


def cmd_web_log(args) -> int:
    """
    网站访问日志分析（WP 0x05 服务器取证）：攻击者IP / 可疑请求 / 一句话木马 SHA-256。

    解析 nginx/apache access log（common/combined 格式），纯本地文本解析，
    不依赖挂载系统（日志可由 MemLens 容器/XFS 通道提取后传入）。
    """
    from memlens.core import web_log_analyze as wl

    if not getattr(args, "log", ""):
        print("用法：MemLens.exe web-log <access.log> [--keyword 路径过滤] [--json]")
        return 1
    with open(args.log, encoding="utf-8-sig", errors="ignore") as f:
        txt = f.read()
    r = wl.analyze_access_log(txt, keyword=getattr(args, "keyword", "") or "")
    s = r["summary"]
    print(f"日志分析：共 {s['total_lines']} 行，可疑请求 {s['suspicious_count']}，"
          f"攻击者 {s['attacker_count']}，一句话木马 {s['webshell_count']}")
    print("\n[攻击者 IP]（按可疑请求排序）")
    for a in r["attackers"][:20]:
        print(f"  {a['ip']:<18} 请求{a['requests']:>5} 可疑{a['suspicious']:>3} "
              f"上传{a['uploads']:>3}  路径示例：{', '.join(a['paths'][:2])[:60]}")
    if r["webshell"]:
        print("\n[一句话木马]")
        for w in r["webshell"]:
            print(f"  SHA256={w['sha256']}")
            print(f"    内容：{w['snippet'][:90]}")
    if not r["attackers"] and not r["webshell"]:
        print("\n（未发现攻击者/木马；检查日志格式是否为 nginx/apache combined）")
    if getattr(args, "json", False):
        out = str(DEFAULT_WORKDIR / "web_log.json")
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n✔ JSON 已导出：{out}")
    return 0


def cmd_server(args) -> int:
    """
    服务器文件级取证（WP 0x05）：wtmp/passwd/trojan/php/sql，不挂载系统。

    MemLens.exe server <wtmp|passwd|trojan|php|sql> <文件> [--password 明文]
    """
    from memlens.core import server_forensics as sf

    kind, path = getattr(args, "kind", ""), getattr(args, "path", "")
    if not path:
        print("用法：MemLens.exe server <wtmp|passwd|trojan|php|sql> <文件> [--password 明文]")
        return 1
    result: dict = {}
    try:
        if kind == "wtmp":
            result = sf.parse_wtmp(path)
            print(f"开机次数 {result['boot_count']}，最早 {result['earliest']}，最新 {result['latest']}")
        elif kind == "passwd":
            with open(path, encoding="utf-8", errors="ignore") as f:
                result = sf.parse_passwd(f.read())
            print(f"用户数 {result['count']}：{', '.join(u['name'] for u in result['users'])}")
        elif kind == "trojan":
            with open(path, encoding="utf-8-sig", errors="ignore") as f:
                result = sf.parse_trojan_config(f.read())
            if "error" in result:
                print(f"解析失败：{result['error']}"); return 1
            print(f"run_type={result.get('run_type')}  local={result.get('local_addr')}:{result.get('local_port')}  "
                  f"remote={result.get('remote_addr')}:{result.get('remote_port')}  域名={result.get('remote_domain') or '-'}")
        elif kind == "php":
            with open(path, encoding="utf-8-sig", errors="ignore") as f:
                result = sf.parse_php_encrypt(f.read(), getattr(args, "password", "") or "")
            print(f"AUTH_CODE={result['auth_code']}  算法={result['algorithm']}")
            for pw, h in result["hashes"].items():
                print(f"  md5('{result['auth_code']}' + '{pw}') = {h}")
        elif kind == "sql":
            with open(path, encoding="utf-8-sig", errors="ignore") as f:
                txt = f.read()
            start = int(datetime(2016, 4, 1).timestamp())
            end = int(datetime(2025, 4, 1).timestamp())
            result = sf.parse_sql_orders(txt, start, end)
            result["gap"] = sf.parse_sql_first_order_gap(txt)
            print(f"订单数（2016-04-01 00:00:00 ~ 2025-04-01 00:00:00）：{result['orders']}")
            if result["gap"]["best"]:
                b = result["gap"]["best"]
                print(f"注册→首单间隔最短用户：{b['user_id']}  间隔 {b['gap']}s "
                      f"（注册 {b['reg_str']} / 首单 {b['first_order_str']}）")
        else:
            print("未知类型，应为 wtmp/passwd/trojan/php/sql"); return 1
    except Exception as exc:
        print(f"解析失败：{exc}"); return 1
    if getattr(args, "json", False):
        out = str(DEFAULT_WORKDIR / f"server_{kind}.json")
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"✔ JSON 已导出：{out}")
    return 0


def cmd_server_solve(args) -> int:
    """
    服务器检材一键求解（WP 0x05）：
    打开 VeraCrypt→exFAT→VMDK→LVM→XFS，一次全盘内容扫描定位各题文件并解析。

    MemLens.exe server-solve <镜像> --password <口令> [--plain <题7明文>]
    """
    from memlens.formats.xfs import open_server_fs
    from memlens.core import server_forensics as sf

    img = getattr(args, "target", "")
    pw = getattr(args, "password", "") or ""
    if not img:
        print("用法：MemLens.exe server-solve <镜像> --password <口令> [--plain 明文]")
        return 1

    def prog(done, total, n_hits):
        pct = done * 100 // total if total else 0
        if pct % 10 == 0 and done % (4 << 30) < (32 << 20):
            print(f"  [进度] 全盘内容扫描 {pct}%（{n_hits} 命中）", flush=True)

    print(f"打开服务器文件系统：{img}", flush=True)
    x, meta = open_server_fs(img, pw)
    xs = x.summary()
    print(f"  XFS：{xs.get('total_gb')} GB  dblocks={xs.get('dblocks')} bs={xs.get('blocksize')} "
          f"lv={meta.get('lvm_lv')} xfs_offset={meta.get('lvm_offset')}", flush=True)

    work = DEFAULT_WORKDIR
    work.mkdir(parents=True, exist_ok=True)
    cache = work / "server_solve_hits.json"
    do_scan = bool(getattr(args, "rescan", False)) or not cache.exists()
    print(("全盘内容扫描（合成 FS 的 extent 不可信，须按内容定位文件）…"
           if do_scan else "从缓存读取扫描命中（--rescan 可强制重扫）…"), flush=True)
    res = sf.solve_server_fs(
        x, progress_cb=prog,
        password=getattr(args, "plain", "") or "sbwyz1",
        region=getattr(args, "region", 4 << 20),
        hits_cache=str(cache), rescan=do_scan)

    print("\n===== 服务器取证求解结果 =====", flush=True)
    # wtmp 是"全盘最早开机时间"的汇总（不是文件片段），单独打印
    w = res.get("wtmp")
    if isinstance(w, dict):
        print(f"\n[wtmp] boot 记录 {w.get('boot_count')} 条", flush=True)
        print(f"   最早开机：{w.get('earliest')}   内核：{w.get('earliest_kernel')}", flush=True)
        for b in w.get("boots", []):
            print(f"   - {b.get('boot_str')}  {b.get('kernel')}  (blk {b.get('blk')})", flush=True)

    for name, items in res.items():
        if name == "wtmp":
            continue
        if not items:
            print(f"\n[{name}] 未定位到有效文件", flush=True)
            continue
        print(f"\n[{name}] {len(items)} 处命中", flush=True)
        for it in items[:3]:
            r = it["result"]
            print(f"   blk {it['blk']} off {it['off']}", flush=True)
            if isinstance(r, dict):
                for k, v in r.items():
                    if v:
                        print(f"      {k}: {v}", flush=True)
            elif r:
                print(f"      {r}", flush=True)
    if getattr(args, "json", False):
        out = str(work / "server_solve.json")
        work.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n✔ JSON 已导出：{out}", flush=True)
    return 0


# ---------------------------------------------------------------------------
def cmd_search(args) -> int:
    """
    跨产物检索（方案 §2.4「分析」能力：能查才能用）。

    用法：
        search <案件ID> <关键词...> [--scope records,findings,timeline]
        search <案件ID> --container <容器文件> --password <口令> --keywords a,b
        search <案件ID> <关键词> --regex
    """
    from memlens.core.search import Query, search, scan_container
    from memlens.core.veracrypt_volume import VeraCryptVolume
    from memlens.core.exfat import ExFat

    store = _store(args)
    try:
        if args.container:
            # 在加密容器内做内容检索（不落盘）
            vol = VeraCryptVolume(args.container, args.password or "")
            fs = ExFat(vol)
            names = args.keywords.split(",") if args.keywords else []
            q = Query(" ".join(names), regex=args.regex)
            hits = []
            for e in fs.list_dir(fs.root_cluster):
                if e["is_dir"]:
                    continue
                hits += scan_container(vol, fs, e, q, source=e["name"],
                                       case_id=args.case_id, limit=args.limit)
                if len(hits) >= args.limit:
                    break
            vol.close()
            rows = [{"产物": h.source, "偏移": h.offset,
                     "上下文": h.context} for h in hits[:args.limit]]
            print(f"容器检索「{q.describe()}」命中 {len(rows)} 处")
            for r in rows:
                print(f"  [{r['产物']}] @{r['偏移']:,}")
                print(f"     {r['上下文']}")
            return 0

        q_text = " ".join(args.keywords)
        scopes = args.scope.split(",") if args.scope else ["records", "findings", "timeline"]
        res = search(store, args.case_id, q_text, scopes=scopes,
                     regex=args.regex, limit=args.limit)
        print(f"检索「{res['parsed']}」 命中 {res['count']} 条  用时 {res['elapsed']}s")
        for h in res["hits"]:
            loc = f"#{h['row_no']}" if h.get("row_no") is not None else ""
            ts = ("  " + h["ts"]) if h.get("ts") else ""
            print(f"  [{h['scope']}] {h['source']} {loc}{ts}")
            print(f"     {h['context']}")
        return 0
    finally:
        store.close()


# ---------------------------------------------------------------------------
def cmd_container(args) -> int:
    """
    取证容器通道（方案 §2.2 数据接入 / §2.3 非内存镜像检材）。

    用法：
        container identify <文件>
        container files    <文件> --password <加密卷口令>
        container extract  <文件> --password <口令> --path <卷内路径>
        container crypto   <文件> --password <口令>
        container traffic  <pcapng> --kind interfaces|bluetooth|rename|hid
        container apk      <apk>
    """
    from memlens.engines.container import ContainerEngine

    eng = ContainerEngine(workdir=Path(getattr(args, "db", None) or DEFAULT_DB).parent)
    sub = args.container_cmd

    def _run(plugin: str, params: dict) -> int:
        meta = next(p for p in eng.list_plugins() if p.name == plugin)
        spec = eng.build_run(meta, args.target, params)
        rows = list(eng.parse_records(spec, "", ""))
        if not rows:
            print("(无记录)")
            return 0
        cols = list(rows[0].keys())
        w = {c: max(len(c), max((len(str(r.get(c, ""))) for r in rows), default=0)) for c in cols}
        w = {c: min(v, 90) for c, v in w.items()}
        print(" | ".join(c.ljust(w[c]) for c in cols))
        print("-" * (sum(w.values()) + 3 * len(cols)))
        for r in rows:
            print(" | ".join(str(r.get(c, "")).replace("\n", " ")[:w[c]].ljust(w[c]) for c in cols))
        print(f"\n共 {len(rows)} 行")
        return 0

    try:
        if sub == "identify":
            from memlens.engines.container import identify_container
            for k, v in identify_container(args.target).items():
                print(f"  {k:10} {v}")
            return 0
        if sub == "files":
            return _run("container.files", {"password": args.password or ""})
        if sub == "extract":
            return _run("container.extract",
                        {"password": args.password or "", "path": args.path or ""})
        if sub == "crypto":
            return _run("container.crypto", {"password": args.password or ""})
        if sub == "xfs":
            return _run("container.xfs",
                        {"password": args.password or "", "path": args.path or ""})
        if sub == "traffic":
            kind = args.kind or "interfaces"
            plug = {"interfaces": "traffic.interfaces",
                    "bluetooth": "traffic.bluetooth",
                    "rename": "traffic.ble_rename",
                    "hid": "traffic.hid"}[kind]
            return _run(plug, {})
        if sub == "apk":
            return _run("mobile.apk", {})
    except Exception as exc:
        print(f"失败：{type(exc).__name__}: {exc}")
        return 1
    print(f"未知子命令：{sub}")
    return 1


# ---------------------------------------------------------------------------
def cmd_mount(args) -> int:
    """
    镜像挂载子系统（新增）：打开镜像 → 列出分区/文件系统 → 浏览/读/提取。

    用法：
        mount open    <image> [--password PW] [--json]
        mount list    <image> [--password PW] [--vol N] [--limit]
        mount read    <image> [--password PW] [--vol N] --path <卷内路径>
        mount extract <image> [--password PW] [--vol N] --path <卷内路径> --out <目标>
        mount carve   <image> [--password PW] [--vol N] [--rules a,b] [--offset] [--length]
    """
    from memlens.formats.mount import ImageMount
    import json as _json

    sub = args.mount_cmd
    m = ImageMount.open(args.target, args.password or "")
    try:
        if sub == "open":
            s = m.summary()
            if args.json:
                print(_json.dumps(s, ensure_ascii=False, indent=2))
                return 0
            print(f"  镜像   {m.path}")
            print(f"  类型   {m.kind}   大小 {m.size/1024**3:.2f} GiB")
            for v in m.volumes:
                sv = v.summary()
                print(f"  卷 {v.index}: {sv.get('fs')}  offset={v.offset}  size={v.size/1024**2:.1f} MiB"
                      + (f"  label={sv.get('label')}" if sv.get("label") else ""))
            for n in m.notes:
                print(f"  · {n}")
            return 0
        if sub == "list":
            vol = _pick_vol(m, args.vol)
            rows = vol.tree()
            if args.limit:
                rows = rows[:args.limit]
            if not rows:
                print("(空卷或该文件系统不支持浏览)")
                return 0
            for r in rows:
                flag = "DEL" if r.get("deleted") else ""
                kind = "dir" if r.get("dir") else f"{r.get('size', 0)}B"
                print(f"  {r.get('path')}  {kind}  {flag}")
            print(f"\n共 {len(rows)} 行")
            return 0
        if sub == "read":
            vol = _pick_vol(m, args.vol)
            data = vol.read(args.path)
            sys.stdout.buffer.write(data)
            return 0
        if sub == "extract":
            vol = _pick_vol(m, args.vol)
            dst = vol.extract(args.path, args.out)
            print(f"已提取 {args.path} → {dst}（{dst.stat().st_size} 字节）")
            return 0
        if sub == "carve":
            vol = _pick_vol(m, args.vol)
            hits = vol.carve([x.strip() for x in (args.rules or "").split(",") if x.strip()],
                             offset=args.offset, length=args.length)
            print(f"{'规则':10} {'起点':>14} {'终点':>14} {'大小':>10}  定界")
            for h in hits:
                print(f"{h['rule']:10} {h['start']:>14} {h['end']:>14} {h['size']:>10}  {h['note']}")
            print(f"\n共 {len(hits)} 个命中")
            return 0
        if sub == "search":
            from memlens.core.fulltext import search_region
            if not args.keyword:
                print("缺少 --keyword")
                return 1
            encs = [x.strip() for x in (args.encodings or "").split(",") if x.strip()]
            read, base, ln = m.volumes[0]._abs_read, m.volumes[0].offset, m.volumes[0].size
            if args.vol:
                v = _pick_vol(m, args.vol)
                read, base, ln = v._abs_read, v.offset, v.size
            hits = search_region(read, base, ln, args.keyword, encs or None, args.limit)
            if not hits:
                print("(无命中)")
                return 0
            for h in hits:
                print(f"  {h['offset']:>14}  {h['enc']:8}  {h['context'][:80]}")
            print(f"\n共 {len(hits)} 个命中")
            return 0
    except Exception as exc:
        print(f"失败：{type(exc).__name__}: {exc}")
        return 1
    print(f"未知子命令：{sub}")
    return 1


def _pick_vol(m, idx: int):
    idx = idx or 1
    for v in m.volumes:
        if v.index == idx:
            return v
    raise ValueError(f"卷 {idx} 不存在（可用：{[v.index for v in m.volumes]}）")


def cmd_carve(args) -> int:
    """文件雕刻：`carve <image> [--password PW] [--vol N] [--rules ...] [--out DIR]`。"""
    from memlens.formats.mount import ImageMount
    import json as _json
    m = ImageMount.open(args.target, args.password or "")
    if args.vol:
        vol = _pick_vol(m, args.vol)
        read, base, ln = vol._abs_read, vol.offset, vol.size
    else:
        read, base, ln = _raw_read_fn(args.target), 0, _file_size(args.target)
    names = [x.strip() for x in (args.rules or "").split(",") if x.strip()]
    from memlens.core.carver import carve_region
    hits = list(carve_region(read, base, ln, names))
    if args.out:
        import os
        os.makedirs(args.out, exist_ok=True)
        from memlens.core.hashing import hash_bytes
        outrows = []
        for h in hits:
            data = read(h.start, h.size)
            ext = {"jpeg": ".jpg", "png": ".png", "gif": ".gif", "pdf": ".pdf",
                   "zip": ".zip", "sqlite": ".db", "elf": ".elf", "pe": ".exe",
                   "bmp": ".bmp", "wav": ".wav", "mp4": ".mp4"}.get(h.rule, ".bin")
            p = os.path.join(args.out, f"{h.start}_{h.rule}{ext}")
            open(p, "wb").write(data)
            outrows.append({"start": h.start, "rule": h.rule, "size": h.size,
                            "out": p, "sha256": hash_bytes(data)["sha256"]})
        print(_json.dumps(outrows, ensure_ascii=False, indent=2))
        print(f"共 {len(outrows)} 个，写入 {args.out}")
        return 0
    for h in hits:
        print(f"{h.rule:10} {h.start:>14} {h.end:>14} {h.size:>10}  {h.note}")
    print(f"\n共 {len(hits)} 个命中")
    return 0


def cmd_hash(args) -> int:
    """哈希：`hash <file> [--algos md5,sha1,sha256,sm3] [--json]`。"""
    from memlens.core.hashing import hash_file
    import json as _json
    algos = [a.strip() for a in (args.algos or "").split(",") if a.strip()] or None
    print(f"计算中：{args.target} ...", file=sys.stderr)

    def _prog(done, total):
        if total:
            print(f"\r  {done/total*100:5.1f}%  {done/1024**2:.0f}/{total/1024**2:.0f} MiB",
                  end="", file=sys.stderr)

    h = hash_file(args.target, algos, _prog)
    print(file=sys.stderr)
    if args.json:
        print(_json.dumps(h, ensure_ascii=False, indent=2))
        return 0
    for a, v in h.items():
        print(f"  {a.upper():8} {v}")
    return 0


def _raw_read_fn(path: str):
    fh = open(path, "rb")

    def _r(off, n):
        fh.seek(off)
        return fh.read(n)
    return _r


def _file_size(path: str) -> int:
    import os
    return os.path.getsize(path)


def cmd_evidence(args) -> int:
    """
    证据登记与保管链（新增）：`evidence add|list|verify`。

    用法：
        evidence add    <image> [--password PW] [--note ...]
        evidence list
        evidence verify
    """
    from memlens.core.evidence import EvidenceStore
    from memlens.formats.mount import ImageMount
    import os
    store = EvidenceStore(os.path.join(os.path.dirname(DEFAULT_DB), "evidence.json")
                          if not args.db else os.path.join(os.path.dirname(args.db), "evidence.json"))
    try:
        if args.evidence_cmd == "add":
            m = ImageMount.open(args.target, args.password or "")
            print(f"登记中：{args.target}（{m.kind}）…", file=sys.stderr)
            rec = store.add(args.target, kind=m.kind, size=m.size,
                            volumes=[v.summary() for v in m.volumes],
                            note=args.note or "")
            print(f"  已登记 #{rec['id']}  {rec['path']}")
            for a, v in rec["hashes"].items():
                print(f"    {a.upper():8} {v}")
            print(f"  保管链哈希 {rec['rec_hash']}")
            return 0
        if args.evidence_cmd == "list":
            recs = store.list()
            if not recs:
                print("(空)")
                return 0
            for r in recs:
                print(f"  #{r['id']}  {r['path']}  [{r['kind']}]  {r['registered_at']}")
                print(f"      SHA256 {r['hashes'].get('sha256','')[:40]}…")
            return 0
        if args.evidence_cmd == "verify":
            ok, info = store.verify()
            print(f"保管链：{'✓ 完整' if ok else '✗ 断裂'}  {info}")
            return 0 if ok else 1
    except Exception as exc:
        print(f"失败：{type(exc).__name__}: {exc}")
        return 1
    print(f"未知子命令：{args.evidence_cmd}")
    return 1


# ---------------------------------------------------------------------------
def cmd_dimensions(args) -> int:
    """
    五维判定（违规跨境访问检测模块，方案 4.2 节 FR-01~FR-07）。

    用法：
        dimensions <case_id>                 # 检查用法（三档）
        dimensions <case_id> --usage forensic  # 取证用法（A/B/C 三级）
        dimensions <case_id> --allow-direction # 开启访问方向维度（默认关闭）
    """
    from memlens.detectors.base import DetectionContext
    from memlens.dimensions import evaluate

    store = _store(args)
    case = store.get_case(args.case_id)
    if not case:
        print(f"案件不存在：{args.case_id}")
        store.close()
        return 1
    ctx = DetectionContext(store, args.case_id)
    verdict = evaluate(ctx, usage=args.usage, allow_direction=args.allow_direction)
    store.save_dimension_results(args.case_id, verdict)

    print("═" * 72)
    print(f"五维判定 · 案件 {args.case_id}")
    print(f"用法：{'检查（三档）' if args.usage == 'check' else '取证（A/B/C 级）'}"
          f"　规则包：{verdict.rulepack_version}")
    print("─" * 72)
    for d in verdict.dimensions:
        if d.state == "disabled":
            print(f"  ○ {d.label}（{d.fr}）　未启用")
            continue
        bar = "█" * int(round(d.score * 20))
        print(f"  ● {d.label}（{d.fr}）　得分 {d.score:.2f}　上限 {d.level_cap}　{bar}")
        for f in d.findings[:4]:
            print(f"      - {f}")
        if d.gaps:
            print(f"      ⚠ 降级 {len(d.gaps)} 项：{d.gaps[0].get('reason','')[:70]}")
    print("─" * 72)
    print(f"  加权总分：{verdict.total:.3f}")
    if args.usage == "check":
        print(f"  检查结论：**{verdict.tier_label}**")
    else:
        print(f"  取证等级：**{verdict.level_label}**（等级上限 {verdict.level_cap}）")
    for n in verdict.notes:
        print(f"  · {n}")
    # 缺口入库
    try:
        store.clear_gaps(args.case_id)
        if verdict.gaps:
            store.add_gaps(args.case_id, verdict.gaps)
            print(f"  缺口清单已更新：{len(verdict.gaps)} 项")
    except Exception as exc:
        print(f"  ⚠ 缺口清单入库失败：{exc}")
    store.close()
    return 0


# ---------------------------------------------------------------------------
def cmd_rulepack(args) -> int:
    """
    规则包管理（方案 FR-21）：版本号 + 发布日期 + 阈值 + 白名单 + 词表 + 变更记录。

    **全程离线**：导入的是本地 JSON 文件，不联网、不校验签名（签名留给业务侧分发链）。
    """
    from memlens.core import rulepack as rp

    mgr = rp.configure(DEFAULT_WORKDIR)
    if args.import_pack:
        try:
            pk = mgr.import_pack(args.import_pack, activate=not args.no_activate)
        except Exception as exc:
            print(f"❌ 规则包导入失败：{exc}")
            return 1
        print(f"✔ 已导入规则包 {pk.version}（{'已激活' if not args.no_activate else '未激活'}）")
        print(f"  发布日期：{pk.published_at or '—'}")
        print(f"  阈值条数：{len(pk.thresholds)}")
        print(f"  SHA-256 ：{pk.sha256}")
        if pk.change_log:
            print(f"  变更记录：{pk.change_log[:200]}")
        return 0

    if args.activate:
        try:
            pk = mgr.rollback(args.activate)
        except Exception as exc:
            print(f"❌ 切换失败：{exc}")
            return 1
        print(f"✔ 已切换生效规则包：{pk.version}")
        return 0

    if args.export:
        try:
            out = mgr.export_pack(args.export, args.out or f"{args.export}.json")
        except Exception as exc:
            print(f"❌ 导出失败：{exc}")
            return 1
        print(f"✔ 已导出：{out}")
        return 0

    cur = rp.current()
    print("═" * 66)
    print(f"当前生效规则包：{cur.version}　发布：{cur.published_at or '—'}")
    print(f"SHA-256：{cur.sha256}")
    print(f"阈值 {len(cur.thresholds)} 条　白名单 {len(cur.whitelist)} 组　词表 {len(cur.wordlist)} 类")
    if cur.change_log:
        print(f"变更记录：{cur.change_log[:300]}")
    print("─" * 66)
    packs = mgr.list_packs()
    if not packs:
        print("（规则包目录为空，当前使用内置基线）")
        return 0
    print("可用版本：")
    for p in packs:
        mark = "★生效" if p.get("active") else "      "
        print(f"  {mark} {p.get('version', '?'):<12} {p.get('published_at', ''):<12} "
              f"{(p.get('sha256') or '')[:16]}  {p.get('change_log', '')[:50]}")
    return 0


def cmd_audit(args) -> int:
    """审计记录与哈希链校验（方案 5.4）。"""
    from memlens.core import timebase

    store = _store(args)
    if args.verify:
        res = store.verify_audit_chain(case_id=args.case_id or None)
        mark = "✔" if res["ok"] else "✘"
        print(f"{mark} 哈希链校验：{res['detail']}（共 {res['total']} 条）")
        if not res["ok"]:
            print(f"  断链位置：audit_id={res['broken_at']}")
        store.close()
        return 0 if res["ok"] else 1

    rows = store.list_audit(case_id=args.case_id or None, limit=args.limit,
                            critical_only=args.critical)
    if not rows:
        print("（无审计记录）")
        store.close()
        return 0
    print(f"审计记录 {len(rows)} 条（哈希链已串联）：")
    for r in rows:
        mark = "★" if r.get("critical") else " "
        print(f" {mark} {r.get('ts_utc', '')}  {r.get('actor', ''):<10} "
              f"{r.get('action', ''):<16} {str(r.get('target', ''))[:44]}")
        print(f"     hash={str(r.get('entry_hash', ''))[:24]} prev={str(r.get('prev_hash', ''))[:24]}")
    store.close()
    return 0


def cmd_gaps(args) -> int:
    """缺口清单（方案表 9）：缺什么 / 为什么 / 怎么补。"""
    store = _store(args)
    rows = store.list_gaps(args.case_id, dimension=args.dimension)
    if not rows:
        print("（无缺口记录）")
        store.close()
        return 0
    print(f"缺口清单 {len(rows)} 项：")
    for g in rows:
        print(f"  · [{g.get('impact', '?')}] {g.get('dimension', '')} — {g.get('reason', '')}")
        if g.get("level_cap"):
            print(f"      结论上限：{g['level_cap']}")
        if g.get("suggestion"):
            print(f"      建议补证：{g['suggestion']}")
    store.close()
    return 0


# ---------------------------------------------------------------------------
def cmd_vmscan(args) -> int:
    """
    虚拟机取证扫描：VM 资产发现 + 配置取证 + 磁盘里的 flag/私钥（只读）。

    覆盖内存之外的盲区：.vmx/.vbox 配置里的明文口令与共享文件夹、
    .vmdk/.qcow2/.vdi 磁盘里的 flag 与私钥、.vmem 内存快照清单。
    """
    from memlens.core import vmscan as vm

    roots = [Path(p) for p in (args.paths or [])]
    vms = vm.discover(roots, max_depth=args.depth)
    print(f"[1/3] 发现虚拟机目录 {len(vms)} 个（扫描深度 {args.depth}）")
    disk_hits: list = []
    for v in vms:
        if v.config:
            v.findings.extend(vm.parse_vmware_config(v.config))
        if args.deep and v.disks:
            print(f"      扫描磁盘（只读字节扫描）：{Path(v.disks[0]).name} …", flush=True)
            for d in v.disks:
                disk_hits.extend(vm.scan_disk_for_secrets([d], max_bytes=int(args.max_gb * (1 << 30))))

    print("[2/3] 结果")
    for v in vms:
        print(f"\n  ▣ {v.family}  {v.root}")
        if v.config:
            print(f"      配置: {Path(v.config).name}")
        for m in v.memory:
            print(f"      内存快照: {Path(m).name}  ← 可直接 analyze")
        for d in v.disks:
            print(f"      磁盘: {Path(d).name}")
        for f in v.findings:
            print(f"      [{f.severity.upper():^8}] {f.detail}"
                  + (f"  值={f.value[:80]}" if f.value else ""))
    if disk_hits:
        print(f"\n  ★ 磁盘命中 {len(disk_hits)} 处：")
        for f in disk_hits[:20]:
            print(f"      [{f.severity.upper():^8}] {Path(f.path).name}  {f.detail}  {f.value[:120]}")

    print("\n[3/3] 下一步建议")
    for i, s in enumerate(vm.next_steps(vms, disk_hits), 1):
        print(f"  {i}. {s}")
    if args.json:
        out = Path(args.out) if args.out else (DEFAULT_WORKDIR / "vmscan.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(vm.summarize(vms, disk_hits), ensure_ascii=False,
                                   indent=2), encoding="utf-8")
        print(f"\n  结构化结果 → {out}")
    return 0


# ---------------------------------------------------------------------------
def cmd_verdict(args) -> int:
    """
    一页纸结论：旗标候选 → 关键事实 → 重点发现 → 下一步建议。

    为什么要它：内存取证的结果散在七八个页签里（进程表/网络/发现项/旗标/时间线/情报），
    用户得自己拼结论。这条命令把散落证据**聚合成一页**，可直接贴进工单或 WP。
    """
    from memlens.core import verdict as vd

    store = _store(args)
    try:
        v = vd.build(store, args.case_id)
        if args.format == "md":
            text = vd.to_markdown(v)
        elif args.format == "json":
            text = vd.to_json(v)
        else:
            text = vd.to_text(v)
        out = getattr(args, "out", None)
        if out:
            Path(out).write_text(text, encoding="utf-8")
            print(f"✔ 结论已写入 {out}")
        else:
            print(text)
    finally:
        store.close()
    return 0


# ---------------------------------------------------------------------------
def cmd_symbols(args) -> int:
    """
    Volatility3 符号表（ISF）管理：查看现状 / 只读挂接本机已有符号 / 本地导入。

    这条命令存在的意义：vol3 的成败几乎完全取决于"内核 ISF 是否就绪"，
    而就绪与否以前只能从一屏 Progress 里猜。现在可以：
      * 直接查现状（有没有、覆盖哪些系统）
      * `--add-dir` 把本机已有的符号目录只读挂进来（离线、零拷贝、秒出结果）
      * `--import` 复制一份到 MemLens 工作目录（便携、可归档、可拷给同学）
    """
    from memlens.core import symbols as sym

    wd = DEFAULT_WORKDIR
    if getattr(args, "import_dir", None):
        src = Path(args.import_dir)
        print(f"从 {src} 导入 ISF → {sym.work_symbols_dir(wd)}")

        def _p(done: int, total: int) -> None:
            print(f"\r  进度 {done}/{total}", end="", flush=True)

        copied, skipped, nbytes = sym.import_from(src, wd, progress=_p)
        print()
        print(f"✔ 导入完成：新复制 {copied} 个，已存在跳过 {skipped} 个"
              f"（{nbytes / 1048576:.1f} MB）")
        print(sym.describe(wd))
        return 0

    if getattr(args, "import_kernel", None):
        # 只取目标镜像内核需要的那一个 ISF（大符号库的正确用法）
        wd = DEFAULT_WORKDIR
        image = args.import_kernel
        session_dir = None
        try:
            from memlens.engines.memprocfs import MemProcFSAdapter
            ad = MemProcFSAdapter()
            sess = ad.loaded_session(image)
            session_dir = sess.root if sess else ad.session_dir(image)
        except Exception:
            session_dir = None
        copied = sym.import_kernel(wd, session_dir=session_dir,
                                   src=getattr(args, "from_dir", None))
        if copied:
            print(f"✔ 已导入 {len(copied)} 个内核符号表（按镜像内核 GUID 精确匹配）：")
            for c in copied:
                print(f"  {c}")
        else:
            print("⚠ 没能定位到匹配的 ISF。提示：")
            print("  · 需要先用 MemProcFS 引擎跑过一次该镜像（modules.csv 提供内核 GUID），或")
            print("  · 用 --from 指定符号库目录，或")
            print("  · 直接联网跑一次 vol3（会自动下载并转换 ISF）")
        print(sym.describe(wd))
        return 0

    if getattr(args, "convert_image", None):
        image = args.convert_image
        print(f"按镜像内核 GUID 从本地 PDB 转 ISF（vol3 离线）：{image}")

        def _pc(done: int, total: int) -> None:
            print(f"\r  转换 {done}/{total}", end="", flush=True)

        out = sym.convert_for_image(wd, image, progress=_pc)
        print()
        if out:
            print("✔ 已生成 vol3 离线 ISF：")
            for o in out:
                print(f"  {o}")
        else:
            print("⚠ 未命中：需先用 MemProcFS 引擎跑过该镜像（modules.csv 提供内核 GUID），")
            print("  且本地 PDB 符号源（MemProcFS 的 Symbols）有对应内核版本。")
        print(sym.describe(wd))
        return 0

    if getattr(args, "convert_pdb", None):
        pdb = args.convert_pdb
        print(f"转换本地 PDB → vol3 ISF：{pdb}")
        out = sym.pdb_to_isf(pdb, sym.work_symbols_dir(wd))
        print(f"✔ {out}")
        print(sym.describe(wd))
        return 0

    if getattr(args, "add_dir", None):
        reg = sym.add_source(args.add_dir, wd)
        print(f"✔ 已登记只读符号源：{Path(args.add_dir).resolve()}")
        print(f"  （记录在 {reg}；源目录全程只读，不会被写入）")
        print(sym.describe(wd))
        return 0

    print(sym.describe(wd))
    print("\nvol3 实际使用的符号搜索路径（-s，分号分隔；第一位是 MemLens 自己的可写目录）：")
    print(f"  {sym.work_symbols_dir(wd)}")
    for d in sym.indexable_extra_sources(wd):
        print(f"  {d}")
    return 0


def cmd_deep(args) -> int:
    """
    ★ 一键深度分析：**打开即全量**，没有"快速/深度"选项。

    流程：探测 → 生成计划 → 全量执行（MemProcFS + vol3 + 字节扫描 + 静态）
          → 检测器 → 情报 → 时间线 → 旗标 → 系统画像 → 报告。
    """
    from memlens.engines import registry as _reg
    from memlens.pipeline.deep import DeepAnalyzer
    from memlens.pipeline import sysprofile as sp

    image = str(Path(args.image).resolve())
    if not Path(image).is_file():
        print(f"文件不存在：{image}")
        return 2

    workdir = Path(args.workdir) if getattr(args, "workdir", None) else DEFAULT_WORKDIR
    workdir.mkdir(parents=True, exist_ok=True)
    store = _store(args)

    engines = {}
    for name in ("memprocfs", "vol3", "memstrings", "static"):
        try:
            eng = _reg.get(name)
            if name == "vol3":
                from memlens.core.vol3_env import Vol3Env
                Vol3Env(workdir).apply(eng)
            engines[name] = eng
        except Exception as exc:
            print(f"⚠ 引擎 {name} 不可用：{exc}")

    def on_event(kind: str, payload) -> None:
        if kind == "progress":
            print(f"\r[{payload.get('percent', 0):5.1f}%] {payload.get('phase')}: "
                  f"{payload.get('phase_message', '')}", end="", flush=True)
        elif kind == "log" and getattr(args, "verbose", False):
            print(f"  {payload.get('text')}")
        elif kind == "plugin_done":
            if payload.get("status") != "ok":
                print(f"\n  ✗ {payload.get('plugin')}: {payload.get('error')}")

    print(f"深度分析：{image}")
    analyzer = DeepAnalyzer(store, workdir, engines=engines, on_event=on_event,
                            run_id=f"cli-{os.getpid()}")
    res = analyzer.analyze(image, name=getattr(args, "case_name", None))

    print("\n" + "=" * 68)
    print(f"状态：{res.status}　耗时：{res.duration_ms / 1000:.1f}s　案件：{res.case_id}")
    print(f"统计：{json.dumps(res.stats, ensure_ascii=False)}")
    if res.findings:
        print(f"\n发现项（{len(res.findings)}）：")
        for f in res.findings[:20]:
            print(f"  [{f.get('severity',''):8}] {f.get('title')}")
    if res.flags:
        print(f"\n旗标候选：{[f.get('value') for f in res.flags[:5]]}")
    if res.errors:
        print(f"\n错误：")
        for e in res.errors:
            print(f"  - {e}")
    if res.failed:
        print(f"\n失败项（{len(res.failed)}）：")
        for f in res.failed[:20]:
            print(f"  - [{f.get('engine')}/{f.get('plugin')}] {f.get('reason')}")

    # 系统画像
    prof = store.get_system_profile(res.case_id)
    fields = prof.get("profile_json") or {}
    if fields:
        print("\n系统画像：")
        for key, label, _grp in sp.PROFILE_FIELDS:
            v = fields.get(key)
            if not v:
                continue
            val = v.get("value")
            if key.endswith("_bytes") and isinstance(val, (int, float)):
                val = f"{sp.human_size(val)}（{int(val):,} B）"
            print(f"  {label:8} = {val}　← {v.get('source')}（{int((v.get('confidence') or 0) * 100)}%）")
    print(f"\n报告目录：{workdir / res.case_id / 'report'}")
    return 0 if res.status == "ok" else 1


def cmd_serve(args) -> int:
    """
    启动 Web 取证控制台（默认形态）。

    与 `main.py` 共用同一套可靠性逻辑：端口冲突自动处理、
    等服务真正 ready 才开浏览器、失败弹消息框（不再静默退出）。
    """
    import threading
    import time as _t

    from memlens.web import app as web_app
    from memlens.web import server as srv

    host = getattr(args, "host", "127.0.0.1")
    port = int(getattr(args, "port", 8765))

    if not srv.port_is_free(host, port):
        if srv.is_memlens_instance(port, host):
            url = f"http://{host}:{port}/"
            print(f"[MemLens] 已在运行：{url}")
            if not getattr(args, "no_browser", False):
                srv.open_browser(url)
            return 0
        try:
            new_port = srv.find_free_port(host, port)
            print(f"[MemLens] 端口 {port} 被占用，改用 {new_port}")
            port = new_port
        except OSError as exc:
            print(f"[MemLens] 找不到可用端口：{exc}", file=sys.stderr)
            srv.notify_error("MemLens 无法启动", f"端口 {port} 被占用且没有空闲端口可用。\n{exc}")
            return 1

    url = f"http://{host}:{port}/"
    t0 = _t.time()
    print(f"[MemLens] 取证控制台：{url}")
    print(f"[MemLens] 数据库后端：{web_app.STATE.store.backend}")

    try:
        import uvicorn
    except ImportError:
        print("未安装 uvicorn：python -m pip install \"uvicorn[standard]\" fastapi")
        return 127

    config = uvicorn.Config(web_app.app, host=host, port=port,
                            log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    th = threading.Thread(target=server.run, daemon=True)
    th.start()

    if not srv.wait_ready(url + "api/health", timeout=srv.READY_TIMEOUT):
        server.should_exit = True
        msg = (f"服务在 {srv.READY_TIMEOUT:.0f} 秒内没有就绪。\n"
               f"日志：{web_app.STATE.workdir / 'memlens.log'}")
        srv.notify_error("MemLens 启动失败", msg)
        print(msg, file=sys.stderr)
        return 1

    print(f"[MemLens] 就绪耗时 {(_t.time() - t0):.2f}s")
    if not getattr(args, "no_browser", False):
        srv.open_browser(url)
    else:
        print(f"[MemLens] 请手动访问：{url}")

    try:
        while th.is_alive():
            th.join(timeout=0.5)
    except KeyboardInterrupt:
        server.should_exit = True
    return 0


def cmd_offline_check(args) -> int:
    """
    断网自检：拦截所有出网 socket，验证 UI 与 API 是否仍能正常提供。

    回答的问题是：**"断网能不能打开？"** —— 而不是靠"我看了代码觉得没联网"。
    """
    from memlens.web.server import probe_offline

    r = probe_offline()
    return 0 if r.get("ok") else 1


def cmd_db(args) -> int:
    """数据库管理：查看后端 / 初始化 / 切换到 MySQL。"""
    store = _store(args)
    print(f"当前后端：{store.backend}")
    print(f"连接串：{store.url}")
    tables = sorted(store.engine.table_names())
    print(f"数据表（{len(tables)}）：{', '.join(tables)}")
    if getattr(args, "cases", False):
        for c in store.list_cases():
            print(f"  {c['case_id']}  {c.get('name','')}  {c.get('os_type','')}  {c.get('created_at','')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memlens",
        description="MemLens —— 属于你自己的内存取证工作台（命令行版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--db", help=f"数据库路径（默认 {DEFAULT_DB}）")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("engines", help="引擎自检")
    s.set_defaults(func=cmd_engines)

    s = sub.add_parser("probe", help="探测镜像格式与操作系统")
    s.add_argument("image")
    s.add_argument("--engine", choices=["vol3", "static"],
                   help="打算使用的引擎（用于抑制不适用的提示）")
    s.add_argument("--fast", action="store_true", help="跳过深度采样（大文件更快）")
    s.add_argument("--json", action="store_true", help="额外输出 JSON")
    s.set_defaults(func=cmd_probe)

    s = sub.add_parser("plugins", help="列出引擎插件（运行时枚举）")
    s.add_argument("--engine", default="vol3")
    s.add_argument("--search", help="关键词过滤（空格分隔为 AND）")
    s.add_argument("--refresh", action="store_true", help="忽略缓存重新枚举")
    s.set_defaults(func=cmd_plugins)

    s = sub.add_parser("analyze", help="一键分析：探测→建案→执行→检测→汇总")
    s.add_argument("image")
    s.add_argument("--plugins", default="",
                   help="预设名（windows-quick/basic/deep）或逗号分隔的插件名；"
                        "留空则按引擎取默认集")
    s.add_argument("--case-name")
    s.add_argument("--engine", default="vol3",
                   help="引擎：vol3（内存镜像）/ static（PE 与未知二进制）/ "
                        "memstrings（镜像字节级字符串与 flag 扫描，任何容器均可）")
    s.add_argument("--renderer", default="jsonl", help="vol3 渲染器（jsonl/json/csv）")
    s.add_argument("--timeout", type=float, default=1800.0, help="单插件超时秒数")
    s.add_argument("--no-cache", action="store_true", help="忽略缓存，强制重跑")
    s.add_argument("--fast", action="store_true", help="探测跳过深度采样")
    s.add_argument("--fast-hash", action="store_true", help="只哈希镜像前 64MB（大镜像提速）")
    s.add_argument("--force", action="store_true", help="容器不可直接分析时仍强行尝试")
    s.add_argument("--offline", action="store_true",
                   help="禁止联网获取符号表（只用本地符号源，见 `memlens symbols`）")
    s.add_argument("--param", action="append", metavar="K=V",
                   help="传给引擎的额外参数，可重复；如 --param pid=1456、"
                        "--param key=HKLM\\\\SOFTWARE\\\\...\\\\Run")
    s.add_argument("-v", "--verbose", action="store_true", help="回显引擎输出")
    s.set_defaults(func=cmd_analyze)

    s = sub.add_parser("cases", help="列出所有案件")
    s.set_defaults(func=cmd_cases)

    s = sub.add_parser("case", help="查看单个案件详情（产物清单）")
    s.add_argument("case_id")
    s.set_defaults(func=cmd_case)

    s = sub.add_parser("findings", help="列出发现项")
    s.add_argument("case_id")
    s.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
    s.add_argument("-v", "--verbose", action="store_true", help="显示说明与证据")
    s.set_defaults(func=cmd_findings)

    s = sub.add_parser("records", help="查询记录")
    s.add_argument("case_id")
    s.add_argument("--plugin", help="插件名（模糊匹配，如 psscan）")
    s.add_argument("--keyword", help="关键词过滤")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--cols", type=int, default=8, help="显示列数上限")
    s.set_defaults(func=cmd_records)

    s = sub.add_parser("export", help="导出记录为 CSV")
    s.add_argument("case_id")
    s.add_argument("--plugin", help="只导出该插件的产物（模糊匹配）")
    s.add_argument("--engine", default="vol3")
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_export)

    # ---- 新增：情报层 ----
    s = sub.add_parser("intel", help="情报扫描：IOC 提取 + 词典匹配（结果入库）")
    s.add_argument("case_id")
    s.add_argument("--dicts", help="逗号分隔的词典 id；留空表示全跑")
    s.add_argument("--no-ioc", action="store_true", help="只跑词典，不提 IOC")
    s.add_argument("--show-ioc", action="store_true", help="列出 IOC 明细")
    s.add_argument("--limit", type=int, default=40, help="每类最多显示多少行")
    s.set_defaults(func=cmd_intel)

    s = sub.add_parser("dict", help="查看内置词典清单 / 某个词典的条目")
    s.add_argument("id", nargs="?", help="词典 id；留空列出全部")
    s.set_defaults(func=cmd_dict)

    s = sub.add_parser("vmscan", help="虚拟机取证扫描：VM 资产 / 配置凭据 / 磁盘里的 flag")
    s.add_argument("paths", nargs="+", help="要扫描的目录（可多个）")
    s.add_argument("--depth", type=int, default=5, help="目录扫描深度（默认 5）")
    s.add_argument("--deep", action="store_true", help="同时字节扫描磁盘（.vmdk/.qcow2/.vdi）找 flag/私钥")
    s.add_argument("--max-gb", type=float, default=8.0, help="单个磁盘最多扫描多少 GB（默认 8）")
    s.add_argument("--json", action="store_true", help="额外输出结构化 JSON")
    s.add_argument("--out", help="JSON 输出路径")
    s.set_defaults(func=cmd_vmscan)

    s = sub.add_parser("browser-history",
                       help="本机浏览器历史采集（按需触发，只读副本不上传）")
    s.add_argument("--sources", action="store_true", help="只列出探测到的历史库，不读内容")
    s.add_argument("--browser", default="all",
                   help="all / edge / chrome / firefox / brave / 360极速 / QQ浏览器")
    s.add_argument("--profile", default="", help="只取某个 Profile（如 Default）")
    s.add_argument("--since", default=None, help="只取该时间之后（YYYY-MM-DD [HH:MM:SS]）")
    s.add_argument("--until", default=None, help="只取该时间之前")
    s.add_argument("--keyword", default="", help="只在 URL/标题里匹配该关键字")
    s.add_argument("--limit", type=int, default=0, help="最多返回多少条（0=不限）")
    s.add_argument("--all-drives", action="store_true",
                   help="全盘扫描：C–Z 所有驱动器的用户目录与便携版浏览器（本机取证用）")
    s.add_argument("--top", type=int, default=12, help="Top 域名显示条数")
    s.add_argument("--show", type=int, default=20, help="最近记录显示条数")
    s.add_argument("--out", default="", help="导出全量 CSV 的路径")
    s.add_argument("--json", action="store_true", help="导出 JSON 到 work/browser_history.json")
    s.add_argument("--appdata", default="",
                   help="分析任意 AppData 根目录（镜像里提取的 Users\\<user>\\AppData，或本机其它用户）")
    s.add_argument("--risk", action="store_true",
                   help="★ 境外 IP + 风险分级（URL/域名/境外地址/风险等级）")
    s.add_argument("--ip-map", default="",
                   help="域名=IP 映射文件（每行 `域名 IP`，从 pcap/流量提取，境外识别更准）")
    s.add_argument("--report", default="",
                   help="导出境外 IP 访问报告（按扩展名 .json/.csv/.md）")
    s.set_defaults(func=cmd_browser_history)

    s = sub.add_parser("url-analyze",
                       help="★ URL / 境外 IP 分析：域名→IP→境外识别→风险等级")
    s.add_argument("urls", nargs="*", help="URL（可多个）")
    s.add_argument("--file", default="", help="从文件读 URL（每行一个，# 注释）")
    s.add_argument("--resolve", action="store_true", help="DNS 解析域名→IP（需联网）")
    s.add_argument("--ip-map", default="",
                   help="域名=IP 映射文件（每行 `域名 IP`，从 pcap/流量提取）")
    s.add_argument("--json", action="store_true", help="导出 JSON 到 work/url_analyze.json")
    s.add_argument("--scanner", default="",
                   help="解析扫描器 result.txt（[url]/[title]/[finger]/[icmp] 格式）")
    s.set_defaults(func=cmd_url_analyze)

    s = sub.add_parser("web-log",
                       help="★ 网站访问日志分析：攻击者IP / 可疑请求 / 一句话木马 SHA-256")
    s.add_argument("log", help="nginx/apache access.log 路径")
    s.add_argument("--keyword", default="", help="只分析路径含该关键字的请求")
    s.add_argument("--json", action="store_true", help="导出 JSON 到 work/web_log.json")
    s.set_defaults(func=cmd_web_log)

    s = sub.add_parser("server",
                       help="★ 服务器文件级取证：wtmp/passwd/trojan/php/sql（不挂载系统）")
    s.add_argument("kind", choices=["wtmp", "passwd", "trojan", "php", "sql"],
                   help="wtmp=开机时间 / passwd=用户数 / trojan=配置 / php=加密 / sql=订单")
    s.add_argument("path", help="文件路径（用「取证容器」从镜像提取后）")
    s.add_argument("--password", default="", help="php 加密明文（题 7：sbwyz1）")
    s.add_argument("--json", action="store_true", help="导出 JSON 到 work/server_<kind>.json")
    s.set_defaults(func=cmd_server)

    s = sub.add_parser("server-solve",
                       help="★ 服务器检材一键求解：打开容器 FS，全盘内容扫描并解析各题")
    s.add_argument("target", help="镜像/容器文件（VeraCrypt 卷，自动穿透 exFAT→VMDK→LVM→XFS）")
    s.add_argument("--password", default="", help="VeraCrypt 口令")
    s.add_argument("--plain", default="sbwyz1", help="题 7 加密明文（默认 sbwyz1）")
    s.add_argument("--json", action="store_true", help="导出 JSON 到 work/server_solve.json")
    s.add_argument("--rescan", action="store_true",
                   help="忽略命中缓存、强制重新全盘扫描（45 GiB 约 10 分钟）")
    s.add_argument("--region", type=int, default=4 << 20,
                   help="每个命中点回读的字节数（默认 4 MiB，用于解析整份文件）")
    s.set_defaults(func=cmd_server_solve)

    s = sub.add_parser("search", help="跨产物检索：证据表 / 结论 / 时间线 / 容器内容")
    s.add_argument("case_id")
    s.add_argument("keywords", nargs="*", help="关键词；支持 \"短语\" key:value -排除 /正则/")
    s.add_argument("--scope", default="records,findings,timeline",
                   help="检索范围（逗号分隔）")
    s.add_argument("--regex", action="store_true", help="按正则解释")
    s.add_argument("--limit", type=int, default=100)
    s.add_argument("--container", default="", help="在加密容器内检索")
    s.add_argument("--password", default="", help="容器口令")
    s.add_argument("--keywords", default="", help="容器检索关键词（逗号分隔）")
    s.set_defaults(func=cmd_search)

    s = sub.add_parser("container", help="取证容器：加密卷/镜像/抓包/APK（非内存镜像检材通道）")
    s.add_argument("container_cmd", choices=["identify", "files", "extract",
                                             "crypto", "xfs", "traffic", "apk"])
    s.add_argument("target", help="目标文件")
    s.add_argument("--password", default="", help="加密卷口令")
    s.add_argument("--path", default="", help="要提取的卷内路径")
    s.add_argument("--kind", default="interfaces",
                   choices=["interfaces", "bluetooth", "rename", "hid"])
    s.set_defaults(func=cmd_container)

    # ---- 新增：镜像挂载 / 文件雕刻 / 哈希 ----
    s = sub.add_parser("mount", help="★ 镜像挂载：打开镜像→分区/FS→浏览/读/提取（新增）")
    s.add_argument("mount_cmd", choices=["open", "list", "read", "extract", "carve", "search"])
    s.add_argument("target", help="镜像/容器文件（RAW/E01/VMDK/VeraCrypt，自动识别）")
    s.add_argument("--password", default="", help="VeraCrypt 口令")
    s.add_argument("--vol", type=int, default=0, help="卷序号（默认 1）")
    s.add_argument("--path", default="", help="卷内路径（read/extract 用）")
    s.add_argument("--out", default="", help="提取目标路径")
    s.add_argument("--rules", default="", help="雕刻规则（逗号分隔，空=全部 20 条）")
    s.add_argument("--offset", type=int, default=0, help="雕刻区间起点（相对卷）")
    s.add_argument("--length", type=int, default=0, help="雕刻区间长度（0=到卷尾）")
    s.add_argument("--keyword", default="", help="跨编码检索关键词（search 用）")
    s.add_argument("--encodings", default="", help="检索编码（逗号分隔，空=全部 5 种）")
    s.add_argument("--limit", type=int, default=200, help="tree/search 行数上限")
    s.add_argument("--json", action="store_true", help="open 时输出 JSON")
    s.set_defaults(func=cmd_mount)

    s = sub.add_parser("carve", help="文件雕刻：按 20 条签名从镜像/区间抠出对象")
    s.add_argument("target", help="镜像/容器文件")
    s.add_argument("--password", default="", help="VeraCrypt 口令")
    s.add_argument("--vol", type=int, default=0, help="在指定卷内雕刻（否则整盘）")
    s.add_argument("--rules", default="", help="规则名（逗号分隔，空=全部）")
    s.add_argument("--offset", type=int, default=0)
    s.add_argument("--length", type=int, default=0)
    s.add_argument("--out", default="", help="把命中导出到目录（自动命名+哈希）")
    s.set_defaults(func=cmd_carve)

    s = sub.add_parser("hash", help="哈希：MD5/SHA-1/SHA-256/SM3（新增统一入口）")
    s.add_argument("target", help="要哈希的文件")
    s.add_argument("--algos", default="", help="逗号分隔算法（默认全部 4 个）")
    s.add_argument("--json", action="store_true", help="输出 JSON")
    s.set_defaults(func=cmd_hash)

    s = sub.add_parser("evidence", help="证据登记与保管链：add/list/verify（新增）")
    s.add_argument("evidence_cmd", choices=["add", "list", "verify"])
    s.add_argument("target", nargs="?", help="要登记的镜像（add 用）")
    s.add_argument("--password", default="", help="VeraCrypt 口令")
    s.add_argument("--note", default="", help="登记备注")
    s.set_defaults(func=cmd_evidence)

    s = sub.add_parser("dimensions", help="五维判定（违规跨境访问检测：工具/通道/执行/外联/方向）")
    s.add_argument("case_id")
    s.add_argument("--usage", choices=["check", "forensic"], default="check",
                   help="检查用法（三档）或取证用法（A/B/C 级，默认 check）")
    s.add_argument("--allow-direction", action="store_true",
                   help="开启访问方向维度（方案要求默认关闭、需单独授权）")
    s.set_defaults(func=cmd_dimensions)

    s = sub.add_parser("rulepack", help="规则包：版本 / 阈值 / 白名单 / 词表（外置，可离线更新与回滚）")
    s.add_argument("--import", dest="import_pack", help="导入离线规则包 JSON（本地文件）")
    s.add_argument("--activate", help="切换生效版本 / 回滚到指定 pack_id")
    s.add_argument("--export", help="导出指定规则包（交付给业务侧改阈值）")
    s.add_argument("--out", help="导出路径")
    s.add_argument("--no-activate", action="store_true", help="只导入不激活")
    s.set_defaults(func=cmd_rulepack)

    s = sub.add_parser("audit", help="审计记录与保管链哈希链校验")
    s.add_argument("case_id", nargs="?", default="", help="案件 ID（留空=全部）")
    s.add_argument("--verify", action="store_true", help="只校验哈希链完整性")
    s.add_argument("--critical", action="store_true", help="只看四类重点操作")
    s.add_argument("--limit", type=int, default=100, help="最多显示条数")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("gaps", help="缺口清单：缺什么 / 为什么 / 怎么补")
    s.add_argument("case_id")
    s.add_argument("--dimension", default="", help="只看某个维度/环节")
    s.set_defaults(func=cmd_gaps)

    s = sub.add_parser("verdict", help="一页纸结论：旗标候选 + 关键事实 + 重点发现 + 下一步建议")
    s.add_argument("case_id")
    s.add_argument("--format", choices=["text", "md", "json"], default="text")
    s.add_argument("--out", help="输出路径（留空打印到终端）")
    s.set_defaults(func=cmd_verdict)

    s = sub.add_parser("symbols", help="Volatility3 符号表：查现状 / 只读挂接 / 本地导入")
    s.add_argument("--add-dir", help="把本机已有的 symbols 目录登记为只读符号源（不复制）")
    s.add_argument("--import", dest="import_dir",
                   help="从该目录导入全部 ISF 到 MemLens 工作目录（便携离线符号库）")
    s.add_argument("--import-kernel", dest="import_kernel", metavar="IMAGE",
                   help="按该镜像的内核 GUID 精确导入所需 ISF（大符号库的正确用法）")
    s.add_argument("--from", dest="from_dir",
                   help="配合 --import-kernel：指定符号库目录（默认用已登记的只读源）")
    s.add_argument("--convert-image", dest="convert_image", metavar="IMAGE",
                   help="按该镜像内核 GUID，从本地 PDB 符号源转出对应 ISF（vol3 离线，仅转需要的 1 个）")
    s.add_argument("--convert-pdb", dest="convert_pdb", metavar="PDB",
                   help="直接把一个本地 PDB 转成 vol3 ISF（缓存到工作目录）")
    s.set_defaults(func=cmd_symbols)

    # ---- 新增：时间线 / 报告 / 知识库 ----
    s = sub.add_parser("timeline", help="导出事件时间线")
    s.add_argument("case_id")
    s.add_argument("--out", help="导出 CSV 路径；留空则在终端显示")
    s.add_argument("--limit", type=int, default=200)
    s.add_argument("--include-untimed", action="store_true", help="保留无时间戳的记录")
    s.set_defaults(func=cmd_timeline)

    s = sub.add_parser("report", help="生成分析报告（Markdown / HTML）")
    s.add_argument("case_id")
    s.add_argument("--format", choices=["md", "html"], default="html")
    s.add_argument("--out", help="输出路径")
    s.add_argument("--max-timeline", type=int, default=120)
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("knowledge", help="取证知识库：征象→结论→下一步")
    s.add_argument("keyword", nargs="?", help="关键词；留空则按案件产物推荐")
    s.add_argument("--case", dest="case_id", help="按该案件已跑插件推荐")
    s.set_defaults(func=cmd_knowledge)

    # ---- v1.0：全栈 Web + 一键深度分析 ----
    s = sub.add_parser("deep", help="★ 一键深度分析（打开即全量，无快速/深度选项）")
    s.add_argument("image")
    s.add_argument("--case-name", help="案件名（默认用文件名）")
    s.add_argument("--workdir", help="工作目录（默认 work/）")
    s.add_argument("-v", "--verbose", action="store_true", help="回显引擎输出")
    s.set_defaults(func=cmd_deep)

    s = sub.add_parser("serve", help="启动 Web 取证控制台（默认形态）")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--no-browser", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("offline-check", help="断网自检：拦截出网，验证 UI/API 仍可用")
    s.set_defaults(func=cmd_offline_check)

    s = sub.add_parser("db", help="数据库：查看后端与数据表")
    s.add_argument("--cases", action="store_true", help="同时列出案件")
    s.set_defaults(func=cmd_db)

    return p


def _harden_stdio() -> None:
    """
    让标准输出/错误"永不因编码问题崩掉"。

    为什么必须有：Windows 中文控制台默认代码页 936（GBK），而本工具的进度/结果
    大量使用 ✅ ❌ ⚠ ✔ △ 这类符号。GBK 编不出这些字符，于是
    `UnicodeEncodeError: 'gbk' codec can't encode character '\\u2705'`
    会在**打印结果的中途**抛出（实测：`memlens engines` 直接崩在自检输出上）——
    用户看到的就是"跑了但啥也没输出"。

    处理方式：**保留控制台原有编码**（GBK 下中文仍然正常显示），只把 errors 改成
    replace —— 编不出的符号退化成 `?`，但绝不会中断整个命令。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            enc = getattr(stream, "encoding", None) or "utf-8"
            stream.reconfigure(encoding=enc, errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            continue


def main(argv: list[str] | None = None) -> int:
    _harden_stdio()
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("\n已中断")
        return 130
    except BrokenPipeError:  # pragma: no cover
        return 0
    except Exception as exc:
        import traceback
        print(f"❌ 执行出错：{exc}", file=sys.stderr)
        if os.environ.get("MEMLENS_DEBUG"):
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
