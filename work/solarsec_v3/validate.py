# -*- coding: utf-8 -*-
"""
MemLens v0.3 真实样本验证：solarsec_202603 的全部 8 个文件。

验证点：
  ① 容器探测：15MB ELF / USD(ELF) / dumped(bin) / flag.locked / synthetic 对照
  ② ELF 解析：节区/动态符号/导入导出/依赖库/build-id/本地函数
  ③ 字符串去噪：bash 补全脚本不再被误报为 UNC/共享路径
  ④ 检测器：ELF 也能出可疑性评分，benign 系统文件不出误报
  ⑤ 记录入库与统计
"""
import sys
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))

from memlens.core.image_probe import ContainerFormat, describe, probe_image
from memlens.detectors.base import DetectionContext, run_all, get_detector
from memlens.engines import registry
from memlens.storage.db import DataStore

BASE = Path(r"E:\附件原件\solar应急响应\solarsec_202603")
OUT = ROOT / "work" / "solarsec_v3"
OUT.mkdir(parents=True, exist_ok=True)

engine = registry.get("static")
plugins = {p.name: p for p in engine.list_plugins()}
print("static 插件:", sorted(plugins))

db = OUT / "v3.db"
if db.exists():
    db.unlink()
store = DataStore(db)

TARGETS = [
    BASE / "03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5",
    BASE / "USD",
    BASE / "flag.solarsec.locked",
    BASE / "dumped_4053_[23d1000-253e000].bin",
    BASE / "dumped_4053_[400000-4f4000].bin",
    BASE / "dumped_4053_[7fe648a0b000-7fe648a16000].bin",
]

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'OK ' if cond else 'FAIL'} {name}" + (f"  [{detail}]" if detail else ""))


for t in TARGETS:
    if not t.exists():
        continue
    print("=" * 78)
    print(f"# {t.name}  ({t.stat().st_size:,} B)")
    print("=" * 78)

    pr = probe_image(str(t), deep=(t.stat().st_size < 20 << 20), for_engine="static")
    print(f"  [探测] {pr.summary()}")
    print(f"  [标签] {describe(pr).splitlines()[3]}")
    for w in pr.warnings:
        print(f"         ! {w[:120]}")

    case_id = store.create_case(t.name, str(t), container=pr.container.value,
                               os_type=pr.os_type.value, os_confidence=pr.os_confidence,
                               allow_missing=True)
    total = 0
    by_plugin = {}
    for name in ("static.profile", "static.elf", "static.pe", "static.strings",
                 "static.packer", "static.deps"):
        if name not in plugins:
            continue
        try:
            rows = list(engine.analyze_file(str(t), plugins[name]))
        except Exception as exc:
            print(f"  [{name}] ERROR {exc}")
            continue
        art = store.start_artifact(case_id, "static", name, category="静态分析",
                                   kind="table", params={}, argv=["x"])
        store.add_records(art, rows)
        store.finish_artifact(art, status="ok" if rows else "partial",
                              row_count=len(rows))
        by_plugin[name] = len(rows)
        total += len(rows)
    print(f"  [入库] {total} 条  {by_plugin}")

    # ELF 结构摘要
    elf_rows = store.records_of_plugin(case_id, "%static.elf%", limit=100)
    hdr = next((r for r in elf_rows if r.get("项") == "ELF 头"), None)
    if hdr:
        print(f"  [ELF ] {hdr.get('位数')}bit {hdr.get('类型')} {hdr.get('机器')} "
              f"入口={hdr.get('入口点')} interp={hdr.get('解释器')} "
              f"节={hdr.get('节区数')} 符号={hdr.get('符号数')} "
              f"导入={hdr.get('导入函数数')} 导出={hdr.get('导出函数数')} "
              f"依赖={hdr.get('依赖库数')} stripped={hdr.get('已剥离符号')} "
              f"buildid={str(hdr.get('build-id'))[:16]}")
        secs = [r for r in elf_rows if r.get("项") == "节区"]
        wx = [s for s in secs if s.get("可写可执行(W+X)")]
        hi = sorted(secs, key=lambda s: -(s.get("熵") or 0))[:3]
        print(f"  [节区] {len(secs)} 个，W+X {len(wx)}，高熵前三: "
              + ", ".join(f"{s.get('节名')}({s.get('熵')})" for s in hi))
        dep = next((r for r in elf_rows if r.get("项") == "依赖库"), None)
        if dep:
            print(f"  [依赖] {dep.get('库')}")
        loc = next((r for r in elf_rows if r.get("项") == "本地函数（符号表）"), None)
        if loc:
            names = (loc.get("函数") or "").split(", ")[:12]
            print(f"  [用户函数] {loc.get('数量')} 个，样例: {names}")

    # 字符串去噪验证
    srows = store.records_of_plugin(case_id, "%static.strings%", limit=200)
    cats = {}
    for r in srows:
        c = r.get("类别")
        if c:
            cats[c] = cats.get(c, 0) + 1
    print(f"  [字符串] 分类分布: {cats}")
    unc = [r for r in srows if r.get("类别") == "UNC/共享路径"]
    noise = [r for r in unc if "${" in str(r.get("字符串", "")) or "awk" in str(r.get("字符串", ""))
             or "//" in str(r.get("字符串", ""))]
    if unc:
        print(f"          UNC 命中 {len(unc)} 条，其中脚本噪声 {len(noise)} 条")
        for r in unc[:3]:
            print(f"            - {str(r.get('字符串'))[:90]}")

    # 检测器
    ctx = DetectionContext(store, case_id)
    det = get_detector("static_sample_suspicious")
    out = det.run(ctx)
    if out:
        for d in out:
            print(f"  [检测] [{d.severity.upper()}] {d.title}")
            print(f"         权重: {d.evidence.get('命中权重')}")
    else:
        print(f"  [检测] 未触发（评分低于阈值）")
    st = store.stats(case_id)
    print(f"  [统计] {st}")
    print()

store.close()

print("=" * 78)
print(f"通过 {len(PASS)} 项 / 失败 {len(FAIL)} 项")
if FAIL:
    print("FAILED:", FAIL)
