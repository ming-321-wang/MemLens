# -*- coding: utf-8 -*-
"""MemLens 静态引擎 × 真实赛题样本：15MB ELF + USD + locked 文件。"""
import sys
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))

from memlens.core.image_probe import describe, probe_image
from memlens.detectors.base import DetectionContext, get_detector
from memlens.engines.static import StaticEngine, profile_file, profile_to_records
from memlens.storage.db import DataStore

BASE = Path(r"E:\附件原件\solar应急响应\solarsec_202603")
OUT = ROOT / "work" / "solarsec"
OUT.mkdir(parents=True, exist_ok=True)

engine = StaticEngine()
plugins = {p.name: p for p in engine.list_plugins()}
db_path = OUT / "solarsec.db"
if db_path.exists():
    db_path.unlink()
store = DataStore(db_path)

TARGETS = [
    BASE / "03d44cc44664aad7816fa73dc38ce8e2a67864911ceb75c49f90fabfdb821ab5",
    BASE / "USD",
    BASE / "flag.solarsec.locked",
    BASE / "dumped_4053_[23d1000-253e000].bin",
]

for t in TARGETS:
    if not t.exists():
        continue
    print("#" * 74)
    print(f"# {t.name}")
    print("#" * 74)

    # ---- 探测 ----
    pr = probe_image(str(t), deep=False, for_engine="static")
    print(f"[探测] {pr.summary()}")

    # ---- 静态引擎 ----
    prof = profile_file(str(t))
    print(f"[画像] type={prof.file_type} size={prof.size:,} entropy={prof.entropy} lang={prof.language!r}")
    if prof.pe:
        print(f"[PE]   {prof.pe.bits}bit {prof.pe.machine} driver={prof.pe.is_driver}")
    if prof.notes:
        for n in prof.notes[:6]:
            print(f"  ⚠ {n}")

    case_id = store.create_case(t.name, str(t), container=pr.container.value,
                               os_type=pr.os_type.value, allow_missing=True)
    total = 0
    for pname in ("static.profile", "static.pe", "static.strings", "static.packer"):
        try:
            rows = list(engine.analyze_file(str(t), plugins[pname]))
        except Exception as exc:
            print(f"  [{pname}] ✘ {exc}")
            continue
        art = store.start_artifact(case_id, "static", pname, category="静态分析",
                                   kind="table", params={}, argv=["x"])
        store.add_records(art, rows)
        store.finish_artifact(art, status="ok", row_count=len(rows))
        total += len(rows)

    print(f"[入库] {total} 条记录")

    # ---- 检测器 ----
    ctx = DetectionContext(store, case_id)
    det = get_detector("static_pe_suspicious")
    out = det.run(ctx)
    if out:
        for d in out:
            print(f"[检测] [{d.severity.upper()}] {d.title}")
            print(f"       权重={d.evidence.get('命中权重')}")
    else:
        print("[检测] 未触发（benign 或非 PE）")

    # ---- 关键内容抽样（strings 里的 URL/IP/命令行） ----
    strs = [r for r in engine.analyze_file(str(t), plugins["static.strings"])]
    interesting = [r for r in strs if r.get("类别") in ("URL 外联", "共享路径", "命令行痕迹", "加壳标记")]
    if interesting:
        print("[字符串] 高危类别命中：")
        for r in interesting[:10]:
            print(f"   [{r['类别']}] {str(r['字符串'])[:110]}")
    # ELF 专属：导出的动态符号
    if prof.file_type == "elf":
        sym_rows = [r for r in engine.analyze_file(str(t), plugins["static.pe"])
                    if str(r.get("项", "")).startswith("动态符号")]
        if sym_rows:
            names = ", ".join(r["名称"] for r in sym_rows[:25])
            print(f"[ELF] 动态符号 {len(sym_rows)} 个（前 25）：{names}")

    print(f"[统计] {store.stats(case_id)}")
    print()

store.close()
print("案件库：", db_path)
