# -*- coding: utf-8 -*-
"""对照测试：确认字符串收紧没误杀良性样本的真实字符串。"""
import sys
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))
from memlens.engines.static import StaticEngine, profile_file
from memlens.detectors.base import DetectionContext, get_detector
from memlens.storage.db import DataStore

eng = StaticEngine()
pm = {p.name: p for p in eng.list_plugins()}
db = ROOT / "work" / "strtest.db"
if db.exists():
    db.unlink()
store = DataStore(db)

SAMPLES = [
    (r"C:\Windows\System32\notepad.exe", "benign-notepad"),
    (r"C:\Windows\System32\calc.exe", "benign-calc"),
    (r"C:\Windows\System32\mmc.exe", "benign-mmc"),
    (r"D:\MemLens\work\attachments\512_512_可疑文件\TestDLL.dll", "MAL-TestDLL"),
    (r"D:\MemLens\work\attachments\1028_1028_challenge\challenge.pcap", "pcap"),
]

print(f"{'样本':<16} {'类型':<8} {'strings':>7}  分类")
for path, tag in SAMPLES:
    if not Path(path).exists():
        print(f"{tag:<16} 不存在")
        continue
    prof = profile_file(path)
    srows = list(eng.analyze_file(path, pm["static.strings"]))
    cats = {}
    for r in srows:
        c = r.get("类别")
        if c:
            cats[c] = cats.get(c, 0) + 1
    print(f"{tag:<16} {prof.file_type:<8} {len(srows):>7}  {cats}")
    for r in srows[:3]:
        print(f"       [{r.get('类别')}] {str(r.get('字符串'))[:70]}")

print("\n=== 检测器评分对照（benign 应低 / MAL 应高）===")
for path, tag in SAMPLES:
    if not Path(path).exists():
        continue
    prof = profile_file(path)
    cid = store.create_case(tag, path, container=prof.file_type, os_type="unknown",
                            allow_missing=True)
    for pn in ("static.profile", "static.pe", "static.elf", "static.strings"):
        a = store.start_artifact(cid, "static", pn, category="静态分析",
                                 kind="table", params={}, argv=["x"])
        try:
            rows = list(eng.analyze_file(path, pm[pn]))
        except Exception:
            rows = []
        store.add_records(a, rows)
        store.finish_artifact(a, status="ok" if rows else "partial", row_count=len(rows))
    out = get_detector("static_sample_suspicious").run(DetectionContext(store, cid))
    if out:
        d = out[0]
        print(f"  {tag:<16} [{d.severity.upper():<6}] {d.confidence:.0%}  {d.title}")
        print(f"       权重: {d.evidence.get('命中权重')}")
    else:
        print(f"  {tag:<16} 未触发（评分低于阈值）")

store.close()
