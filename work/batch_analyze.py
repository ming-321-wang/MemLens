# -*- coding: utf-8 -*-
"""批量用 MemLens 分析平台下载的全部真实样本，统计成功/失败，暴露工具缺陷。"""
import ast
import csv
import json
import subprocess
import sys
import traceback
from pathlib import Path

ROOT = Path(r"D:\MemLens")
sys.path.insert(0, str(ROOT))
from memlens.core.image_probe import probe_image
from memlens.detectors.base import DetectionContext, run_all, get_detector
from memlens.engines import registry
from memlens.storage.db import DataStore

SCAN = ROOT / "work" / "attachments" / "scan"
DB = ROOT / "work" / "batch.db"
if DB.exists():
    DB.unlink()
store = DataStore(DB)
eng = registry.get("static")
plugins = {p.name: p for p in eng.list_plugins()}

# 收集样本
samples = []
for ex in sorted(SCAN.iterdir()):
    if not ex.is_dir():
        continue
    for p in ex.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in (".py", ".md", ".yml", ".yaml", ".json", ".crt", ".key",
                                ".set_abcdef", ".conf", ".c", ".sh", ".html", ".ini",
                                ".tmpl", ".location_override", ".tld", ".6"):
            continue
        if p.stat().st_size > 200 * 1024 * 1024:
            continue
        samples.append(p)
print(f"待分析样本 {len(samples)} 个\n")

results = []
for p in samples:
    rec = {"文件": p.name, "路径": str(p.relative_to(SCAN)), "大小": p.stat().st_size}
    try:
        pr = probe_image(str(p), deep=False, for_engine="static")
        rec["容器"] = pr.container.value
        rec["引擎"] = "static" if pr.container in (
            probe_image.__globals__["ContainerFormat"].EXECUTABLE,
            probe_image.__globals__["ContainerFormat"].ELF_BIN,
            probe_image.__globals__["ContainerFormat"].PCAP,
            probe_image.__globals__["ContainerFormat"].PCAPNG,
        ) else "-"
    except Exception as e:
        rec["容器"] = f"ERR:{type(e).__name__}"
    try:
        cid = store.create_case(p.name, str(p), container=rec.get("容器", ""),
                               os_type="unknown", allow_missing=False)
    except Exception as e:
        rec["案件"] = f"ERR:{e}"
        results.append(rec)
        continue
    total = 0
    errs = []
    for name, pm in plugins.items():
        a = store.start_artifact(cid, "static", name, category="静态分析",
                                 kind="table", params={}, argv=["x"])
        try:
            rows = list(eng.analyze_file(str(p), pm))
        except Exception as e:
            rows = []
            errs.append(f"{name}:{type(e).__name__}:{str(e)[:80]}")
        n = store.add_records(a, rows)
        store.finish_artifact(a, status="ok" if n else "partial", row_count=n)
        total += n
    rec["记录数"] = total
    rec["插件错误"] = "; ".join(errs)
    try:
        ctx = DetectionContext(store, cid)
        out = get_detector("static_sample_suspicious").run(ctx)
        rec["发现项"] = len(out)
        rec["最高分"] = f"{out[0].confidence:.0%}" if out else "-"
    except Exception as e:
        rec["发现项"] = f"ERR:{type(e).__name__}"
    # 关键数据点
    key = {}
    try:
        for r in store.records_of_plugin(cid, "%static.pe%", limit=5):
            if r.get("项") == "PE 头":
                key["PE"] = f"{r.get('位数')}bit {r.get('CPU')} DLL={r.get('DLL')} 签名={r.get('数字签名')}"
        for r in store.records_of_plugin(cid, "%static.elf%", limit=5):
            if r.get("项") == "ELF 头":
                key["ELF"] = f"{r.get('位数')}bit {r.get('类型')} 节={r.get('节区数')} 剥离={r.get('已剥离符号')}"
        pc = next((r for r in store.records_of_plugin(cid, "%pcap%", limit=5)
                   if r.get("项") in ("pcap 概要", "pcapng 概要")), None)
        if pc:
            key["PCAP"] = f"包数={pc.get('包数') or pc.get('EPB 数')} linktype={pc.get('linktype')}"
        prof = store.records_of_plugin(cid, "%static.profile%", limit=3)
        if prof:
            key["画像"] = f"type={prof[0].get('文件类型')} ent={prof[0].get('整体熵')}"
    except Exception:
        pass
    rec["关键数据"] = key
    results.append(rec)
    store.conn.execute("DELETE FROM cases WHERE case_id=?", (cid,))
    store.conn.commit()

store.close()

# 汇总
print("=" * 110)
print(f"{'文件':<28}{'大小':>10} {'容器':<10}{'记录':>6}{'发现':>5} {'最高分':>7}  关键数据")
print("=" * 110)
for r in results:
    kd = r.get("关键数据") or {}
    ks = " | ".join(f"{k}:{v}" for k, v in kd.items() if v)[:90]
    print(f"{r['文件'][:27]:<28}{r['大小']:>10,} {r.get('容器','?'):<10}"
          f"{r.get('记录数',0):>6} {str(r.get('发现项','-')):>5} {str(r.get('最高分','-')):>7}  {ks}")

print("\n=== 插件错误汇总（工具缺陷）===")
errs = [r for r in results if r.get("插件错误")]
print(f"报错样本数: {len(errs)}")
from collections import Counter
c = Counter()
for r in errs:
    for e in r["插件错误"].split("; "):
        c[e.split(":")[0] + ":" + e.split(":")[1][:40] if ":" in e else e] += 1
for k, n in c.most_common():
    print(f"  {n:>3}x {k}")

print("\n=== 容器识别分布 ===")
c2 = Counter(r.get("容器", "?") for r in results)
for k, n in c2.most_common():
    print(f"  {n:>3}x {k}")

with open(ROOT / "work" / "batch_results.csv", "w", newline="", encoding="utf-8-sig") as fp:
    w = csv.DictWriter(fp, fieldnames=["文件", "路径", "大小", "容器", "引擎", "记录数",
                                       "发现项", "最高分", "插件错误"])
    w.writeheader()
    for r in results:
        w.writerow({k: r.get(k, "") for k in w.fieldnames})
print(f"\n已存 work/batch_results.csv")
