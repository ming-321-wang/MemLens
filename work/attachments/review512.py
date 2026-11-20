# -*- coding: utf-8 -*-
"""查看 qsnctf-512 案件的全部记录与发现项，评估检测质量。"""
import json
import sys
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))
from memlens.storage.db import DataStore

db = ROOT / "work" / "memlens.db"
store = DataStore(db)
cases = store.list_cases()
c = [x for x in cases if "512" in x["name"]]
if not c:
    print("案件不存在，所有案件:", [x["name"] for x in cases]); raise SystemExit
cid = c[-1]["case_id"]
print(f"案件 {cid}  {c[-1]['name']}\n")

for art in store.list_artifacts(cid):
    print(f"### {art['plugin']}  ({art['row_count']} 行, {art['status']})")
    if art["plugin"] == "static.profile":
        for r in store.records_of_plugin(cid, "%static.profile%", limit=20):
            print("   ", {k: v for k, v in r.items() if k in
                  ("文件", "文件类型", "整体熵", "语言/运行时", "SHA-256", "画像提醒")})
    elif art["plugin"] == "static.pe":
        recs = store.records_of_plugin(cid, "%static.pe%", limit=200)
        hdr = next((r for r in recs if r.get("项") == "PE 头"), None)
        if hdr:
            print("    PE 头:", {k: v for k, v in hdr.items()
                  if k not in ("文件", "项")})
        secs = [r for r in recs if r.get("项") == "节区"]
        print(f"    节区 {len(secs)}:")
        for s in secs:
            print(f"       {s.get('节名'):<10} size={s.get('原始大小'):>9,} ent={s.get('熵')} WX={s.get('可写且可执行(W+X)')}")
        imps = [r for r in recs if r.get("项") == "导入表"]
        print(f"    导入表 {len(imps)} 个 DLL:")
        for i in imps:
            fn = (i.get("函数") or "")[:200]
            print(f"       {i.get('DLL'):<20} {i.get('函数数')} 函数: {fn}")
        exp = [r for r in recs if r.get("项") == "导出表"]
        for e in exp:
            print(f"    导出表: {e.get('导出函数数')} 个: {(e.get('函数') or '')[:300]}")
    elif art["plugin"] == "static.strings":
        for r in store.records_of_plugin(cid, "%static.strings%", limit=40):
            print(f"    [{r.get('类别'):<12}] {str(r.get('字符串'))[:100]}")
    print()

print("=" * 70)
print("发现项：")
for f in store.list_findings(cid):
    print(f"[{f['severity'].upper()}] {f['confidence']:.0%} {f['title']}")
    print(f"  说明: {f['description'][:200]}")
    ev = f.get("evidence") or {}
    print(f"  权重: {ev.get('命中权重')}")
    for k in ("格式", "文件类型", "位数/CPU", "是否DLL", "是否驱动", "静态链接",
              "已剥离", "依赖库", "SHA-256", "加壳标记", "导入函数数"):
        if k in ev:
            print(f"  {k}: {ev[k]}")
    print(f"  高危字符串: {ev.get('高危字符串样例')}")

store.close()
