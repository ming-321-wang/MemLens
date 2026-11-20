# -*- coding: utf-8 -*-
"""清理自测产生的数据（保留数据库结构与样本文件）。"""
import sys
from pathlib import Path

ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))
from memlens.storage.db import DataStore

db = ROOT / "work" / "memlens.db"
store = DataStore(db)

before = store.list_cases()
print(f"清理前案件数：{len(before)}")
for c in before:
    print(f"  {c['case_id']}  {c['name']}")

# 删掉全部自测案件（名字里带 GUI-自测 / synthetic 的）
store.conn.execute("DELETE FROM cases WHERE name LIKE 'GUI-自测%' OR name LIKE '%synthetic%'")
store.conn.commit()
after = store.list_cases()
print(f"清理后案件数：{len(after)}")
print("统计：", store.stats(after[0]["case_id"]) if after else "（库已空）")
store.conn.execute("VACUUM")
store.close()

# 删掉测试导出文件
for p in [ROOT / "work" / "_gui_test_export.csv"]:
    if p.exists():
        p.unlink()
        print(f"已删除 {p.name}")
print("清理完成")
