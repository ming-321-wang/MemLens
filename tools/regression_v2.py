# -*- coding: utf-8 -*-
"""
MemLens 回归测试 v2（offscreen GUI + CLI 静态域）

覆盖：引擎自检 / 插件枚举（vol3 180 + static 4）/ 引擎切换 / 预设切换 /
      探测对 PE 与内存样本的分流 / 静态引擎端到端入库 / 检测器双向判定 /
      表格-过滤-排序 / CSV 导出（NUL 安全）/ 发现项表。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"
ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from memlens.engines import registry
from memlens.ui.main_window import MainWindow, PRESETS, CATEGORY_ORDER

R: dict[str, object] = {}
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'✅' if cond else '❌'} {name}" + (f"   {detail}" if detail else ""))


def phase1():
    # ---- 1. 引擎自检 ----
    avail = {e.name: (ok, why) for e, ok, why in registry.iter_available() if e}
    check("引擎注册：vol3 + static", set(avail) == {"vol3", "static"}, str(set(avail)))
    check("static 引擎可用", avail.get("static", (False,))[0], avail.get("static", ("", ""))[1])

    v3 = registry.get("vol3")
    st = registry.get("static")
    n_vol3 = len(v3.list_plugins()) if v3.available()[0] else 0
    n_st = len(st.list_plugins())
    check("vol3 插件枚举（运行时）", n_vol3 > 150, f"{n_vol3} 个")
    check("static 插件枚举", n_st == 4, f"{n_st} 个")

    app.processEvents()
    QTimer.singleShot(300, phase2)


def phase2():
    win.show()
    # ---- 2. 引擎切换 ----
    keys = list(win._engine_labels)
    check("GUI 引擎下拉含两项", keys == ["vol3", "static"], str(keys))

    win.engine_box.setCurrentIndex(keys.index("static"))
    app.processEvents()
    tops = [win.plugin_tree.topLevelItem(i).text(0) for i in range(win.plugin_tree.topLevelItemCount())]
    check("切 static 后插件树只剩【静态分析】",
          tops == ["静态分析（4）"], str(tops))
    check("切 static 后只列出 static.* 插件",
          all(p.name.startswith("static.") for p in win.plugins))
    sel = win.selected_plugins()
    check("static 默认预设选中 4 项", len(sel) == 4, f"{len(sel)} 项")

    # ---- 3. 探测分流：载入一个真实 PE，应自动切到 static ----
    win.load_image(r"C:\Windows\System32\notepad.exe")
    QTimer.singleShot(6000, phase3)


def phase3():
    pr = win.probe_result
    check("PE 探测识别为 exe", pr is not None and pr.container.value == "exe",
          pr.container.value if pr else "None")
    check("PE 探测后自动切到 static 引擎", win._engine_name() == "static",
          win._engine_name())
    check("static 下可分析", win.btn_analyze.isEnabled())
    check("不再出现自相矛盾的告警",
          all("请改用" not in w for w in pr.warnings), str(pr.warnings[:2]))

    # ---- 4. 静态分析入库 ----
    win.on_analyze()
    QTimer.singleShot(25000, phase4)


def phase4():
    cid = win.case_id
    check("静态分析已建立案件", bool(cid), str(cid))
    arts = win.store.list_artifacts(cid) if cid else []
    ok_arts = [a for a in arts if a["status"] == "ok"]
    check("4 个静态插件全部 ok", len(ok_arts) == 4,
          str([(a["plugin"], a["status"], a["row_count"]) for a in arts]))
    total = win.store.stats(cid)["records"] if cid else 0
    check("记录数 > 100", total > 100, f"{total} 条")

    # ---- 5. 检测器 ----
    notes = []
    win.detect_worker = None
    from memlens.detectors.base import DetectionContext, run_all
    from memlens.detectors.base import get_detector
    ctx = DetectionContext(win.store, cid)
    static_det = get_detector("static_pe_suspicious")
    out = static_det.run(ctx)
    check("静态检测器对 benign 文件不出误报", len(out) == 0, f"{len(out)} 条")
    f, n = run_all(ctx)
    check("benign 样本总发现项为 0", len(f) == 0, f"{len(f)} 条")
    check("检测器有正面反馈（未静默）", any("static_pe_suspicious" in x for x in n), str(n[:2]))

    # ---- 6. 表格 + 导出 ----
    if ok_arts:
        win.result_table.show_artifact(ok_arts[0]["artifact_id"], "画像")
        check("表格有行", win.result_table.model.rowCount() > 0)
        win.result_table.search.setText("sha")
        win.result_table._on_search()
        win.result_table.model.sort(0, 0)
        p = ROOT / "work" / "_reg_export.csv"
        n2 = win.store.export_records_csv(p, artifact_id=ok_arts[0]["artifact_id"])
        check("CSV 导出成功", p.exists() and n2 > 0, f"{n2} 行")
        p.unlink(missing_ok=True)

    print("\n" + "=" * 60)
    print(f"通过 {len(PASS)} 项，失败 {len(FAIL)} 项")
    if FAIL:
        print("失败项：", FAIL)
    else:
        print("回归测试全部通过 ✅")
    app.quit()


app = QApplication([])
win = MainWindow(project_root=ROOT)
QTimer.singleShot(9000, phase1)
app.exec()
