# -*- coding: utf-8 -*-
"""GUI 自动化验证（offscreen，不弹窗打扰用户）：验证主窗口装配 + 引擎集成 + 表格联动。"""
from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ["QT_QPA_PLATFORM"] = "offscreen"
ROOT = Path(r"D:\DSH\工作区\MemLens")
sys.path.insert(0, str(ROOT))

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from memlens.ui.main_window import MainWindow

app = QApplication([])
win = MainWindow(project_root=ROOT)
win.show()

RESULT = {}
_DONE = {"flag": False}


def _guard(fn):
    """包一层：任何异常都记录下来并结束，绝不让 app.exec() 无定时器地空转（会挂死）。"""
    def inner(*a, **kw):
        try:
            fn(*a, **kw)
        except Exception as exc:            # noqa: BLE001
            import traceback
            traceback.print_exc()
            RESULT["error"] = f"{fn.__name__}: {exc!r}"
            finish()
    return inner


def phase1():
    """等 _bootstrap 完成引擎自检与插件枚举。"""
    RESULT["engine"] = win._engine_name()
    RESULT["plugins"] = len(win.plugins)
    RESULT["tree_tops"] = win.plugin_tree.topLevelItemCount()
    RESULT["selected_after_preset"] = len(win.selected_plugins())
    RESULT["analyze_enabled"] = win.btn_analyze.isEnabled()
    RESULT["preset"] = win.preset_box.currentText()
    # 搜索过滤
    win.plugin_search.setText("process")
    vis = 0
    for i in range(win.plugin_tree.topLevelItemCount()):
        top = win.plugin_tree.topLevelItem(i)
        if top.isHidden():
            continue
        for j in range(top.childCount()):
            if not top.child(j).isHidden():
                vis += 1
    RESULT["search_process_visible"] = vis
    win.plugin_search.setText("")
    # 全选
    win._set_all_checked(True)
    RESULT["selected_all"] = len(win.selected_plugins())
    win._set_all_checked(False)
    win._apply_preset(win.preset_box.currentText())
    RESULT["selected_preset"] = len(win.selected_plugins())

    # 载入合成样本，验证探测 worker
    sample = ROOT / "samples" / "synthetic_windows.raw"
    win.load_image(str(sample))
    QTimer.singleShot(6000, phase2)


def phase2():
    pr = win.probe_result
    RESULT["probe_container"] = pr.container.value if pr else None
    RESULT["probe_os"] = pr.os_type.value if pr else None
    RESULT["probe_analysable"] = pr.analysable if pr else None
    RESULT["warn_view_len"] = len(win.warn_view.toPlainText())
    RESULT["warn_view"] = win.warn_view.toPlainText()[:200]
    RESULT["env_card_ok"] = win.card_env is not None

    # 表格联动测试：往库里塞几行假记录，验证分页表格（先建案件，外键约束才放行）
    try:
        case_id = win.store.create_case("GUI-自测案件", str(ROOT / "samples" / "synthetic_windows.raw"))
        RESULT["test_case"] = case_id
        art = win.store.start_artifact(case_id, "vol3", "windows.pslist.PsList",
                                       category="进程", kind="table", params={}, argv=["x"])
        win.store.add_records(art, [
            {"PID": 4, "PPID": 0, "ImageFileName": "System", "Threads": 145},
            {"PID": 1234, "PPID": 4, "ImageFileName": "evil.exe", "Threads": 8},
        ])
        win.store.finish_artifact(art, status="ok", row_count=2)
        win.result_table.show_artifact(art, "进程列表（测试）")
        RESULT["table_rows"] = win.result_table.model.rowCount()
        RESULT["table_cols"] = win.result_table.model.columnCount()
        RESULT["table_status"] = win.result_table.page_label.text()
        # 产物选择器（新增：一次分析几十个产物要能翻看）
        win.case_id = case_id
        win._load_case_results()
        RESULT["artifact_combo"] = win.result_table.artifact_combo.count()
        RESULT["combo_label"] = win.result_table.artifact_combo.currentText()
        # 过滤
        win.result_table.search.setText("evil")
        win.result_table._on_search()
        RESULT["table_filtered_rows"] = win.result_table.model.rowCount()
        # 排序
        win.result_table.model.sort(0, 0)
        RESULT["sort_ok"] = True
        # 导出
        out = ROOT / "work" / "_gui_test_export.csv"
        n = win.store.export_records_csv(out, artifact_id=art)
        RESULT["export_rows"] = n
        RESULT["export_exists"] = out.exists()
        # 发现项表格（挂一条假发现项）
        win.store.add_finding(case_id, title="GUI 自测发现项", detector="self_test",
                              severity="high", confidence=0.9, sources=["psscan"],
                              evidence={"pid": 1234})
        win.case_id = case_id
        win.refresh_findings()
        RESULT["finding_rows"] = win.finding_table.rowCount()
    except Exception as exc:
        RESULT["table_error"] = repr(exc)

    QTimer.singleShot(500, finish)


def finish():
    if _DONE["flag"]:
        return
    _DONE["flag"] = True
    print("=" * 60, flush=True)
    for k, v in RESULT.items():
        print(f"{k:26} = {v}", flush=True)
    print("=" * 60, flush=True)
    ok = (RESULT.get("plugins", 0) >= 20
          and RESULT.get("probe_container") == "raw"
          and RESULT.get("table_rows") == 2
          and RESULT.get("artifact_combo", 0) >= 1
          and RESULT.get("export_rows") == 2)
    print("GUI 验证：", "通过 ✅" if ok else "存在问题 ⚠", flush=True)
    app.quit()


phase1 = _guard(phase1)
phase2 = _guard(phase2)

QTimer.singleShot(9000, phase1)
# 兜底：任何一步卡住都强制收尾，避免"测试挂死"这种最难查的失败形态
QTimer.singleShot(45000, finish)
app.exec()
