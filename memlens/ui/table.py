"""
MemLens · 结果表格（服务端分页 + 关键词过滤 + 排序 + 导出）

为什么不用 QTableWidget：内存镜像的插件产物动辄数万到数十万行，
必须"按页从数据库取"，否则界面会先被数据压死。
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from memlens.storage.db import DataStore


class DictTableModel(QAbstractTableModel):
    """以 list[dict] 为数据源的表格模型（列由首行键决定，支持增量设置）。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._rows: list[dict[str, Any]] = []
        self._cols: list[str] = []

    # ---------------------------------------------------------------- 数据
    def set_rows(self, rows: list[dict[str, Any]], columns: list[str] | None = None) -> None:
        self.beginResetModel()
        self._rows = rows
        if columns:
            self._cols = columns
        else:
            cols: list[str] = []
            for r in rows[:200]:          # 只扫描前若干行推列，避免大结果集卡顿
                for k in r.keys():
                    if k not in cols:
                        cols.append(str(k))
            self._cols = cols
        self.endResetModel()

    def rows(self) -> list[dict[str, Any]]:
        return self._rows

    # ---------------------------------------------------------------- Qt 接口
    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._cols)

    def data(self, index: QModelIndex, role=Qt.DisplayRole):  # noqa: N802
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = self._cols[index.column()]
        value = row.get(col, "")
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            if isinstance(value, (list, dict)):
                text = str(value)
            elif isinstance(value, bytes):
                text = value.hex()
            else:
                text = "" if value is None else str(value)
            return text if len(text) < 500 else text[:500] + "…"
        if role == Qt.ForegroundRole:
            # 轻微可视化：PID 为奇数的行不做特殊处理，但"疑似/注入"类关键词标红
            text = str(value)
            if any(k in text for k in ("Injected", "Malfind", "PAGE_EXECUTE_READWRITE")):
                return QColor("#d9534f")
        return None

    def headerData(self, section: int, orientation, role=Qt.DisplayRole):  # noqa: N802
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self._cols[section] if section < len(self._cols) else ""
        return str(section + 1)

    def sort(self, column: int, order=Qt.AscendingOrder) -> None:  # noqa: N802
        if not self._cols or column >= len(self._cols):
            return
        key = self._cols[column]

        def sort_key(row: dict[str, Any]):
            v = row.get(key)
            if v is None:
                return (1, "")
            if isinstance(v, (int, float)):
                return (0, v)
            text = str(v)
            # 十六进制/纯数字混合时按数值排更符合直觉
            try:
                return (0, int(text, 0))
            except (ValueError, TypeError):
                return (0, text)

        self.beginResetModel()
        self._rows.sort(key=sort_key, reverse=(order == Qt.DescendingOrder))
        self.endResetModel()


class ResultTableWidget(QWidget):
    """带分页、过滤、导出的结果浏览控件。"""

    status = Signal(str)

    def __init__(self, store: DataStore, parent=None) -> None:
        super().__init__(parent)
        self.store = store
        self.artifact_id: str | None = None
        self.plugin_name: str = ""
        self.page = 0
        self.page_size = 200
        self.keyword = ""
        self.total = 0
        self._artifacts: list[dict[str, Any]] = []
        self._build_ui()

    # ---------------------------------------------------------------- UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        bar = QHBoxLayout()
        # 产物选择器：一次分析会有几十个产物，只显示"最后一个"等于没结果可看
        bar.addWidget(QLabel("产物："))
        self.artifact_combo = QComboBox()
        self.artifact_combo.setMinimumWidth(300)
        self.artifact_combo.setToolTip("本次分析的所有产物（行数>0）；切换即翻看对应数据表")
        self.artifact_combo.currentIndexChanged.connect(self._on_artifact_pick)
        bar.addWidget(self.artifact_combo)

        self.label = QLabel("（尚未选择结果）")
        self.label.setStyleSheet("font-weight: bold;")
        bar.addWidget(self.label)
        bar.addStretch(1)

        bar.addWidget(QLabel("过滤："))
        self.search = QLineEdit()
        self.search.setPlaceholderText("关键词（回车过滤）")
        self.search.setFixedWidth(220)
        self.search.returnPressed.connect(self._on_search)
        bar.addWidget(self.search)

        bar.addWidget(QLabel("每页："))
        self.page_combo = QComboBox()
        for n in (100, 200, 500, 1000, 5000):
            self.page_combo.addItem(str(n), n)
        self.page_combo.setCurrentIndex(1)
        self.page_combo.currentIndexChanged.connect(self._on_page_size)
        bar.addWidget(self.page_combo)

        self.btn_prev = QPushButton("◀ 上一页")
        self.btn_prev.clicked.connect(lambda: self._goto(self.page - 1))
        self.btn_next = QPushButton("下一页 ▶")
        self.btn_next.clicked.connect(lambda: self._goto(self.page + 1))
        bar.addWidget(self.btn_prev)
        bar.addWidget(self.btn_next)

        self.btn_export = QPushButton("导出 CSV")
        self.btn_export.clicked.connect(self._export)
        bar.addWidget(self.btn_export)
        layout.addLayout(bar)

        self.model = DictTableModel(self)
        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setAlternatingRowColors(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.view.setSortingEnabled(True)
        self.view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.verticalHeader().setDefaultSectionSize(22)
        layout.addWidget(self.view)

        self.page_label = QLabel("")
        layout.addWidget(self.page_label)

    # ---------------------------------------------------------------- 数据
    def show_artifact(self, artifact_id: str, plugin_name: str = "", keyword: str = "") -> None:
        self.artifact_id = artifact_id
        self.plugin_name = plugin_name or artifact_id
        self.keyword = keyword
        self.page = 0
        self._sync_combo(artifact_id)
        self.refresh()

    def set_keyword(self, keyword: str) -> None:
        self.keyword = keyword
        self.page = 0
        self.refresh()

    # ---------------------------------------------------------------- 产物浏览
    #: 产物价值排序：打开结果页时优先显示这些（内存取证第一眼该看的东西）
    _PRIORITY: tuple[str, ...] = (
        "process", "pslist", "psscan", "findevil", "net", "netscan",
        "registry_run", "services", "malfind", "timeline_process",
        "hivelist", "users", "sysinfo", "info",
    )

    @classmethod
    def _rank(cls, plugin: str) -> tuple[int, str]:
        low = (plugin or "").lower()
        for i, key in enumerate(cls._PRIORITY):
            if key in low:
                return (i, low)
        return (len(cls._PRIORITY), low)

    def load_case_artifacts(self, artifacts: list[dict[str, Any]], *, prefer: str = "") -> None:
        """
        填充产物下拉框，并自动选中"最值得先看"的那个产物。

        背景（用户体验 bug）：分析完 20+ 个插件后只显示最后一个成功产物的表，
        用户看到的是"一堆日志 + 一张莫名其妙的表"，自然会觉得"这工具没用"。
        """
        usable = [a for a in artifacts if int(a.get("row_count") or 0) > 0]
        self._artifacts = usable
        self.artifact_combo.blockSignals(True)
        self.artifact_combo.clear()
        for a in usable:
            label = f"[{a.get('engine', '')}] {a.get('plugin', '')} · {int(a.get('row_count') or 0):,} 行"
            self.artifact_combo.addItem(label, a["artifact_id"])
        self.artifact_combo.blockSignals(False)
        if not usable:
            return
        chosen = 0
        if prefer:
            for i, a in enumerate(usable):
                if prefer.lower() in str(a.get("plugin", "")).lower():
                    chosen = i
                    break
        else:
            chosen = min(range(len(usable)),
                         key=lambda i: self._rank(str(usable[i].get("plugin", ""))))
        self.artifact_combo.setCurrentIndex(chosen)
        self._show_index(chosen)

    def _show_index(self, index: int) -> None:
        if not (0 <= index < len(self._artifacts)):
            return
        a = self._artifacts[index]
        self.show_artifact(a["artifact_id"], str(a.get("plugin", "")))

    def _on_artifact_pick(self, index: int) -> None:
        self._show_index(index)

    def _sync_combo(self, artifact_id: str) -> None:
        """外部直接 show_artifact 时，把下拉框同步过去（不触发二次刷新）。"""
        for i in range(self.artifact_combo.count()):
            if self.artifact_combo.itemData(i) == artifact_id:
                self.artifact_combo.blockSignals(True)
                self.artifact_combo.setCurrentIndex(i)
                self.artifact_combo.blockSignals(False)
                return

    def refresh(self) -> None:
        if not self.artifact_id:
            return
        self.total = self.store.count_records(artifact_id=self.artifact_id)
        rows = self.store.query_records(
            artifact_id=self.artifact_id,
            keyword=self.keyword or None,
            limit=self.page_size,
            offset=self.page * self.page_size,
        )
        payload = [r["parsed"] for r in rows]
        self.model.set_rows(payload)
        shown = len(payload)
        pages = max(1, (self.total + self.page_size - 1) // self.page_size)
        self.label.setText(f"{self.plugin_name}   共 {self.total:,} 行")
        self.page_label.setText(
            f"第 {self.page + 1}/{pages} 页，本页 {shown} 行"
            + (f"（过滤：{self.keyword}）" if self.keyword else "")
        )
        self.btn_prev.setEnabled(self.page > 0)
        self.btn_next.setEnabled((self.page + 1) * self.page_size < self.total)
        self.status.emit(f"已加载 {self.plugin_name}：{self.total} 行")

    # ---------------------------------------------------------------- 交互
    def _on_search(self) -> None:
        self.keyword = self.search.text().strip()
        self.page = 0
        self.refresh()

    def _on_page_size(self) -> None:
        self.page_size = int(self.page_combo.currentData())
        self.page = 0
        self.refresh()

    def _goto(self, page: int) -> None:
        if page < 0:
            return
        self.page = page
        self.refresh()

    def _export(self) -> None:
        if not self.artifact_id:
            QMessageBox.information(self, "提示", "还没有可导出的结果")
            return
        default = f"{self.plugin_name.replace('.', '_') or 'result'}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "导出 CSV", default, "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            n = self.store.export_records_csv(path, artifact_id=self.artifact_id)
            self.status.emit(f"已导出 {n} 行 → {path}")
            QMessageBox.information(self, "导出完成", f"已导出 {n} 行到：\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "导出失败", str(exc))
