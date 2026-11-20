"""
MemLens · 主窗口（v0.9）

布局：
    ┌─────────────────────────── 工具栏（两行） ─────────────────────────────┐
    │ 打开镜像 │ ⚡一键分析 │ 停止 │ 引擎▾ 预设▾ │ 案件                   │
    │ ⚡找 flag │ 重新检测 │ 情报 │ 报告 │ 引擎自检 │ 符号环境 │ 宽松模式 │ 关于 │
    ├──────────────┬────────────────────────────────────────────────────────┤
    │ 左栏          │ 标签页：①分析 ②运行 ③结果 ④发现项 ⑤旗标 ⑥情报 ⑦日志   │
    │ ·镜像卡片     │   ②运行：结论条 + 阶段进度 + 插件状态表（本版重点）     │
    │ ·环境卡片     │                                                        │
    │ ·案件统计     │                                                        │
    │ ·提醒         │                                                        │
    ├──────────────┴────────────────────────────────────────────────────────┤
    │ 状态栏：当前阶段 + 真实进度 + 耗时                                      │
    └────────────────────────────────────────────────────────────────────────┘

这一版针对的正是"点了开始分析，然后什么都没分析出来"：

  1. **先出线索再出系统信息**：字节快扫（flag/IOC）排在插件之前，几秒~几分钟内就有东西看；
  2. **阶段可见**：内核定位/符号下载/页表扫描全部翻译成人话，配真实百分比与耗时；
  3. **失败可见**：每个插件的状态、行数、耗时、**为什么是 0 行**都摆在表里，不用翻日志；
  4. **结论置顶**：找到 flag 立刻在最上面大号显示，一键复制。
"""

from __future__ import annotations

import os
import time
import traceback
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from memlens.core import flagbank
from memlens.core.image_probe import ContainerFormat, can_analyze, refresh_warnings
from memlens.core.vol3_env import Vol3Env
from memlens.engines import registry
from memlens.engines.base import PluginMeta
from memlens.storage.db import DataStore
from memlens.ui import theme
from memlens.ui.table import ResultTableWidget
from memlens.ui.worker import AnalyzeWorker, DetectWorker, ProbeWorker

APP_TITLE = "MemLens · 内存取证工作台"
VERSION = "0.9.0"

# 预设（与 CLI 保持一致，GUI 用下拉框选；按引擎分组显示）
PRESETS: dict[str, list[str]] = {
    # ---- MemProcFS（虚拟盘取证：一次收集，几十个产物，最快出结果）----
    "🚀 MemProcFS 快速取证（推荐首跑）": [
        "mprocfs.harvest", "mprocfs.sysinfo", "mprocfs.process", "mprocfs.net",
        "mprocfs.netdns", "mprocfs.findevil", "mprocfs.registry_run", "mprocfs.users",
        "mprocfs.cmdlines", "mprocfs.envs", "mprocfs.flag_hits",
    ],
    "MemProcFS 标准取证（进程+网络+服务+异常+持久化）": [
        "mprocfs.harvest", "mprocfs.sysinfo", "mprocfs.process", "mprocfs.threads",
        "mprocfs.modules", "mprocfs.unloaded_modules", "mprocfs.net", "mprocfs.netdns",
        "mprocfs.findevil", "mprocfs.yara", "mprocfs.services", "mprocfs.drivers",
        "mprocfs.files", "mprocfs.registry_run", "mprocfs.registry_hives",
        "mprocfs.eventlog", "mprocfs.users", "mprocfs.timeline_process",
        "mprocfs.timeline_net",
    ],
    "MemProcFS 深度取证（含全部时间线，耗磁盘/时间）": [
        "mprocfs.harvest", "mprocfs.sysinfo", "mprocfs.process", "mprocfs.threads",
        "mprocfs.modules", "mprocfs.unloaded_modules", "mprocfs.handles",
        "mprocfs.net", "mprocfs.netdns", "mprocfs.findevil", "mprocfs.yara",
        "mprocfs.services", "mprocfs.drivers", "mprocfs.devices",
        "mprocfs.virtualmachines", "mprocfs.files", "mprocfs.registry_run",
        "mprocfs.registry_hives", "mprocfs.eventlog", "mprocfs.bitlocker",
        "mprocfs.users", "mprocfs.procinfo", "mprocfs.timeline_process",
        "mprocfs.timeline_net", "mprocfs.timeline_thread", "mprocfs.timeline_ntfs",
        "mprocfs.timeline_registry", "mprocfs.timeline_kernelobject",
    ],
    "MemProcFS 只出进程与网络（几十秒）": [
        "mprocfs.harvest", "mprocfs.process", "mprocfs.net",
    ],
    # ---- Volatility3（内存镜像）----
    "⚡ 秒出线索（字节扫 flag/IOC）": [
        "memstrings.flag", "memstrings.ioc",
    ],
    "快速摸底（约 6 个插件）": [
        "windows.info", "windows.pslist", "windows.psscan",
        "windows.netscan", "windows.cmdline", "banners",
    ],
    "标准分析（约 11 个插件）": [
        "windows.info", "windows.pslist", "windows.psscan", "windows.pstree",
        "windows.cmdline", "windows.dlllist", "windows.netscan", "windows.malfind",
        "windows.modules", "windows.svclist", "banners",
    ],
    "深度分析（约 27 个插件）": [
        "windows.info", "windows.pslist", "windows.psscan", "windows.pstree",
        "windows.psxview", "windows.cmdline", "windows.envars", "windows.privileges",
        "windows.dlllist", "windows.ldrmodules", "windows.handles", "windows.vadinfo",
        "windows.netscan", "windows.netstat", "windows.malfind", "windows.modules",
        "windows.modscan", "windows.driverscan", "windows.callbacks", "windows.ssdt",
        "windows.svclist", "windows.svcdiff", "windows.filescan",
        "windows.registry.hivelist", "windows.registry.hivescan",
        "windows.registry.userassist", "banners",
    ],
    "只看进程与网络（最快）": [
        "windows.info", "windows.pslist", "windows.psscan", "windows.netscan",
    ],
    # ---- 静态样本分析 ----
    "样本全维度（profile+PE+strings+packer）": [
        "static.profile", "static.pe", "static.strings", "static.packer",
    ],
    "样本快速画像（profile+加壳）": [
        "static.profile", "static.packer",
    ],
    # ---- 镜像字节级扫描（不依赖 Volatility，任何容器都能跑）----
    "字节扫描·全量（含全部字符串）": [
        "memstrings.flag", "memstrings.ioc", "memstrings.ascii", "memstrings.utf16",
    ],
}

# 插件分组展示顺序（GUI 树用；与 engines/vol3.py 的 CATEGORY_ORDER 保持一致）
CATEGORY_ORDER = [
    "系统", "进程", "网络", "恶意代码", "注册表", "凭据", "文件", "服务",
    "时间线",
    "Linux-进程与用户", "Linux-网络", "Linux-内核与安全", "Linux-文件系统", "Linux-其他",
    "macOS", "静态分析", "镜像扫描", "其他",
]


def _c(name: str) -> QColor:
    return QColor(theme.__dict__.get(name, theme.TEXT))


def _resolve_workdir(project_root: Path) -> Path:
    """
    解析工作目录（存 memlens.db、产物、vol3 符号缓存）。

    打包成 exe 后 exe 目录**未必可写**（例如放进 Program Files），
    所以策略是：优先用 exe 同目录的 work/（便携、数据跟着程序走）；
    实测不可写则回退到 %LOCALAPPDATA%\\MemLens\\work。
    """
    cand = project_root / "work"
    try:
        cand.mkdir(parents=True, exist_ok=True)
        probe = cand / ".write_test"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        return cand
    except OSError:
        pass
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    fallback = Path(base) / "MemLens" / "work"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


class InfoCard(QFrame):
    """
    左栏的"键值卡片"。

    为什么不用 QGroupBox + QTextEdit 拼字符串：那些值是**会变的**（镜像大小、容器结论、
    符号表状态…），每次 setPlainText 会丢掉选择、也会重新排版；这里让每个字段持有一个
    QLabel，按 (行号) 复用，更新即改文本，不重建控件。
    """

    def __init__(self, title: str, rows: list[tuple[str, str]] | None = None) -> None:
        super().__init__()
        self.setObjectName("Card")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 8, 10, 8)
        outer.setSpacing(4)
        head = QLabel(title)
        head.setObjectName("CardTitle")
        outer.addWidget(head)
        self.grid = QGridLayout()
        self.grid.setContentsMargins(0, 2, 0, 0)
        self.grid.setHorizontalSpacing(8)
        self.grid.setVerticalSpacing(3)
        self.grid.setColumnStretch(1, 1)
        outer.addLayout(self.grid)
        self._values: dict[int, QLabel] = {}
        for i, (k, v) in enumerate(rows or []):
            self.set_value(i, k, v)

    def set_value(self, row: int, key: str, value: str, color: str | None = None) -> None:
        if row not in self._values:
            k = QLabel(key)
            k.setObjectName("CardTitle")
            k.setAlignment(Qt.AlignTop | Qt.AlignLeft)
            v = QLabel("")
            v.setObjectName("CardValue")
            v.setWordWrap(True)
            v.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.grid.addWidget(k, row, 0, Qt.AlignTop)
            self.grid.addWidget(v, row, 1)
            self._values[row] = v
        lbl = self._values[row]
        lbl.setText(value)
        lbl.setStyleSheet(f"color:{color};" if color else "")


class MainWindow(QMainWindow):
    """MemLens 主窗口。"""

    def __init__(self, *, project_root: Path | None = None) -> None:
        super().__init__()
        self.project_root = project_root or Path(__file__).resolve().parents[2]
        self.workdir = _resolve_workdir(self.project_root)
        self.db_path = self.workdir / "memlens.db"
        self.vol3env = Vol3Env(self.workdir)

        self.image_path: str | None = None
        self.probe_result = None
        self.case_id: str | None = None
        self.plugins: list[PluginMeta] = []
        self.probe_worker: ProbeWorker | None = None
        self.analyze_worker: AnalyzeWorker | None = None
        self.detect_worker: DetectWorker | None = None
        self._status_rows: dict[str, int] = {}
        self._phase_started: float = 0.0
        self._last_flag: str = ""

        self.setWindowTitle(f"{APP_TITLE}  v{VERSION}")
        self.resize(1400, 880)
        self._build_ui()
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        QTimer.singleShot(200, self._bootstrap)

    # ================================================================ UI 构建
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 6)
        root.setSpacing(6)

        root.addWidget(self._build_toolbar())

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([330, 1050])
        root.addWidget(splitter, 1)

        # 状态栏：当前阶段 + 真实进度 + 耗时
        self.status_phase = QLabel("就绪")
        self.status_elapsed = QLabel("")
        self.status_elapsed.setStyleSheet(f"color:{theme.TEXT_DIM};")
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(220)
        self.progress.setVisible(False)
        self.phase_bar = QProgressBar()
        self.phase_bar.setObjectName("PhaseBar")
        self.phase_bar.setMaximumWidth(160)
        self.phase_bar.setVisible(False)
        self.statusBar().addWidget(self.status_phase, 1)
        self.statusBar().addPermanentWidget(self.status_elapsed)
        self.statusBar().addPermanentWidget(self.phase_bar)
        self.statusBar().addPermanentWidget(self.progress)

    # ---------------------------------------------------------------- 工具栏
    def _build_toolbar(self) -> QWidget:
        box = QWidget()
        outer = QVBoxLayout(box)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(4)

        # ---- 第一行：证据 / 主流程 ----
        r1 = QHBoxLayout()
        r1.setSpacing(6)
        self.btn_open = QPushButton("📂 打开镜像")
        self.btn_open.clicked.connect(self.on_open_image)
        r1.addWidget(self.btn_open)

        self.btn_analyze = QPushButton("⚡ 一键分析")
        self.btn_analyze.setObjectName("Primary")
        self.btn_analyze.setToolTip("探测 → 字节快扫(flag/IOC) → 内核符号预检 → 所选插件 → 检测器 → 汇总")
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.clicked.connect(self.on_analyze)
        r1.addWidget(self.btn_analyze)

        self.btn_stop = QPushButton("⏹ 停止")
        self.btn_stop.setObjectName("Danger")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.on_stop)
        r1.addWidget(self.btn_stop)

        r1.addSpacing(8)
        r1.addWidget(QLabel("引擎："))
        self.engine_box = QComboBox()
        # MemProcFS 放第一位：同样的镜像它能给出多得多的产物（注册表/事件日志/时间线），
        # 且"一次收集多次读"的模型比 vol3"每插件重解析一遍"快得多。
        self._engine_labels = {"memprocfs": "内存镜像（MemProcFS 虚拟盘 · 推荐）",
                               "vol3": "内存镜像（Volatility 3）",
                               "static": "静态样本（PE/未知二进制）",
                               "memstrings": "镜像字节扫描（字符串/flag/IOC）"}
        self.engine_box.addItems(list(self._engine_labels.values()))
        self.engine_box.setCurrentIndex(0)
        self.engine_box.currentIndexChanged.connect(self._on_engine_changed)
        r1.addWidget(self.engine_box)

        r1.addWidget(QLabel("预设："))
        self.preset_box = QComboBox()
        self.preset_box.addItems(list(PRESETS.keys()))
        self.preset_box.setCurrentIndex(1)
        self.preset_box.currentTextChanged.connect(self._apply_preset)
        r1.addWidget(self.preset_box)

        r1.addStretch(1)
        self.lbl_case = QLabel("未建立案件")
        self.lbl_case.setStyleSheet(f"color:{theme.TEXT_DIM};")
        r1.addWidget(self.lbl_case)
        outer.addLayout(r1)

        # ---- 第二行：取证动作 ----
        r2 = QHBoxLayout()
        r2.setSpacing(6)
        self.btn_flag = QPushButton("⚡ 找 flag")
        self.btn_flag.setObjectName("Flag")
        self.btn_flag.setToolTip("在整机镜像字节里扫多编码 flag，并把案件内所有产物的命中汇总到「旗标」页")
        self.btn_flag.setEnabled(False)
        self.btn_flag.clicked.connect(self.on_find_flags)
        r2.addWidget(self.btn_flag)

        self.btn_loose = QCheckBox("宽松模式（连 `任意前缀{...}` 一起报）")
        self.btn_loose.setToolTip("默认关闭：实测真实镜像里 i18n{...}/mathit{...}/FileIdIndex-{GUID}\n"
                                  "这类模板噪声会把真正的命中淹掉")
        r2.addWidget(self.btn_loose)

        self.chk_prescan = QCheckBox("字节快扫")
        self.chk_prescan.setChecked(True)
        self.chk_prescan.setToolTip(
            "在跑 vol3 插件之前，先对整机镜像做一次多编码 flag 字节扫描——不依赖符号表，\n"
            "夺旗题常常在这一步就直接出答案（实测 2 GiB 约 3~12 分钟，取决于磁盘）。\n"
            "不急着要 flag、只想看系统信息时，可以取消勾选。")
        r2.addWidget(self.chk_prescan)

        self.btn_detect = QPushButton("↻ 重新检测")
        self.btn_detect.setEnabled(False)
        self.btn_detect.clicked.connect(self.on_redetect)
        r2.addWidget(self.btn_detect)

        self.btn_intel = QPushButton("🔍 情报扫描")
        self.btn_intel.setEnabled(False)
        self.btn_intel.setToolTip("IOC 提取 + 词典匹配，结果入库并单独成页")
        self.btn_intel.clicked.connect(self.on_intel_scan)
        r2.addWidget(self.btn_intel)

        self.btn_report = QPushButton("📄 生成报告")
        self.btn_report.setEnabled(False)
        self.btn_report.clicked.connect(self.on_report)
        r2.addWidget(self.btn_report)

        r2.addStretch(1)
        self.btn_env = QPushButton("🧪 符号/缓存环境")
        self.btn_env.setToolTip("查看 vol3 缓存与符号表落在哪里、是否已就绪（首次分析要下载一次）")
        self.btn_env.clicked.connect(self.on_symbol_env)
        r2.addWidget(self.btn_env)

        self.btn_engines = QPushButton("🔧 引擎自检")
        self.btn_engines.clicked.connect(self.on_engine_check)
        r2.addWidget(self.btn_engines)

        self.btn_about = QPushButton("?")
        self.btn_about.setFixedWidth(34)
        self.btn_about.clicked.connect(self.on_about)
        r2.addWidget(self.btn_about)
        outer.addLayout(r2)
        return box

    # ---------------------------------------------------------------- 左栏
    def _build_left_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.card_img = InfoCard("镜像 / 证据", [
            ("文件", "尚未载入"), ("大小", "—"), ("容器", "—"), ("系统", "—"), ("分析", "—"),
        ])
        layout.addWidget(self.card_img)

        self.card_env = InfoCard("分析环境（vol3）", [
            ("缓存", str(self.vol3env.cache_dir)), ("符号表", "未初始化"), ("状态", "—"),
        ])
        layout.addWidget(self.card_env)

        self.card_case = InfoCard("案件统计", [
            ("案件", "—"), ("产物", "0"), ("记录", "0"), ("发现项", "0"),
        ])
        layout.addWidget(self.card_case)

        box = QGroupBox("提醒")
        bl = QVBoxLayout(box)
        self.warn_view = QTextEdit()
        self.warn_view.setReadOnly(True)
        self.warn_view.setPlaceholderText("（无）")
        self.warn_view.setMaximumHeight(150)
        bl.addWidget(self.warn_view)
        layout.addWidget(box)
        layout.addStretch(1)

        self._refresh_env_card()
        return panel

    # ---------------------------------------------------------------- 右侧
    def _build_right_panel(self) -> QWidget:
        panel = QWidget()
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        # 结论条放在**标签页之外**：找到 flag 时无论在哪个页面都看得见
        # （放在「运行」页里的话，切到别的页就消失了）
        self.banner = QFrame()
        self.banner.setObjectName("Banner")
        bl = QHBoxLayout(self.banner)
        bl.setContentsMargins(12, 8, 12, 8)
        self.lbl_flag_icon = QLabel("🎯 旗标命中")
        self.lbl_flag_icon.setObjectName("CardTitle")
        self.lbl_flag_big = QLabel("—")
        self.lbl_flag_big.setObjectName("FlagBig")
        self.lbl_flag_big.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_flag_note = QLabel("")
        self.lbl_flag_note.setObjectName("Dim")
        self.btn_copy_flag = QPushButton("复制")
        self.btn_copy_flag.clicked.connect(self.on_copy_flag)
        bl.addWidget(self.lbl_flag_icon)
        bl.addWidget(self.lbl_flag_big, 1)
        bl.addWidget(self.lbl_flag_note)
        bl.addWidget(self.btn_copy_flag)
        self.banner.setVisible(False)
        outer.addWidget(self.banner)

        self.tabs = QTabWidget()

        # ---- ① 分析：插件选择 ----
        tab_pick = QWidget()
        pl = QVBoxLayout(tab_pick)
        row = QHBoxLayout()
        row.addWidget(QLabel("搜索插件："))
        self.plugin_search = QLineEdit()
        self.plugin_search.setPlaceholderText("如：进程 / malfind / registry（空格分隔为 AND）")
        self.plugin_search.textChanged.connect(self._filter_plugins)
        row.addWidget(self.plugin_search, 1)
        self.btn_all = QPushButton("全选")
        self.btn_all.clicked.connect(lambda: self._set_all_checked(True))
        self.btn_none = QPushButton("全不选")
        self.btn_none.clicked.connect(lambda: self._set_all_checked(False))
        row.addWidget(self.btn_all)
        row.addWidget(self.btn_none)
        pl.addLayout(row)

        self.plugin_tree = QTreeWidget()
        self.plugin_tree.setHeaderLabels(["插件", "引擎内名称"])
        self.plugin_tree.setColumnWidth(0, 360)
        self.plugin_tree.setAlternatingRowColors(True)
        pl.addWidget(self.plugin_tree, 1)
        self.tabs.addTab(tab_pick, "① 分析")

        # ---- ② 运行：本版重点 ----
        tab_run = QWidget()
        rl = QVBoxLayout(tab_run)
        rl.setSpacing(6)

        self.lbl_phase = QLabel("等待开始分析")
        self.lbl_phase.setObjectName("Phase")
        self.lbl_phase.setWordWrap(True)
        rl.addWidget(self.lbl_phase)

        self.run_bar = QProgressBar()
        rl.addWidget(self.run_bar)

        srow = QHBoxLayout()
        self.lbl_symbol = QLabel("符号表：未预检")
        self.lbl_symbol.setObjectName("Dim")
        self.lbl_symbol.setWordWrap(True)
        srow.addWidget(self.lbl_symbol, 1)
        self.btn_open_result = QPushButton("查看选中插件结果")
        self.btn_open_result.clicked.connect(self._open_selected_result)
        srow.addWidget(self.btn_open_result)
        rl.addLayout(srow)

        self.status_table = QTableWidget(0, 5)
        self.status_table.setHorizontalHeaderLabels(["插件", "状态", "行数", "耗时", "说明 / 失败原因"])
        self.status_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.status_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.status_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.status_table.setAlternatingRowColors(True)
        self.status_table.doubleClicked.connect(lambda _: self._open_selected_result())
        rl.addWidget(self.status_table, 1)
        self.tabs.addTab(tab_run, "② 运行")

        # ---- ③ 结果 ----
        self.store = DataStore(self.db_path)
        self.result_table = ResultTableWidget(self.store)
        self.result_table.status.connect(self.statusBar().showMessage)
        self.tabs.addTab(self.result_table, "③ 结果")

        # ---- ④ 发现项 ----
        tab_find = QWidget()
        fl = QVBoxLayout(tab_find)
        frow = QHBoxLayout()
        frow.addWidget(QLabel("严重度："))
        self.sev_filter = QComboBox()
        self.sev_filter.addItems(["全部", "critical", "high", "medium", "low", "info"])
        self.sev_filter.currentTextChanged.connect(lambda _: self.refresh_findings())
        frow.addWidget(self.sev_filter)
        frow.addStretch(1)
        self.btn_finding_detail = QPushButton("查看详情")
        self.btn_finding_detail.clicked.connect(self._show_finding_detail)
        frow.addWidget(self.btn_finding_detail)
        fl.addLayout(frow)

        self.finding_table = QTableWidget(0, 5)
        self.finding_table.setHorizontalHeaderLabels(["严重度", "置信度", "标题", "检测器", "证据源"])
        self.finding_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.finding_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.finding_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.finding_table.setAlternatingRowColors(True)
        self.finding_table.doubleClicked.connect(lambda _: self._show_finding_detail())
        fl.addWidget(self.finding_table, 1)
        self.tabs.addTab(tab_find, "④ 发现项")

        # ---- ⑤ 旗标 ----
        tab_flag = QWidget()
        ggl = QVBoxLayout(tab_flag)
        grow = QHBoxLayout()
        self.btn_flags_refresh = QPushButton("↻ 从现有产物重新汇总")
        self.btn_flags_refresh.clicked.connect(self.refresh_flags)
        self.btn_flags_copy = QPushButton("复制选中值")
        self.btn_flags_copy.clicked.connect(self._copy_selected_flag)
        self.btn_flags_export = QPushButton("导出 CSV")
        self.btn_flags_export.clicked.connect(self._export_flags)
        self.lbl_flags_count = QLabel("候选 0 条")
        self.lbl_flags_count.setObjectName("Dim")
        grow.addWidget(self.btn_flags_refresh)
        grow.addWidget(self.btn_flags_copy)
        grow.addWidget(self.btn_flags_export)
        grow.addStretch(1)
        grow.addWidget(self.lbl_flags_count)
        ggl.addLayout(grow)

        self.flag_table = QTableWidget(0, 6)
        self.flag_table.setHorizontalHeaderLabels(
            ["候选值", "类型", "来源插件", "出现次数", "镜像偏移", "上下文"])
        self.flag_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Interactive)
        self.flag_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.flag_table.setColumnWidth(0, 340)
        self.flag_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.flag_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.flag_table.setAlternatingRowColors(True)
        self.flag_table.doubleClicked.connect(lambda _: self._copy_selected_flag())
        ggl.addWidget(self.flag_table, 1)
        self.tabs.addTab(tab_flag, "⑤ 旗标")

        # ---- ⑥ 情报 ----
        tab_intel = QWidget()
        il = QVBoxLayout(tab_intel)
        irow = QHBoxLayout()
        self.btn_run_intel = QPushButton("▶ 扫描本案情报")
        self.btn_run_intel.clicked.connect(self.on_intel_scan)
        irow.addWidget(self.btn_run_intel)
        irow.addWidget(QLabel("来源筛选："))
        self.intel_source = QComboBox()
        self.intel_source.addItem("全部情报产物", "")
        irow.addWidget(self.intel_source)
        irow.addStretch(1)
        self.btn_intel_refresh = QPushButton("刷新")
        self.btn_intel_refresh.clicked.connect(self.refresh_intel)
        irow.addWidget(self.btn_intel_refresh)
        il.addLayout(irow)

        self.intel_table = QTableWidget(0, 6)
        self.intel_table.setHorizontalHeaderLabels(
            ["严重度", "类型", "值", "次数", "来源插件", "说明 / 建议"])
        self.intel_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.intel_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.intel_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.intel_table.setAlternatingRowColors(True)
        il.addWidget(self.intel_table, 1)

        self.intel_log = QTextEdit()
        self.intel_log.setReadOnly(True)
        self.intel_log.setMaximumHeight(110)
        il.addWidget(self.intel_log)
        self.tabs.addTab(tab_intel, "⑥ 情报")

        # ---- ⑦ 日志 ----
        tab_log = QWidget()
        ll = QVBoxLayout(tab_log)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        ll.addWidget(self.log_view)
        brow = QHBoxLayout()
        self.btn_log_clear = QPushButton("清空日志")
        self.btn_log_clear.clicked.connect(self.log_view.clear)
        brow.addStretch(1)
        brow.addWidget(self.btn_log_clear)
        ll.addLayout(brow)
        self.tabs.addTab(tab_log, "⑦ 日志")

        outer.addWidget(self.tabs, 1)
        return panel

    # ================================================================ 启动
    def _engine_name(self) -> str:
        return list(self._engine_labels.keys())[self.engine_box.currentIndex()]

    def _on_engine_changed(self) -> None:
        """切引擎 = 重载插件树 + 换预设集 + 按新语境重算提醒。"""
        name = self._engine_name()
        if self.probe_result is not None:
            refresh_warnings(self.probe_result, name)
            self._render_warnings()
        engine = registry.get(name)
        ok, why = engine.available()
        if not ok:
            self.log(f"⚠ {engine.display} 引擎不可用：{why}")
            self.plugins = []
            self._populate_plugins()
            self.btn_analyze.setEnabled(False)
            return
        try:
            self.plugins = engine.list_plugins()
        except Exception as exc:
            self.log(f"⚠ 枚举插件失败：{exc}")
            return
        self.log(f"[{engine.display}] 已枚举 {len(self.plugins)} 个插件")
        self.preset_box.blockSignals(True)
        self.preset_box.clear()
        self.preset_box.addItems([k for k, v in PRESETS.items() if self._preset_engine(k) == name])
        self.preset_box.blockSignals(False)
        self._populate_plugins()
        if self.preset_box.count():
            self._apply_preset(self.preset_box.currentText())
        if self.probe_result is not None:
            self.btn_analyze.setEnabled(self._can_analyze_current())

    @staticmethod
    def _preset_engine(preset_name: str) -> str:
        """
        判断某个预设属于哪个引擎（按内容判断，不按键名前缀——
        键名随时会改，内容才是事实）。
        """
        plugins = PRESETS.get(preset_name) or []
        if plugins and all(str(p).startswith("static.") for p in plugins):
            return "static"
        if plugins and all(str(p).startswith("memstrings.") for p in plugins):
            return "memstrings"
        if plugins and all(str(p).startswith("mprocfs.") for p in plugins):
            return "memprocfs"
        return "vol3"

    def _bootstrap(self) -> None:
        self.log(f"MemLens v{VERSION} 启动，工作目录：{self.workdir}")
        avail: dict[str, bool] = {}
        for engine, ok, why in registry.iter_available():
            name = engine.display if engine else "(构造失败)"
            if engine is not None:
                avail[engine.name] = bool(ok)
            self.log(("✅ " if ok else "❌ ") + f"{name}：{why}")
        # 引擎默认选择：MemProcFS 可用就用它（产物最全、最快出结果），否则回退 vol3
        if avail.get("memprocfs"):
            self.engine_box.setCurrentIndex(list(self._engine_labels).index("memprocfs"))
        elif avail.get("vol3"):
            self.engine_box.setCurrentIndex(list(self._engine_labels).index("vol3"))
        for name in self._engine_labels:
            eng = registry.get(name)
            ok, why = eng.available()
            if ok:
                continue
            if name == "memprocfs":
                self.warn("MemProcFS 引擎不可用，已回退到 Volatility 3。\n"
                          f"原因：{why}\n\n"
                          "MemProcFS 能一次拿到进程/网络/注册表/事件日志/时间线（快得多），"
                          "建议把 MemProcFS 放到：\n"
                          "    <MemLens>\\tools\\MemProcFS\\memprocfs.exe")
            elif name == "vol3":
                self.warn("Volatility 3 引擎不可用，内存镜像分析将无法使用。\n"
                          f"原因：{why}\n\n修复：在 MemLens 的虚拟环境里执行\n"
                          "    python -m pip install volatility3")
        self._on_engine_changed()
        self._refresh_env_card()
        self.btn_analyze.setEnabled(False)
        self.log("提示：内存镜像首次分析需要下载内核符号表（约 10 MB，1-3 分钟），"
                 "之后同一镜像只需几秒；点「🧪 符号/缓存环境」可查看状态。")

    def _can_analyze_current(self) -> bool:
        if self.probe_result is None:
            return False
        ok, _why = can_analyze(self.probe_result, self._engine_name())
        return ok

    # ================================================================ 插件面板
    def _populate_plugins(self) -> None:
        self.plugin_tree.clear()
        by_cat: dict[str, list[PluginMeta]] = {}
        for p in self.plugins:
            by_cat.setdefault(p.category, []).append(p)
        order = CATEGORY_ORDER
        cats = sorted(by_cat.keys(), key=lambda c: (order.index(c) if c in order else 99, c))
        self._plugin_items: dict[str, QTreeWidgetItem] = {}
        for cat in cats:
            top = QTreeWidgetItem([f"{cat}（{len(by_cat[cat])}）", ""])
            top.setFlags(top.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsAutoTristate)
            top.setCheckState(0, Qt.Unchecked)
            top.setExpanded(True)
            for p in by_cat[cat]:
                child = QTreeWidgetItem([p.display, p.name])
                child.setFlags(child.flags() | Qt.ItemIsUserCheckable)
                child.setCheckState(0, Qt.Unchecked)
                child.setData(0, Qt.UserRole, p.name)
                if p.description:
                    child.setToolTip(0, p.description)
                    child.setToolTip(1, p.description)
                top.addChild(child)
                self._plugin_items[p.name] = child
            self.plugin_tree.addTopLevelItem(top)

    def _filter_plugins(self, text: str) -> None:
        terms = [t.lower() for t in text.split() if t.strip()]
        for i in range(self.plugin_tree.topLevelItemCount()):
            top = self.plugin_tree.topLevelItem(i)
            visible_children = 0
            for j in range(top.childCount()):
                child = top.child(j)
                hay = f"{child.text(0)} {child.text(1)}".lower()
                match = all(t in hay for t in terms) if terms else True
                child.setHidden(not match)
                visible_children += int(match)
            top.setHidden(visible_children == 0)

    def _set_all_checked(self, checked: bool) -> None:
        state = Qt.Checked if checked else Qt.Unchecked
        for i in range(self.plugin_tree.topLevelItemCount()):
            top = self.plugin_tree.topLevelItem(i)
            if top.isHidden():
                continue
            for j in range(top.childCount()):
                child = top.child(j)
                if not child.isHidden():
                    child.setCheckState(0, state)

    def _apply_preset(self, preset_name: str) -> None:
        names = set(PRESETS.get(preset_name, []))
        if not names:
            return
        for i in range(self.plugin_tree.topLevelItemCount()):
            top = self.plugin_tree.topLevelItem(i)
            for j in range(top.childCount()):
                child = top.child(j)
                full = child.data(0, Qt.UserRole) or ""
                parts = full.split(".")
                short = ".".join(parts[:-1]) if (len(parts) >= 2 and parts[-1][:1].isupper()) else full
                child.setCheckState(0, Qt.Checked if (full in names or short in names) else Qt.Unchecked)

    def selected_plugins(self) -> list[PluginMeta]:
        chosen: list[str] = []
        for i in range(self.plugin_tree.topLevelItemCount()):
            top = self.plugin_tree.topLevelItem(i)
            for j in range(top.childCount()):
                child = top.child(j)
                if child.checkState(0) == Qt.Checked:
                    chosen.append(child.data(0, Qt.UserRole))
        index = {p.name: p for p in self.plugins}
        return [index[n] for n in chosen if n in index]

    # ================================================================ 证据载入
    def on_open_image(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择内存镜像 / 证据文件", "",
            "内存镜像 (*.raw *.mem *.dmp *.vmem *.vmsn *.sav *.bin *.dd *.dump *.lime *.core *.vol);;"
            "所有文件 (*.*)",
        )
        if path:
            self.load_image(path)

    def load_image(self, path: str) -> None:
        self.image_path = path
        self.card_img.set_value(0, "文件", Path(path).name)
        self.card_img.set_value(1, "大小", "探测中…")
        self.card_img.set_value(2, "容器", "…")
        self.card_img.set_value(3, "系统", "…")
        self.card_img.set_value(4, "分析", "…")
        self.log(f"载入镜像：{path}")
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.btn_analyze.setEnabled(False)
        self.btn_flag.setEnabled(False)

        self.probe_worker = ProbeWorker(path, deep=True)
        self.probe_worker.done.connect(self._on_probe_done)
        self.probe_worker.failed.connect(self._on_probe_failed)
        self.probe_worker.start()

    def _on_probe_done(self, result) -> None:
        self.probe_result = result
        self.progress.setVisible(False)
        try:
            size_mb = os.path.getsize(self.image_path) / (1 << 20)
            size_text = f"{size_mb:,.1f} MiB"
        except OSError:
            size_text = "—"
        self.card_img.set_value(0, "文件", Path(self.image_path or "").name)
        self.card_img.set_value(1, "大小", size_text)
        self.card_img.set_value(2, "容器", str(result.container.value),
                                theme.WARN if result.container.value in ("other", "memfrag")
                                else theme.OK)
        self.card_img.set_value(3, "系统",
                                f"{result.os_type.value}（置信度 {result.os_confidence:.0%}）",
                                theme.OK if result.os_type.value in ("windows", "linux", "macos")
                                else theme.WARN)
        self.log("探测结果：" + result.summary())
        for ev in result.evidence:
            self.log("  · " + str(ev))

        if result.container in (ContainerFormat.EXECUTABLE, ContainerFormat.ELF_BIN,
                                ContainerFormat.OTHER):
            idx = list(self._engine_labels.keys()).index("static")
            self.engine_box.blockSignals(True)
            self.engine_box.setCurrentIndex(idx)
            self.engine_box.blockSignals(False)
            refresh_warnings(result, "static")
            self._on_engine_changed()
            self._render_warnings()
            self.status_phase.setText("这是样本文件，已自动切到「静态样本」引擎")
        else:
            self._render_warnings()
            ok, why = can_analyze(result, self._engine_name())
            self.card_img.set_value(4, "分析", "可以分析" if ok else f"需先处理：{why}",
                                    theme.OK if ok else theme.DANGER)
            self.btn_analyze.setEnabled(self._can_analyze_current())
            self.btn_flag.setEnabled(True)
            self.status_phase.setText(f"探测完成：{result.container.value} / {result.os_type.value}")
            self.tabs.setCurrentIndex(0)

    def _render_warnings(self) -> None:
        if self.probe_result is None:
            self.warn_view.clear()
            return
        ws = list(self.probe_result.warnings)
        self.warn_view.setPlainText("\n".join(f"! {w}" for w in ws) or "（无）")

    def _on_probe_failed(self, message: str) -> None:
        self.progress.setVisible(False)
        self.log("✘ 探测失败：" + message)
        QMessageBox.critical(self, "探测失败", message)

    # ================================================================ 分析
    def on_analyze(self) -> None:
        if not self.image_path:
            return
        plugins = self.selected_plugins()
        if not plugins:
            QMessageBox.information(self, "提示", "请先勾选要执行的插件（顶部「预设」可一键选择）")
            return

        engine_name = self._engine_name()
        self.tabs.setCurrentIndex(1)          # 切到「运行」
        self._reset_run_view(plugins)
        self.log("=" * 74)
        self.log(f"开始分析：{len(plugins)} 个插件；引擎={engine_name}；"
                 f"字节快扫={'开' if engine_name == 'vol3' else '关'}")
        self.btn_analyze.setEnabled(False)
        self.btn_flag.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self._phase_started = time.time()
        self._timer.start()

        self.analyze_worker = AnalyzeWorker(
            image_path=self.image_path,
            plugins=plugins,
            db_path=self.db_path,
            workdir=self.workdir,
            case_name=Path(self.image_path).stem,
            engine_name=engine_name,
            renderer="jsonl",
            timeout=1800.0,
            cache=True,
            loose_flags=self.btn_loose.isChecked(),
            pre_scan=self.chk_prescan.isChecked(),
        )
        self.analyze_worker.event.connect(self._on_analyze_event)
        self.analyze_worker.failed.connect(self._on_analyze_failed)
        self.analyze_worker.finished.connect(self._on_analyze_finished)
        self.analyze_worker.start()

    def on_find_flags(self) -> None:
        """一键找 flag：字节扫 + 汇总（复用当前案件，不重跑历史插件）。"""
        if not self.image_path:
            return
        engine = registry.get("memstrings")
        pool = {p.name: p for p in engine.list_plugins()}
        plugins = [pool[n] for n in ("memstrings.flag", "memstrings.ioc") if n in pool]
        if not plugins:
            return
        case_id = self.case_id
        if case_id is None:
            self.log("⚡ 找 flag：还没有案件，将先建立案件（只跑字节扫描，不跑 vol3 插件）")
        self.tabs.setCurrentIndex(1)
        self._reset_run_view(plugins)
        self.btn_analyze.setEnabled(False)
        self.btn_flag.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self._phase_started = time.time()
        self._timer.start()
        self.analyze_worker = AnalyzeWorker(
            image_path=self.image_path,
            plugins=[],
            db_path=self.db_path,
            workdir=self.workdir,
            case_name=Path(self.image_path).stem,
            engine_name="memstrings",
            timeout=1800.0,
            case_id=case_id,
            pre_scan=True,
            warmup=False,
            loose_flags=self.btn_loose.isChecked(),
        )
        self.analyze_worker.event.connect(self._on_analyze_event)
        self.analyze_worker.failed.connect(self._on_analyze_failed)
        self.analyze_worker.finished.connect(self._on_analyze_finished)
        self.analyze_worker.start()

    def on_stop(self) -> None:
        if self.analyze_worker and self.analyze_worker.isRunning():
            self.analyze_worker.cancel()
            self.log("已请求停止：当前任务会被终止，后续插件不再执行")
            self.status_phase.setText("正在停止…")

    def _reset_run_view(self, plugins: list[PluginMeta]) -> None:
        self.status_table.setRowCount(0)
        self._status_rows.clear()
        for p in plugins:
            self._status_row(p.name, p.display, "queued")
        self.run_bar.setRange(0, max(len(plugins), 1))
        self.run_bar.setValue(0)
        self.phase_bar.setVisible(False)
        self.lbl_phase.setText("准备中…")
        self.status_phase.setText("准备中…")

    def _status_row(self, plugin: str, display: str = "", status: str = "queued") -> int:
        """取/建插件状态行（字节快扫会追加不在勾选列表里的插件行）。"""
        if plugin in self._status_rows:
            return self._status_rows[plugin]
        r = self.status_table.rowCount()
        self.status_table.insertRow(r)
        item = QTableWidgetItem(display or plugin)
        item.setToolTip(plugin)
        self.status_table.setItem(r, 0, item)
        for col in range(1, 5):
            self.status_table.setItem(r, col, QTableWidgetItem(""))
        self._set_status(r, status)
        self._status_rows[plugin] = r
        self.status_table.resizeColumnsToContents()
        self.status_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        return r

    def _set_status(self, row: int, status: str, rows: int = 0, ms: int = 0,
                    note: str = "") -> None:
        color = QColor(theme.STATUS_COLORS.get(status, theme.TEXT))
        st = QTableWidgetItem(theme.STATUS_TEXT.get(status, status))
        st.setForeground(color)
        self.status_table.setItem(row, 1, st)
        n = QTableWidgetItem(f"{rows:,}" if rows else "—")
        n.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.status_table.setItem(row, 2, n)
        t = QTableWidgetItem(f"{ms/1000:.1f}s" if ms else "—")
        t.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.status_table.setItem(row, 3, t)
        note_item = QTableWidgetItem(note)
        if note:
            note_item.setToolTip(note)
            note_item.setForeground(QColor(theme.DANGER if status == "failed" else theme.WARN))
        self.status_table.setItem(row, 4, note_item)

    def _open_selected_result(self) -> None:
        items = {i.row() for i in self.status_table.selectedIndexes()}
        if not items:
            QMessageBox.information(self, "提示", "请在状态表里先选中一个插件")
            return
        row = sorted(items)[0]
        plugin = self.status_table.item(row, 0).toolTip() or self.status_table.item(row, 0).text()
        arts = [a for a in self.store.list_artifacts(self.case_id or "")
                if a["plugin"] == plugin] if self.case_id else []
        if not arts:
            QMessageBox.information(self, "提示", f"插件 {plugin} 还没有已入库的结果")
            return
        a = arts[-1]
        self.result_table.show_artifact(a["artifact_id"], f"{plugin}")
        self.tabs.setCurrentIndex(2)

    def on_redetect(self) -> None:
        if not self.case_id:
            QMessageBox.information(self, "提示", "还没有案件")
            return
        self.log("重新运行检测器…")
        self.detect_worker = DetectWorker(self.db_path, self.case_id)
        self.detect_worker.done.connect(lambda f, n: (
            self.log(f"检测完成：{len(f)} 条发现项"),
            [self.log("· " + x) for x in n],
            self.refresh_findings(),
        ))
        self.detect_worker.failed.connect(lambda m: QMessageBox.critical(self, "检测失败", m))
        self.detect_worker.start()

    def on_engine_check(self) -> None:
        lines = []
        for engine, ok, why in registry.iter_available():
            name = engine.display if engine else "(构造失败)"
            lines.append(("✅ " if ok else "❌ ") + f"{name}：{why}")
        QMessageBox.information(self, "引擎自检", "\n".join(lines) or "（无可用引擎）")
        self.log("引擎自检：" + " | ".join(lines))

    def on_symbol_env(self) -> None:
        """符号/缓存环境：把"首次为什么要等三分钟"讲清楚。"""
        from memlens.engines.vol3 import Volatility3Adapter

        env = self.vol3env.ensure()
        st = env.status()
        engine = registry.get("vol3")
        text = [
            f"工作目录：{self.workdir}",
            f"符号缓存目录：{env.cache_dir}",
            f"符号表目录：{env.symbols_dir}",
            "",
            f"本地 ISF 索引：{st.indexed_local} 项",
            f"在线符号清单：{st.indexed_remote} 项",
            f"已下载内核符号表：{st.isf_files} 个" + ("" if st.isf_files else "（首次分析要下载一次）"),
            f"PDB 原始缓存：{st.pdb_cache_mb:.1f} MB",
            "",
            "说明：Windows 内核符号表（ISF）由 vol3 按镜像里的 PDB GUID 自动获取——",
            "先下载 ntkrnlmp.pdb（约 10 MB），再转成 ISF（总计 1-3 分钟，只做一次）。",
            "MemLens 把这两样都放在工作目录下，所以：",
            "  · exe 装在 Program Files / 只读盘也能正常工作；",
            "  · 拷贝整个 work 目录到别的机器可离线复用，无需再下载。",
        ]
        if st.isf_files == 0:
            text += ["", "⚠ 还没拿到内核符号表：第一次分析务必保持联网，并耐心等这 1-3 分钟。"]
        if isinstance(engine, Volatility3Adapter):
            text += ["", f"vol3 命令前缀：{' '.join(engine._command_prefix())}"]
        QMessageBox.information(self, "符号 / 缓存环境", "\n".join(text))
        self.log("符号环境：" + st.summary())
        self._refresh_env_card()

    def on_about(self) -> None:
        QMessageBox.about(
            self, "关于 MemLens",
            f"<b>MemLens</b> v{VERSION} —— 内存取证工作台<br><br>"
            "独立实现的取证编排与分析工具：<br>"
            "· 镜像容器探测（raw/LiME/崩溃转储/VMware…）<br>"
            "· 三段式分析：字节快扫 → 符号预检 → 插件执行<br>"
            "· Volatility 3 引擎适配（插件运行时枚举、缓存/符号固定在工位目录）<br>"
            "· 统一证据模型（SQLite：案件/产物/记录/发现项）<br>"
            "· 检测器 + 旗标聚合台（跨产物找 flag）<br><br>"
            f"工作目录：{self.workdir}",
        )

    # ================================================================ 事件回填
    def _on_analyze_event(self, kind: str, payload: dict) -> None:  # noqa: C901
        if kind == "stage":
            text = payload.get("text", "")
            self.status_phase.setText(text)
            self.lbl_phase.setText(text)
            self.log("» " + text)
        elif kind == "phase":
            label = payload.get("label") or payload.get("phase", "")
            text = payload.get("text", "")
            pct = payload.get("percent")
            secs = (payload.get("elapsed_ms") or 0) / 1000
            self.lbl_phase.setText(f"{payload.get('plugin', '')} · {label}：{text}"
                                   + (f"（{secs:.0f}s）" if secs else ""))
            self.status_phase.setText(f"{label}：{text}")
            if pct is not None:
                self.phase_bar.setVisible(True)
                self.phase_bar.setRange(0, 100)
                self.phase_bar.setValue(int(pct))
        elif kind == "progress":
            pct = payload.get("percent")
            if pct is not None:
                self.phase_bar.setVisible(True)
                self.phase_bar.setRange(0, 100)
                self.phase_bar.setValue(int(pct))
            done = payload.get("done") or 0
            total = payload.get("total") or 0
            if total:
                self.lbl_phase.setText(
                    f"字节扫描 {payload.get('plugin', '')}：{done/(1<<20):.0f}/"
                    f"{total/(1<<20):.0f} MiB（{done/total:.0%}）")
        elif kind == "line":
            line = payload.get("line", "").rstrip()
            if line:
                self.log(f"  [{payload.get('plugin', '')}] {line}")
        elif kind == "symbol":
            ok = payload.get("ok")
            self.lbl_symbol.setText("符号表：" + str(payload.get("summary") or ""))
            self.lbl_symbol.setStyleSheet(
                f"color:{theme.OK if ok else theme.WARN};")
            if ok:
                self.log("✅ 符号预检：" + str(payload.get("summary")))
            else:
                self.warn("符号预检未通过：" + str(payload.get("error") or ""))
                if payload.get("advise"):
                    self.log("   建议：" + str(payload["advise"]).replace("\n", "\n   "))
                for ln in payload.get("key_lines") or []:
                    self.log("   · " + str(ln))
            self._refresh_env_card()
        elif kind == "case":
            self.case_id = payload["case_id"]
            self.lbl_case.setText(f"案件：{self.case_id}")
            self.btn_detect.setEnabled(True)
            self.btn_intel.setEnabled(True)
            self.btn_report.setEnabled(True)
            self.log(f"案件已建立：{self.case_id}")
        elif kind == "probe":
            for w in payload.get("warnings") or []:
                self.log("  ⚠ " + str(w))
        elif kind == "result":
            self._on_plugin_result(payload)
        elif kind == "flags":
            self._render_flags(payload.get("items") or [])
            best = payload.get("best")
            if best:
                self._show_flag_banner(best["value"], best.get("sources") or [])
                self.log(f"🎯 旗标命中：{best['value']}（来源：{', '.join(best.get('sources') or [])}）")
            else:
                self.log(f"旗标汇总：{len(payload.get('items') or [])} 条候选，未发现明文 flag")
        elif kind == "done":
            self._on_analyze_done(payload)

    def _on_plugin_result(self, payload: dict) -> None:
        plugin = payload.get("plugin", "")
        row = self._status_row(plugin, payload.get("display") or plugin)
        status = payload.get("status", "ok")
        self._set_status(row, status, int(payload.get("rows") or 0),
                         int(payload.get("duration_ms") or 0),
                         payload.get("reason") or payload.get("error") or "")
        mark = theme.STATUS_TEXT.get(status, status)
        self.log(f"{mark} {payload.get('display')}：{status}，{payload.get('rows')} 行，"
                 f"{payload.get('duration_ms')}ms"
                 + (f"，原因：{payload.get('reason')}" if payload.get("reason") else ""))
        if payload.get("advise"):
            self.log("   建议：" + str(payload["advise"]).replace("\n", "\n   "))
        done = self.run_bar.value() + 1
        self.run_bar.setValue(min(done, self.run_bar.maximum()))
        if payload.get("rows"):
            self.result_table.show_artifact(payload["artifact_id"], payload.get("display") or plugin)

    def _on_analyze_done(self, payload: dict) -> None:
        stats = payload.get("stats", {})
        self.card_case.set_value(0, "案件", str(payload.get("case_id") or "—"))
        self.card_case.set_value(1, "产物", str(stats.get("artifacts", 0)))
        self.card_case.set_value(2, "记录", f"{stats.get('records', 0):,}")
        self.card_case.set_value(3, "发现项", str(stats.get("findings", 0)))
        self.refresh_findings()
        self.refresh_flags()
        self._load_case_results()
        self.log("=" * 74)
        self.log(f"分析完成：{stats}")
        self.lbl_phase.setText(f"分析完成：{stats.get('records', 0):,} 条记录 / "
                               f"{stats.get('findings', 0)} 条发现项")
        self._timer.stop()
        # 落地页顺序：旗标 > 发现项 > 结果表 > 运行状态。
        # 早期版本在"没有旗标也没有发现项"时会停在「运行」页，用户眼前只有一屏程序日志，
        # 于是得出"这工具只会输出日志"的结论 —— 这正是要修掉的体验 bug。
        flags = self.flag_table.rowCount()
        has_rows = self.result_table.artifact_combo.count() > 0
        if flags:
            self.tabs.setCurrentIndex(4)
        elif stats.get("findings"):
            self.tabs.setCurrentIndex(3)
        elif has_rows:
            self.tabs.setCurrentIndex(2)
        else:
            self.tabs.setCurrentIndex(1)

    def _load_case_results(self) -> None:
        """把本案件所有"有数据的产物"灌进结果页的产物下拉框，并默认选中进程表。"""
        if not self.case_id:
            return
        try:
            arts = self.store.list_artifacts(self.case_id)
        except Exception as exc:      # 数据库异常不该连带把界面搞崩
            self.log(f"⚠ 读取产物清单失败：{exc}")
            return
        before = self.result_table.artifact_combo.count()
        self.result_table.load_case_artifacts(arts)
        after = self.result_table.artifact_combo.count()
        if after:
            self.log(f"结果页已就绪：{after} 个产物可选（本次新增 {max(0, after - before)}）")

    def _on_analyze_failed(self, message: str) -> None:
        self.log("✘ 分析失败：" + message)
        self.lbl_phase.setText("分析失败：" + message.splitlines()[0])
        QMessageBox.critical(self, "分析失败", message[:2000])
        self._timer.stop()
        self.progress.setVisible(False)
        self.btn_analyze.setEnabled(True)
        self.btn_flag.setEnabled(bool(self.image_path))

    def _on_analyze_finished(self) -> None:
        self.progress.setVisible(False)
        self.phase_bar.setVisible(False)
        self.btn_analyze.setEnabled(bool(self.image_path))
        self.btn_flag.setEnabled(bool(self.image_path))
        self.btn_stop.setEnabled(False)
        self._timer.stop()
        self.status_elapsed.setText("")

    def _tick(self) -> None:
        if self._phase_started:
            el = int(time.time() - self._phase_started)
            self.status_elapsed.setText(f"已用 {el // 60:02d}:{el % 60:02d}")

    # ================================================================ 旗标
    def _show_flag_banner(self, value: str, sources: list[str]) -> None:
        self._last_flag = value
        self.lbl_flag_big.setText(value)
        self.lbl_flag_note.setText("来源：" + ", ".join(sources[:3]) if sources else "")
        self.banner.setVisible(True)

    def _render_flags(self, items: list[dict]) -> None:
        self.flag_table.setRowCount(0)
        for it in items:
            r = self.flag_table.rowCount()
            self.flag_table.insertRow(r)
            v = QTableWidgetItem(str(it.get("value", "")))
            if it.get("kind") == "明文":
                v.setForeground(QColor(theme.OK))
                f = v.font()
                f.setBold(True)
                v.setFont(f)
            self.flag_table.setItem(r, 0, v)
            self.flag_table.setItem(r, 1, QTableWidgetItem(str(it.get("kind", ""))))
            self.flag_table.setItem(r, 2, QTableWidgetItem(", ".join(it.get("sources") or [])))
            c = QTableWidgetItem(str(it.get("count", 1)))
            c.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.flag_table.setItem(r, 3, c)
            self.flag_table.setItem(r, 4, QTableWidgetItem(str(it.get("offset_hex") or "")))
            ctx = str(it.get("ctx") or "")[:200]
            ci = QTableWidgetItem(ctx)
            if ctx:
                ci.setToolTip(ctx)
            self.flag_table.setItem(r, 5, ci)
        self.lbl_flags_count.setText(f"候选 {len(items)} 条")
        self.flag_table.resizeColumnsToContents()
        self.flag_table.setColumnWidth(0, min(max(self.flag_table.columnWidth(0), 260), 460))
        self.flag_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)

    def refresh_flags(self) -> None:
        if not self.case_id:
            return
        try:
            items = flagbank.collect(self.store, self.case_id, limit=300,
                                     include_loose=self.btn_loose.isChecked())
        except Exception as exc:
            self.log(f"旗标汇总失败：{exc}")
            return
        self._render_flags(items)
        best = next((i for i in items if i["kind"] == "明文"), None)
        if best:
            self._show_flag_banner(best["value"], best.get("sources") or [])
        self.log(f"旗标已刷新：{len(items)} 条候选")

    def on_copy_flag(self) -> None:
        if self._last_flag:
            QApplication.clipboard().setText(self._last_flag)
            self.statusBar().showMessage(f"已复制：{self._last_flag}", 4000)

    def _copy_selected_flag(self) -> None:
        rows = {i.row() for i in self.flag_table.selectedIndexes()}
        if not rows:
            return
        item = self.flag_table.item(sorted(rows)[0], 0)
        if item:
            QApplication.clipboard().setText(item.text())
            self.statusBar().showMessage(f"已复制：{item.text()}", 4000)

    def _export_flags(self) -> None:
        if not self.flag_table.rowCount():
            QMessageBox.information(self, "提示", "还没有旗标候选")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出旗标候选", "flags.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        import csv
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(["候选值", "类型", "来源插件", "出现次数", "镜像偏移", "上下文"])
                for r in range(self.flag_table.rowCount()):
                    w.writerow([self.flag_table.item(r, c).text() if self.flag_table.item(r, c) else ""
                                for c in range(6)])
            self.statusBar().showMessage(f"已导出 {self.flag_table.rowCount()} 条 → {path}", 5000)
        except Exception as exc:
            QMessageBox.critical(self, "导出失败", str(exc))

    # ================================================================ 发现项
    def refresh_findings(self) -> None:
        if not self.case_id:
            return
        sev = self.sev_filter.currentText()
        findings = self.store.list_findings(
            self.case_id, severity=None if sev == "全部" else sev
        )
        self.finding_table.setRowCount(0)
        for f in findings:
            r = self.finding_table.rowCount()
            self.finding_table.insertRow(r)
            sev_item = QTableWidgetItem(f["severity"].upper())
            sev_item.setForeground(QColor(theme.SEVERITY_COLORS.get(f["severity"], theme.TEXT)))
            self.finding_table.setItem(r, 0, sev_item)
            self.finding_table.setItem(r, 1, QTableWidgetItem(f"{f['confidence']:.0%}"))
            self.finding_table.setItem(r, 2, QTableWidgetItem(f["title"]))
            self.finding_table.setItem(r, 3, QTableWidgetItem(f["detector"]))
            self.finding_table.setItem(r, 4, QTableWidgetItem(", ".join(f["sources"])))
            self.finding_table.item(r, 0).setData(Qt.UserRole, f)
        self.finding_table.resizeColumnsToContents()
        self.finding_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.log(f"发现项已刷新：{len(findings)} 条")

    def _show_finding_detail(self) -> None:
        rows = {i.row() for i in self.finding_table.selectedIndexes()}
        if not rows:
            QMessageBox.information(self, "提示", "请先选中一条发现项")
            return
        item = self.finding_table.item(sorted(rows)[0], 0)
        f = item.data(Qt.UserRole) if item else None
        if not f:
            return
        import json
        text = (
            f"【{f['severity'].upper()}】置信度 {f['confidence']:.0%}\n"
            f"{f['title']}\n\n"
            f"检测器：{f['detector']}\n证据源：{', '.join(f['sources'])}\n\n"
            f"{f.get('description') or ''}\n\n"
            "证据：\n" + json.dumps(f.get("evidence") or {}, ensure_ascii=False, indent=2)
        )
        dlg = QMessageBox(self)
        dlg.setWindowTitle("发现项详情")
        dlg.setText(text[:6000])
        dlg.exec()

    # ================================================================ 小工具
    def log(self, text: str) -> None:
        self.log_view.append(text)
        self.log_view.ensureCursorVisible()

    def warn(self, text: str) -> None:
        self.log("⚠ " + text)
        self.warn_view.setPlainText(text)

    def _refresh_env_card(self) -> None:
        try:
            st = self.vol3env.status()
        except Exception:
            return
        self.card_env.set_value(0, "缓存", str(self.vol3env.cache_dir))
        self.card_env.set_value(1, "符号表",
                                f"{st.isf_files} 个已下载" if st.isf_files else "未下载（首次需联网）",
                                theme.OK if st.isf_files else theme.WARN)
        self.card_env.set_value(2, "状态",
                                f"ISF 索引 {st.indexed_local} / 在线 {st.indexed_remote}"
                                + (f"；PDB 缓存 {st.pdb_cache_mb:.0f}MB" if st.pdb_cache_mb else ""))

    # ============================================================ 情报 / 报告
    def on_intel_scan(self) -> None:
        if not self.case_id:
            QMessageBox.information(self, "提示", "请先打开证据并完成一次分析，"
                                                  "情报扫描需要已有的插件产物作为输入。")
            return
        from memlens.intel.scan import scan_case

        self.btn_run_intel.setEnabled(False)
        self.btn_intel.setEnabled(False)
        self.intel_log.setPlainText("情报扫描中…（条目多时需要一些时间）")
        self.statusBar().showMessage("情报扫描中…")
        case_id = self.case_id

        def work() -> dict:
            return scan_case(self.store, case_id).__dict__

        def done() -> None:
            self.btn_run_intel.setEnabled(True)
            self.btn_intel.setEnabled(True)
            self.statusBar().showMessage("情报扫描完成")
            self.refresh_intel()

        run_in_thread(self, work, done, "情报扫描出错")

    def refresh_intel(self) -> None:
        if not self.case_id:
            return
        arts = [a for a in self.store.list_artifacts(self.case_id)
                if a["engine"] == "intel"]
        current = self.intel_source.currentData()
        self.intel_source.blockSignals(True)
        self.intel_source.clear()
        self.intel_source.addItem("全部情报产物", "")
        for a in arts:
            self.intel_source.addItem(a["plugin"], a["artifact_id"])
        idx = self.intel_source.findData(current)
        self.intel_source.setCurrentIndex(max(idx, 0))
        self.intel_source.blockSignals(False)

        wanted = self.intel_source.currentData()
        rows: list[dict] = []
        for a in arts:
            if wanted and a["artifact_id"] != wanted:
                continue
            rows.extend(self.store.records_of_plugin(self.case_id, a["plugin"], limit=2000))

        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        rows.sort(key=lambda r: (sev_rank.get(str(r.get("severity", "info")), 5),
                                 -int(r.get("count") or 1)))

        self.intel_table.setRowCount(0)
        for rec in rows:
            r = self.intel_table.rowCount()
            self.intel_table.insertRow(r)
            sev = str(rec.get("severity", "info"))
            s_item = QTableWidgetItem(sev.upper())
            s_item.setForeground(QColor(theme.SEVERITY_COLORS.get(sev, theme.TEXT)))
            self.intel_table.setItem(r, 0, s_item)
            kind = str(rec.get("ioc_type") or rec.get("dict") or "")
            if rec.get("scope"):
                kind += f"（{rec['scope']}）"
            self.intel_table.setItem(r, 1, QTableWidgetItem(kind))
            self.intel_table.setItem(r, 2, QTableWidgetItem(str(rec.get("value")
                                                                 or rec.get("match") or "")[:300]))
            self.intel_table.setItem(r, 3, QTableWidgetItem(str(rec.get("count", 1))))
            self.intel_table.setItem(r, 4, QTableWidgetItem(str(rec.get("sources", ""))[:200]))
            note = rec.get("advice") or rec.get("note") or ""
            self.intel_table.setItem(r, 5, QTableWidgetItem(str(note)[:300]))
        self.intel_table.resizeColumnsToContents()
        self.intel_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.log(f"情报已刷新：{len(rows)} 条")

    def on_report(self) -> None:
        if not self.case_id:
            QMessageBox.information(self, "提示", "请先建立案件。")
            return
        from memlens import report as rp

        choice_box = QMessageBox(self)
        choice_box.setWindowTitle("生成报告")
        choice_box.setText(f"为案件 {self.case_id} 生成报告：")
        choice_box.setStandardButtons(QMessageBox.Cancel)
        html_btn = choice_box.addButton("HTML（可直接打印/截图）", QMessageBox.ActionRole)
        md_btn = choice_box.addButton("Markdown（便于贴工单）", QMessageBox.ActionRole)
        choice_box.exec()
        btn = choice_box.clickedButton()
        if btn is html_btn:
            fmt = "html"
        elif btn is md_btn:
            fmt = "md"
        else:
            return
        out = self.workdir / f"report_{self.case_id}.{fmt}"
        try:
            path = rp.export(self.store, self.case_id, str(out), fmt=fmt)
        except Exception as exc:
            QMessageBox.critical(self, "生成失败", str(exc))
            self.log(f"❌ 报告生成失败：{exc}")
            return
        self.log(f"报告已生成：{path}（{os.path.getsize(path):,} 字节）")
        self.statusBar().showMessage(f"报告已生成：{path}")
        QMessageBox.information(self, "完成", f"报告已生成：\n{path}")


class _ThreadRunner(QThread):
    """跑一个可调用对象的裸线程（继承 QThread 而非改写实例方法，更稳）。"""

    def __init__(self, work, parent=None) -> None:
        super().__init__(parent)
        self._work = work

    def run(self) -> None:      # noqa: D102
        self._work()


def run_in_thread(parent, work, done, err_title: str = "执行出错") -> None:
    """
    在后台线程跑一个函数，完成后回主线程回调。

    情报扫描要遍历全部记录，几十万行时在主线程跑会把界面卡死，
    所以这里统一走线程。异常必须弹窗而不是静默吞掉——否则用户
    只看到按钮变回可用，却不知道扫描其实失败了。

    线程对象挂在 parent 上保活：局部变量在函数返回后就没了，
    QThread 被 GC 回收会直接崩。
    """
    def runner() -> None:
        try:
            work()
        except Exception as exc:            # noqa: BLE001
            parent.log(f"❌ {err_title}：{exc}")

            def show() -> None:
                QMessageBox.critical(parent, err_title, str(exc))
                if callable(done):
                    done()
            QTimer.singleShot(0, show)
            return
        if callable(done):
            QTimer.singleShot(0, done)

    t = _ThreadRunner(runner, parent)
    t.finished.connect(lambda: None)
    setattr(parent, f"_bg_thread_{id(t):x}", t)
    t.start()


def describe_detail(result) -> str:
    """把 ProbeResult 的证据条目渲染到文本（CLI/自检用）。"""
    lines = ["证据："]
    for ev in result.evidence:
        lines.append(f"  · {ev}")
    if result.os_strings:
        lines.append("系统指纹命中：")
        for k, v in result.os_strings.items():
            if v:
                lines.append(f"  · {k.rstrip(chr(0))} × {v}")
    return "\n".join(lines)
