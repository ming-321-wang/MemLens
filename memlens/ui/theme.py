"""
MemLens · 界面主题（深色"取证控制台"）

为什么用 QSS 而不是默认外观：取证工作在暗环境长时间盯屏，默认灰白控件的对比度低、
状态色（成功/失败/高危）无处安放；而 QSS 是**零依赖**方案，打包 exe 也不会引入额外资源。

约定：
  * 颜色全部走常量，界面代码不写死色值（改主题只改这一处）；
  * 状态色同时提供"深色背景上的文字色"（见 STATUS_COLORS），保证可读性；
  * 只用 Qt 原生控件就能生效的选择器，不依赖自定义控件属性（避免 exe 里样式丢失）。
"""

from __future__ import annotations

# ---------------------------------------------------------------- 调色板
BG = "#171922"          # 主背景
BG_ALT = "#1e2130"      # 次级背景（面板）
BG_CARD = "#232739"     # 卡片
BG_INPUT = "#12141c"    # 输入/表格底
BORDER = "#2f3550"
TEXT = "#d9dcea"
TEXT_DIM = "#8b93a7"
ACCENT = "#4f8cff"
ACCENT_DARK = "#2b5fd0"
OK = "#37d67a"
WARN = "#f5c542"
DANGER = "#ff5c5c"
CRIT = "#c471ff"

#: 插件/任务状态 → (颜色, 文案)
STATUS_COLORS: dict[str, str] = {
    "ok": OK,
    "partial": WARN,
    "failed": DANGER,
    "running": ACCENT,
    "queued": TEXT_DIM,
    "skipped": TEXT_DIM,
    "cancelled": TEXT_DIM,
}
STATUS_TEXT: dict[str, str] = {
    "ok": "✔ 完成",
    "partial": "△ 无结果",
    "failed": "✘ 失败",
    "running": "▶ 运行中",
    "queued": "· 排队",
    "skipped": "⊘ 跳过",
    "cancelled": "⊘ 取消",
}

SEVERITY_COLORS: dict[str, str] = {
    "critical": CRIT,
    "high": DANGER,
    "medium": WARN,
    "low": OK,
    "info": TEXT_DIM,
}

QSS = f"""
QWidget {{ background: {BG}; color: {TEXT};
           font-family: "Microsoft YaHei UI", "Segoe UI", sans-serif; font-size: 12px; }}
QMainWindow, QDialog {{ background: {BG}; }}

/* ---- 卡片 / 分组 ---- */
QGroupBox {{ background: {BG_ALT}; border: 1px solid {BORDER}; border-radius: 8px;
             margin-top: 14px; padding: 8px 8px 6px 8px; font-weight: 600; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 1px 6px;
                    color: {ACCENT}; background: {BG_ALT}; border-radius: 4px; }}
QFrame#Card {{ background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 8px; }}
QFrame#Banner {{ background: #1b2a1f; border: 1px solid {OK}; border-radius: 8px; }}
QLabel#CardTitle {{ color: {TEXT_DIM}; font-size: 11px; letter-spacing: 1px; }}
QLabel#CardValue {{ color: {TEXT}; font-size: 13px; }}
QLabel#FlagBig {{ color: {OK}; font-family: Consolas, monospace; font-size: 15px; font-weight: 600; }}
QLabel#Phase {{ color: {ACCENT}; font-weight: 600; }}
QLabel#Dim {{ color: {TEXT_DIM}; }}
QLabel#Warn {{ color: {WARN}; }}

/* ---- 按钮 ---- */
QPushButton {{ background: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 6px;
               padding: 5px 10px; color: {TEXT}; }}
QPushButton:hover {{ background: #2b3049; border-color: {ACCENT}; }}
QPushButton:pressed {{ background: {ACCENT_DARK}; }}
QPushButton:disabled {{ color: #5a6076; background: #1b1e2a; border-color: #262b3d; }}
QPushButton#Primary {{ background: {ACCENT_DARK}; border-color: {ACCENT}; font-weight: 600; }}
QPushButton#Primary:hover {{ background: {ACCENT}; }}
QPushButton#Flag {{ background: #23402c; border-color: {OK}; color: #b9f7d0; font-weight: 600; }}
QPushButton#Flag:hover {{ background: #2c5540; }}
QPushButton#Danger {{ background: #40232a; border-color: {DANGER}; }}

/* ---- 输入 ---- */
QLineEdit, QComboBox, QSpinBox, QPlainTextEdit, QTextEdit {{
    background: {BG_INPUT}; border: 1px solid {BORDER}; border-radius: 6px; padding: 4px 6px;
    selection-background-color: {ACCENT_DARK}; }}
QLineEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{ border: 0; width: 18px; }}
QComboBox QAbstractItemView {{ background: {BG_CARD}; border: 1px solid {BORDER};
                               selection-background-color: {ACCENT_DARK}; }}
QTextEdit, QPlainTextEdit {{ font-family: Consolas, "Courier New", monospace; font-size: 12px; }}

/* ---- 表格 / 树 ---- */
QTreeWidget, QTableWidget, QTableView {{
    background: {BG_INPUT}; alternate-background-color: #1a1d29; border: 1px solid {BORDER};
    border-radius: 8px; gridline-color: #262b3d; selection-background-color: {ACCENT_DARK};
    selection-color: #ffffff; }}
QHeaderView::section {{ background: {BG_CARD}; color: {TEXT_DIM}; border: 0;
                        border-right: 1px solid {BORDER}; border-bottom: 1px solid {BORDER};
                        padding: 5px 6px; font-weight: 600; }}
QTreeWidget::item {{ padding: 2px; }}
QTreeWidget::item:selected, QTableWidget::item:selected {{ background: {ACCENT_DARK}; }}

/* ---- 标签页 ---- */
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 8px; top: -1px; }}
QTabBar::tab {{ background: {BG_ALT}; color: {TEXT_DIM}; padding: 7px 14px; margin-right: 2px;
                border: 1px solid {BORDER}; border-bottom: 0;
                border-top-left-radius: 7px; border-top-right-radius: 7px; }}
QTabBar::tab:selected {{ background: {BG_CARD}; color: {TEXT}; border-color: {ACCENT}; }}
QTabBar::tab:hover {{ color: {TEXT}; }}

/* ---- 进度条 ---- */
QProgressBar {{ background: {BG_INPUT}; border: 1px solid {BORDER}; border-radius: 7px;
                text-align: center; color: {TEXT}; height: 16px; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 6px; }}
QProgressBar#PhaseBar::chunk {{ background: {OK}; }}
QProgressBar#PhaseBar {{ height: 10px; }}

/* ---- 滚动条 ---- */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #3a4160; border-radius: 5px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #3a4160; border-radius: 5px; min-width: 24px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}

/* ---- 杂项 ---- */
QSplitter::handle {{ background: {BORDER}; width: 2px; }}
QStatusBar {{ background: {BG_ALT}; color: {TEXT_DIM}; border-top: 1px solid {BORDER}; }}
QStatusBar QLabel {{ color: {TEXT_DIM}; }}
QToolTip {{ background: {BG_CARD}; color: {TEXT}; border: 1px solid {ACCENT}; padding: 4px; }}
QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {BORDER};
                        border-radius: 3px; background: {BG_INPUT}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QMessageBox {{ background: {BG_ALT}; }}
"""


def apply_theme(app) -> None:
    """给 QApplication 套用主题（失败也不该让程序起不来）。"""
    try:
        app.setStyleSheet(QSS)
    except Exception:
        pass
