# -*- mode: python ; coding: utf-8 -*-
"""
MemLens 打包 spec（PyInstaller 6.x）

关键决策与理由：
  1. **onedir 而非 onefile**：MemLens 的内存分析架构是"exe 起子进程跑
     Volatility3"（见 main.py 的 --vol3-entry）。onefile 每次子进程调用都要
     把整个包解压一遍（含 300+ MB Qt），内存分析会慢到不可用。
     onedir 则是同目录直接起进程，秒级。
  2. **collect_all('volatility3')**：vol3 的插件是运行时用 importlib 动态发现的，
     PyInstaller 静态分析抓不到；不整体收集的话运行时一个插件都找不到。
     （本体仅 12 MiB，代价很小）
  3. **collect_submodules('memlens')**：本项目的 engines / detectors 同样是
     注册表式动态导入（registry），也必须整体收集。
  4. **排除 QtWebEngine 等**：PySide6 原始体积 632 MB，而 UI 只用到
     QtCore / QtGui / QtWidgets 三块。排除未用模块可把产物压到 ~80 MB。
  5. **必须在 ASCII 路径下打包**：中文路径会让 PyInstaller 的路径处理出错，
     所以统一用 memlens 项目自身路径 D:\\MemLens（已是 ASCII）。
"""

from PyInstaller.utils.hooks import collect_all, collect_submodules
import os as _os

# ---------------------------------------------------------------- 收集
datas = []
binaries = []
hiddenimports = []

# Volatility3：插件动态发现，必须整体收集（submodules + data + binaries）
for pkg in ("volatility3",):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

# MemLens 自身：engines/detectors 走注册表式动态导入
hiddenimports += collect_submodules("memlens")

# 数据文件
datas += [
    ("D:/MemLens/memlens/storage/schema.sql", "memlens/storage"),
    ("D:/MemLens/memlens.ico", "."),
]

# ── v1.0：Web 前端静态资源（FastAPI 要用 StaticFiles 挂载）──
# ⚠ 打包后 `__file__` 指向 `_MEIPASS/memlens/web/static/`，所以目标目录必须
#   保持 `memlens/web/static` 这个相对路径，否则前端会 404。
import glob as _glob

for _f in _glob.glob("D:/MemLens/memlens/web/static/*"):
    if _os.path.isfile(_f):
        datas.append((_f, "memlens/web/static"))

# 兜底：显式列出关键入口（即使 collect 失败也能跑）
hiddenimports += [
    "volatility3.cli",
    "memlens.engines._vol3_entry",
    "memlens.engines.vol3",
    "memlens.engines.static",
    "memlens.engines.elf",
    "memlens.engines.pcap",
    "memlens.engines.archive",
    "memlens.engines.memfrag",
    "memlens.engines.registry",
    "memlens.detectors.hidden_process",
    "memlens.detectors.injection",
    "memlens.detectors.static_pe",
    "memlens.detectors.memprocfs_triage",
    "pefile",
    # ── 加速：numpy（VeraCrypt 批量 XTS 解密向量化，可选但强烈建议）──
    "numpy",
    "numpy.core",
    "numpy.lib",
    # ── v1.0：全栈 Web 后端 ──
    "memlens.web.app",
    "memlens.web.static",
    "memlens.pipeline.deep",
    "memlens.pipeline.plan",
    "memlens.pipeline.sysprofile",
    "memlens.storage.models",
    "fastapi",
    "starlette",
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "sqlalchemy",
    "sqlalchemy.dialects.mysql.pymysql",
    "pymysql",
    "websockets",
    "httptools",
    "anyio",
]

# ---------------------------------------------------------------- 排除
# 体积大且本项目完全不用（UI 只用 QtCore/QtGui/QtWidgets）
EXCLUDES = [
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebEngineQuick", "PySide6.QtWebChannel", "PySide6.QtWebSockets",
    "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuick3D", "PySide6.QtQuickWidgets",
    "PySide6.QtQuickControls2",
    "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.Qt3DInput",
    "PySide6.Qt3DLogic", "PySide6.Qt3DAnimation", "PySide6.Qt3DExtras",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
    "PySide6.QtCharts", "PySide6.QtDataVisualization", "PySide6.QtGraphs",
    "PySide6.QtDesigner", "PySide6.QtUiTools", "PySide6.QtHelp",
    "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtBluetooth", "PySide6.QtNfc",
    "PySide6.QtPositioning", "PySide6.QtSerialPort", "PySide6.QtSensors",
    "PySide6.QtRemoteObjects", "PySide6.QtScxml", "PySide6.QtStateMachine",
    "PySide6.QtSpatialAudio", "PySide6.QtTextToSpeech", "PySide6.QtPdf",
    "PySide6.QtPdfWidgets", "PySide6.QtNetworkAuth", "PySide6.QtOpenGL",
    "PySide6.QtOpenGLWidgets", "PySide6.QtSvg", "PySide6.QtSvgWidgets",
    # 明确与内存取证无关的第三方大件
    "matplotlib", "pandas", "scipy", "IPython", "jupyter", "notebook",
    "tkinter", "test", "unittest", "pydoc_data",
    "pyarrow", "gcsfs", "s3fs", "fsspec",
]

a = Analysis(
    ["D:/MemLens/main.py"],
    pathex=["D:/MemLens"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MemLens",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                 # UPX 压缩会拖慢启动，且对 Qt DLL 易出问题
    console=False,             # GUI 程序：不弹控制台
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="D:/MemLens/memlens.ico",
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="MemLens",
)
