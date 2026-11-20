"""
MemLens · 入口（桌面启动器 / Web 控制台 / vol3 子进程）

## 三种运行方式

1. **Web 控制台（默认）**：`MemLens.exe` / `python main.py`
   → 起本地 FastAPI 服务 → 自动打开浏览器 → 打开证据即**全量深度分析**。
   这是主形态：UI 完整（概览/产物/时间线/发现项/情报/旗标/用户/日志），
   且能同时服务 Windows / Linux / macOS 的镜像。

2. **原生桌面 GUI**：`python main.py --desktop`
   → 保留 v0.10 的 PySide6 界面（离线单机、无浏览器场景）。

3. **vol3 子进程**：`MemLens.exe --vol3-entry <vol3 参数…>`
   → 打包后 vol3 引擎需要"再起一个进程"跑 Volatility3。
   此时 sys.executable 指向 exe 本身而不是 python，所以 exe 必须
   自己支持这个入口开关 —— 否则封装后的内存分析全部失效。
   （这是打包 PySide6 + Volatility3 程序最容易漏掉的一环）

## 子命令

```
MemLens.exe <证据文件>            # 打开文件并自动开始深度分析
MemLens.exe --serve --port 8765   # 只起服务，不开浏览器
MemLens.exe --desktop             # 原生 GUI
MemLens.exe --web --port 9000     # 指定端口
```
"""

from __future__ import annotations

import os
import sys
import webbrowser
from pathlib import Path

# 子进程模式开关。改动时**必须**同步 memlens/engines/vol3.py 里的同名常量。
VOL3_ENTRY_FLAG = "--vol3-entry"

FROZEN = bool(getattr(sys, "frozen", False))


def _fix_streams() -> None:
    """
    打包后的 exe（--windowed）没有控制台 ⇒ 把输出**全部写进日志文件**。

    ⚠ **不要用 `sys.stdout is None` 判断**（实测踩过，很隐蔽）：
       PyInstaller 6.x 的 windowed 模式给的是一个**"假流"对象**（不是 None），
       所以 `if sys.stdout is None: sys.stdout = fp` **永远不成立** ——
       结果是：日志文件被创建了（0 字节），但所有 print 仍然写进被丢弃的假流，
       **排障时日志里什么都看不到**，只能靠猜。
    ⇒ 判定标准改成"有没有真实控制台"，并且**无条件接管** stdout/stderr。

    日志要点：
      ① **行缓冲**（buffering=1），否则进程被杀时内容还留在缓冲区里；
      ② 目录跟随 `MEMLENS_HOME`（没有则用 exe 同级目录），与数据同处；
      ③ 超过 512 KB 自动轮转一份 .log.1，避免无限增长。

    ★★★ **子进程入口绝不重定向**（2026-11-10 实测定位的打包版头号 bug）：
       `--vol3-entry` 是父进程 spawn 出来的 vol3 执行端，它的 **stdout 就是父进程
       解析 JSONL 的数据管道**。若在这里把 stdout 换成日志文件，父进程只能收到
       **空输出** → vol3 每个插件都"成功但 0 行"/失败 → 界面上只剩程序日志
       （这正是用户说的"日志还只是程序日志"）。
       `--selftest` 同理：它要把 JSON 报告打到控制台/文件供人查看。
    """
    if len(sys.argv) >= 2 and sys.argv[1] in (VOL3_ENTRY_FLAG, "--selftest"):
        return                      # 数据通道/自检输出：保持原样，绝不接管
    if not FROZEN and sys.stdout is not None and sys.stderr is not None:
        return                      # 源码运行：有真控制台，直接用
    log_path = None
    try:
        home = os.environ.get("MEMLENS_HOME")
        if home:
            base = Path(home).resolve()
        elif FROZEN:
            base = Path(sys.executable).resolve().parent
        else:
            base = _root()
        work = base / "work"
        work.mkdir(parents=True, exist_ok=True)
        log_path = work / "memlens.log"
        try:
            if log_path.is_file() and log_path.stat().st_size > 512 * 1024:
                log_path.replace(log_path.with_suffix(".log.1"))
        except OSError:
            pass
        fp = open(log_path, "a", encoding="utf-8", errors="replace", buffering=1)
    except Exception:
        fp = open(os.devnull, "w", encoding="utf-8")
    # ★ 无条件接管（不再判断 is None）
    sys.stdout = fp
    sys.stderr = fp
    if log_path is not None:
        try:
            sys.stderr.write(f"[MemLens] 无控制台模式，输出写入 {log_path}\n")
            sys.stderr.flush()
        except Exception:
            pass


def _root() -> Path:
    """项目根：开发期是源码目录；打包后是 exe 所在目录。"""
    if FROZEN:
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


ROOT = _root()
if not FROZEN and str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _vol3_entry() -> int:
    """子进程模式：把参数交给 Volatility3 的 CLI 后退出，不启动 GUI。"""
    del sys.argv[1]
    from memlens.engines._vol3_entry import main as vol_main
    return vol_main()


def _initial_image() -> str | None:
    """
    从命令行取"要打开的证据文件"。
    用法：MemLens.exe D:\\cases\\mem.raw
    （同时支持把文件拖到 exe 上启动）
    """
    for a in sys.argv[1:]:
        if a.startswith("-"):
            continue
        try:
            if Path(a).is_file():
                return a
        except OSError:
            continue
    return None


def _parse_args(argv: list[str]) -> dict:
    opts = {"mode": "web", "host": "127.0.0.1", "port": 8765,
            "open_browser": True, "image": None, "extra": []}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--desktop", "--gui"):
            opts["mode"] = "desktop"
        elif a in ("--web", "--serve"):
            opts["mode"] = "web"
        elif a == "--no-browser":
            opts["open_browser"] = False
        elif a in ("--host", "--port"):
            key = a[2:]
            i += 1
            if i < len(argv):
                opts[key] = int(argv[i]) if key == "port" else argv[i]
        elif a.startswith("--port="):
            opts["port"] = int(a.split("=", 1)[1])
        elif a.startswith("--host="):
            opts["host"] = a.split("=", 1)[1]
        elif not a.startswith("-"):
            try:
                if Path(a).is_file():
                    opts["image"] = a
                else:
                    opts["extra"].append(a)
            except OSError:
                pass
        i += 1
    return opts


def _run_web(opts: dict) -> int:
    """
    启动 Web 取证控制台。

    ★ 这一段是"用户说打开慢 / 有时候根本打不开"的修复现场（2026-10-24）：
      旧版三个毛病：
        ① 端口被占用 → uvicorn 绑定失败 → **windowed exe 没有控制台 → 静默退出**
           （日志实测：`[Errno 10048] ... 8765`，用户连点 4 次都"没反应"）；
        ② 浏览器 `sleep(1.5)` 就打开，而服务器 2.5 s 才 ready → 白屏"无法访问此网站"；
        ③ `/api/health` 每次都同步跑 `vol.py --help` 子进程（0.8 s）→ 首屏慢。
      现在：
        ① 端口被占 → 是自己就直接开已有实例；是别人就**自动换端口**；
           实在起不来 → **弹 Windows 消息框**（不再静默）；
        ② **等 `/api/health` 真能响应了才开浏览器**；
        ③ 引擎自检改后台预热 + 60 s 缓存（见 `web/app.py::engine_status`）。
    """
    import threading
    import time as _t

    from memlens.web import app as web_app
    from memlens.web import server as srv

    host = opts.get("host", "127.0.0.1")
    port = int(opts.get("port", 8765))
    image = opts.get("image")

    # ---------- ① 端口冲突处理 ----------
    if not srv.port_is_free(host, port):
        if srv.is_memlens_instance(port, host):
            url = f"http://{host}:{port}/"
            print(f"[MemLens] MemLens 已经在运行：{url}")
            if opts.get("open_browser"):
                srv.open_browser(url)
            else:
                srv.notify_info("MemLens 已在运行", f"取证控制台已在运行：\n{url}")
            return 0
        try:
            new_port = srv.find_free_port(host, port)
            print(f"[MemLens] 端口 {port} 被其他程序占用，自动改用 {new_port}")
            port = new_port
        except OSError as exc:
            msg = (f"端口 {port} 被占用，且 {port}~{port + srv.PORT_SCAN_TRIES - 1} "
                   f"都没有空闲端口。\n\n{exc}\n\n"
                   f"可以用 --port 指定其它端口，例如：MemLens.exe --port 9000")
            srv.notify_error("MemLens 无法启动", msg)
            sys.stderr.write(f"[MemLens] {msg}\n")
            return 1

    url = f"http://{host}:{port}/"
    t_start = _t.time()
    print(f"[MemLens] 取证控制台：{url}")
    print(f"[MemLens] 数据库后端：{web_app.STATE.store.backend}")
    if image:
        print(f"[MemLens] 启动后将自动打开并深度分析：{image}")

    try:
        import uvicorn
    except ImportError:
        sys.stderr.write("未安装 uvicorn。执行：python -m pip install \"uvicorn[standard]\" fastapi\n")
        srv.notify_error("MemLens 缺少依赖", "未安装 uvicorn / fastapi，请用 MemLens 提供的 exe，"
                                           "或在虚拟环境里执行：\n"
                                           "    python -m pip install \"uvicorn[standard]\" fastapi")
        return 127

    # ---------- ② 后台线程跑 uvicorn，主线程负责"等 ready → 开浏览器" ----------
    config = uvicorn.Config(web_app.app, host=host, port=port,
                             log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    th = threading.Thread(target=server.run, name="memlens-uvicorn", daemon=True)
    th.start()

    ready = srv.wait_ready(url + "api/health", timeout=srv.READY_TIMEOUT)
    if not ready:
        msg = (f"服务在 {srv.READY_TIMEOUT:.0f} 秒内没有就绪。\n\n"
               f"可能原因：端口 {port} 被占用、数据库连接卡住、或依赖缺失。\n"
               f"日志见：{web_app.STATE.workdir / 'memlens.log'}")
        server.should_exit = True
        srv.notify_error("MemLens 启动失败", msg)
        sys.stderr.write(f"[MemLens] {msg}\n")
        return 1

    print(f"[MemLens] 就绪耗时 {(_t.time() - t_start):.2f}s")
    if opts.get("open_browser"):
        target = url + ("#open=" + image.replace("\\", "/") if image else "")
        if srv.open_browser(target):
            print("[MemLens] 已在浏览器中打开")
        else:
            # 浏览器拉不起来（无桌面/无默认浏览器）→ 必须让用户知道地址
            print(f"[MemLens] 无法自动打开浏览器，请手动访问：{url}")
            srv.notify_info("MemLens 已启动", f"无法自动打开浏览器，请手动访问：\n\n{url}")
    else:
        print(f"[MemLens] 请手动访问：{url}")

    # ---------- ③ 主线程驻留 ----------
    try:
        while th.is_alive():
            th.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\n[MemLens] 正在停止…")
        server.should_exit = True
        try:
            th.join(timeout=10)
        except Exception:
            pass
    return 0


def _run_desktop(opts: dict) -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        sys.stderr.write(
            "未安装 PySide6。请在 MemLens 的虚拟环境里执行：\n"
            "    python -m pip install PySide6\n"
        )
        return 127

    from PySide6.QtCore import QTimer
    from memlens.ui import theme
    from memlens.ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("MemLens")
    app.setApplicationDisplayName("MemLens 内存取证工作台")
    theme.apply_theme(app)

    icon = _find_icon()
    if icon is not None:
        try:
            from PySide6.QtGui import QIcon
            app.setWindowIcon(QIcon(str(icon)))
        except Exception:
            pass

    window = MainWindow(project_root=ROOT)
    window.show()

    image = opts.get("image")
    if image:
        QTimer.singleShot(250, lambda: window.load_image(image))

    return app.exec()


def _find_icon() -> Path | None:
    """定位应用图标（打包内嵌 / exe 同目录 / 源码目录 三处依次找）。"""
    cands: list[Path] = []
    base = getattr(sys, "_MEIPASS", None)
    if base:
        cands.append(Path(base) / "memlens.ico")
    cands.append(ROOT / "memlens.ico")
    cands.append(Path(__file__).resolve().parent / "memlens.ico")
    for c in cands:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return None


def _selftest() -> int:
    """
    打包自检（`MemLens.exe --selftest`）。

    为什么需要：GUI/Web 打包成 exe 后最容易坏在**看不见的地方**——符号表写不进去、
    MemProcFS 没带上、引擎没注册、数据库建不了表，而双击时只表现为"界面空空的"。
    这里一次性列出来，并把报告写到 exe 同级 `work\\selftest.json`，便于脚本判断。

    退出码：0 = 关键项全过；1 = 有失败项。
    """
    import json

    report: dict = {"frozen": bool(getattr(sys, "frozen", False)), "exe_dir": str(ROOT),
                    "checks": {}}

    def _ck(name: str, ok: bool, detail: str = "") -> None:
        report["checks"][name] = {"ok": bool(ok), "detail": str(detail)[:300]}

    try:
        from memlens.engines import registry
        for name in registry.installed():
            try:
                eng = registry.get(name)
                ok, why = eng.available()
            except Exception as exc:
                ok, why = False, f"构造失败：{exc}"
            _ck(f"engine.{name}", ok, why)
            try:
                _ck(f"plugins.{name}", len(registry.get(name).list_plugins()) > 0,
                    f"{len(registry.get(name).list_plugins())} 个")
            except Exception as exc:
                _ck(f"plugins.{name}", False, str(exc))
    except Exception as exc:
        _ck("engines", False, f"引擎导入失败：{exc}")

    try:
        from memlens.detectors.base import all_detectors
        ds = all_detectors()
        _ck("detectors", bool(ds), ", ".join(d.name for d in ds))
    except Exception as exc:
        _ck("detectors", False, str(exc))

    try:
        from memlens.storage.db import DataStore
        db = ROOT / "work" / "memlens.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        DataStore(db).close()
        _ck("database", db.is_file(), str(db))
    except Exception as exc:
        _ck("database", False, str(exc))

    try:
        from memlens.engines.memprocfs import find_executable
        exe = find_executable()
        _ck("memprocfs_runtime", exe is not None,
            str(exe) if exe else "未找到 memprocfs.exe（应放在 exe 同级 tools\\MemProcFS）")
    except Exception as exc:
        _ck("memprocfs_runtime", False, str(exc))

    try:
        from memlens.core.vol3_env import Vol3Env
        _ck("vol3_symbols", True, Vol3Env(ROOT / "work").ensure().status().summary())
    except Exception as exc:
        _ck("vol3_symbols", False, str(exc))

    report["ok"] = all(v["ok"] for v in report["checks"].values())
    try:
        out = ROOT / "work" / "selftest.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass
    try:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    except Exception:
        pass
    return 0 if report["ok"] else 1


def _cli_subcommand() -> bool:
    """argv[1] 是否为 cli.py 的已知子命令（url-analyze/web-log/browser-history/container…）。"""
    if len(sys.argv) < 2 or sys.argv[1].startswith("-"):
        return False
    try:
        import argparse
        from memlens.cli import build_parser
        p = build_parser()
        for action in p._actions:
            if isinstance(action, argparse._SubParsersAction) and sys.argv[1] in action.choices:
                return True
    except Exception:
        pass
    return False


def main() -> int:
    _fix_streams()

    # ---- 子进程模式必须最先判断（早于任何 Qt / FastAPI 导入）----
    if len(sys.argv) >= 2 and sys.argv[1] == VOL3_ENTRY_FLAG:
        return _vol3_entry()

    # ---- 打包自检（不需要 GUI / Web 服务）----
    if "--selftest" in sys.argv[1:]:
        return _selftest()

    # ★ CLI 子命令优先（MemLens.exe url-analyze … / web-log … / container …）。
    #   否则 exe 会把子命令当"证据文件"，静默启动 Web 控制台，CLI 永远不生效。
    #   （windowed exe 无控制台：CLI 输出走日志，结果用 --json/--report 导出文件。）
    if _cli_subcommand():
        from memlens.cli import main as cli_main
        return cli_main(sys.argv[1:])

    opts = _parse_args(sys.argv[1:])
    if opts["mode"] == "desktop":
        return _run_desktop(opts)
    return _run_web(opts)


if __name__ == "__main__":
    sys.exit(main())
