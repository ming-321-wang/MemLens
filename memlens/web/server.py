"""
MemLens · 本地 Web 服务启动器（可靠性核心）

## 这个模块存在的理由：用户报"打开慢 / 有时候根本打不开"

实测根因（全部来自 `dist/MemLens/work/memlens.log`）：

```
ERROR: [Errno 10048] error while attempting to bind on address ('127.0.0.1', 8765):
       [winerror 10048] 通常每个套接字地址(协议/网络地址/端口)只允许使用一次。
```

exe 是 `--windowed` 打包的（**没有控制台**），所以：
1. 端口被占用 → uvicorn 绑定失败 → 异常只写进日志文件 → **双击完全没反应**；
2. 上一版的浏览器是 `sleep(1.5)` 后就打开的，而服务器要 2.5 s 才 ready
   → 浏览器先打开 → 看到"无法访问此网站" → 用户以为软件坏了。

本模块把这两件事都变成"可恢复 + 可见"：

| 场景 | 旧行为 | 新行为 |
|---|---|---|
| 端口被**别的程序**占 | 静默退出 | **自动换端口**（8765→8766→…，最多 20 个）并用实际端口开浏览器 |
| 端口被**本工具自己**占 | 静默退出 | 直接**打开已有实例的浏览器**并提示"已在运行" |
| 服务器还没 ready | 浏览器白屏 | **轮询 `/api/health` 直到 200** 再开浏览器（最多 60 s） |
| 绑定彻底失败 | 日志里一行 | **弹 Windows 消息框** + 写日志 + 退出码非 0 |
| 数据库连不上 | 可能长时间卡住 | **连接超时 5 s**，失败自动回退 SQLite |

## 断网

启动路径**完全不触网**：
前端是纯本地 HTML/CSS/JS（无 CDN、无外部字体），
后端只监听 127.0.0.1，
符号表下载只发生在**分析阶段**且有本地缓存。
（本模块提供 `probe_offline()` 做运行时验证：拦截所有出网 socket。）
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

#: 默认可用端口（可被占用，逐个往后找）
DEFAULT_PORT = 8765
#: 最多尝试的端口数
PORT_SCAN_TRIES = 20
#: 等待服务器 ready 的超时（秒）
READY_TIMEOUT = 60.0
#: 探活超时
PROBE_TIMEOUT = 2.0


# ------------------------------------------------------------------ 端口


def port_is_free(host: str, port: int) -> bool:
    """
    这个端口现在能不能绑？

    ⚠ **Windows 上不能设 `SO_REUSEADDR`**（实测踩过）：
       Windows 的 `SO_REUSEADDR` 语义比 Unix 宽松 —— 已经有 socket 在
       `bind()+listen()` 该端口后，另一个 socket **带着 SO_REUSEADDR 仍能 bind 成功**，
       于是"探测端口空闲"永远返回 True → 自动换端口逻辑失效 → uvicorn 真的绑定时
       才报 `[Errno 10048]`（用户看到的"双击没反应"）。
       所以这里**不设** SO_REUSEADDR，并且**真的 listen 一下**再关掉
       （只 bind 不 listen 不足以判断端口能否被服务占用）。
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            s.listen(1)
            return True
        except OSError:
            return False


def find_free_port(host: str = "127.0.0.1", preferred: int = DEFAULT_PORT,
                   tries: int = PORT_SCAN_TRIES) -> int:
    """从 preferred 开始找一个空闲端口。"""
    for i in range(max(1, tries)):
        p = preferred + i
        if p > 65535:
            break
        if port_is_free(host, p):
            return p
    raise OSError(f"{host} 上从 {preferred} 起的 {tries} 个端口都被占用")


# ------------------------------------------------------------------ 探活


def probe(url: str, timeout: float = PROBE_TIMEOUT) -> dict[str, Any] | None:
    """请求一个 URL，返回 JSON（失败返回 None）。"""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            body = r.read()
            if not body:
                return {}
            try:
                return json.loads(body.decode("utf-8", "replace"))
            except Exception:
                return {"ok": True, "raw": len(body)}
    except urllib.error.HTTPError as e:
        return {"ok": False, "http": e.code}
    except Exception:
        return None


def is_memlens_instance(port: int, host: str = "127.0.0.1") -> bool:
    """这个端口上是不是已经在跑一个 MemLens（而不是别的程序）？"""
    info = probe(f"http://{host}:{port}/api/health", timeout=PROBE_TIMEOUT)
    return bool(info and info.get("app") == "MemLens")


def wait_ready(url: str, timeout: float = READY_TIMEOUT,
               interval: float = 0.25) -> bool:
    """轮询直到服务真正能响应（而不是"端口已监听"）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = probe(url, timeout=PROBE_TIMEOUT)
        if info and (info.get("ok") or info.get("app") == "MemLens"):
            return True
        time.sleep(interval)
    return False


# ------------------------------------------------------------------ 提示


def notify_error(title: str, message: str) -> None:
    """
    弹一个 Windows 消息框（窗口化 exe 没有控制台，错误必须"看得见"）。

    非 Windows / 无 GUI 时退化为写 stderr。
    """
    text = f"{title}\n\n{message}"
    try:
        if os.name == "nt":
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, text, "MemLens", 0x10)
            return
    except Exception:
        pass
    try:
        sys.stderr.write(f"[MemLens] {title}: {message}\n")
    except Exception:
        pass


def notify_info(title: str, message: str) -> None:
    try:
        if os.name == "nt":
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, message, title, 0x40)
            return
    except Exception:
        pass
    try:
        sys.stderr.write(f"[MemLens] {title}: {message}\n")
    except Exception:
        pass


def open_browser(url: str) -> bool:
    """打开浏览器（失败不致命，只记录）。"""
    try:
        import webbrowser

        return bool(webbrowser.open(url))
    except Exception:
        return False


# ------------------------------------------------------------------ 断网探针


def probe_offline(verbose: bool = True) -> dict[str, Any]:
    """
    **运行时验证"断网能不能开"**：把所有出网 socket 指向黑洞，
    然后启动服务并请求首页与 API，看是否仍能正常响应。

    这比手工拔网线更可控、可重复，而且能精确回答
    "启动路径到底有没有依赖外网"。

    Returns: {"offline": True, "ok": bool, "checks": {...}}
    """
    import threading

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    blocked = {"n": 0}

    def _blocked_connect(self, address):
        host = address[0] if isinstance(address, tuple) else ""
        # 只拦"出网"，本机回环必须放行
        if isinstance(address, tuple) and host not in ("127.0.0.1", "::1", "localhost"):
            blocked["n"] += 1
            raise OSError(f"[offline-probe] 出网被拦截：{address}")
        return real_connect(self, address)

    def _blocked_connect_ex(self, address):
        host = address[0] if isinstance(address, tuple) else ""
        if isinstance(address, tuple) and host not in ("127.0.0.1", "::1", "localhost"):
            blocked["n"] += 1
            return 111          # ECONNREFUSED
        return real_connect_ex(self, address)

    socket.socket.connect = _blocked_connect          # type: ignore[method-assign]
    socket.socket.connect_ex = _blocked_connect_ex    # type: ignore[method-assign]

    checks: dict[str, Any] = {}
    ok = True
    try:
        from memlens.web import app as web_app

        host, port = "127.0.0.1", _pick_free_port()
        cfg = web_app.create_app()
        # 用 uvicorn 线程起服务
        import uvicorn

        server = uvicorn.Server(uvicorn.Config(cfg, host=host, port=port,
                                               log_level="error", access_log=False))
        t = threading.Thread(target=server.run, daemon=True)
        t.start()
        ready = web_app_wait(host, port)
        checks["server_ready"] = ready
        if not ready:
            ok = False
        base = f"http://{host}:{port}"
        for path in ("/", "/static/app.js", "/static/style.css", "/api/health", "/api/cases"):
            info = probe(base + path, timeout=10)
            good = bool(info) and info is not None
            checks[path] = good
            if not good:
                ok = False
        checks["blocked_outbound_attempts"] = blocked["n"]
        server.should_exit = True
        t.join(timeout=10)
    except Exception as exc:
        ok = False
        checks["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        socket.socket.connect = real_connect          # type: ignore[method-assign]
        socket.socket.connect_ex = real_connect_ex    # type: ignore[method-assign]

    result = {"offline": True, "ok": ok, "checks": checks}
    if verbose:
        print(f"断网探针：{'通过 ✔' if ok else '失败 ✘'}")
        for k, v in checks.items():
            print(f"   {k:28} {v}")
    return result


def web_app_wait(host: str, port: int, timeout: float = 30.0) -> bool:
    return wait_ready(f"http://{host}:{port}/api/health", timeout=timeout)


def _pick_free_port(preferred: int = 8877) -> int:
    for i in range(50):
        p = preferred + i
        if port_is_free("127.0.0.1", p):
            return p
    raise OSError("找不到空闲端口用于断网探针")
