"""
MemLens · Web 后端（FastAPI）

## 为什么是"全栈"

原来的 MemLens 是 PySide6 桌面壳 + Python 引擎。桌面壳有三个硬伤：

1. **UI 能力受限**：要加一个"系统画像概览页""跨产物联动筛选""多标签对比"，
   在 QWidget 里是几百行样板代码；Web 端是一段 JS。
2. **无法远程/共享**：取证结果要靠拷贝数据库文件给别人。
3. **多模态展示受限**：甘特图、时间线、关系图这些在 Web 端是现成方案。

于是本模块把 MemLens 拆成 **FastAPI 后端 + 纯前端 SPA**：
后端仍然复用原来那套（已验证的）Python 取证引擎与证据模型，
前端换成浏览器里的取证控制台。桌面端保留一个**启动器**：
`MemLens.exe` → 起本地服务 → 自动开浏览器 → 用完关掉。

## 关键设计

* **事件总线**：深度分析在后台线程跑，通过 WebSocket 把
  `progress / log / plugin_start / plugin_done / probe / plan / done` 推给前端。
* **单进程、仅监听 127.0.0.1**：取证数据敏感，不做鉴权但也不对外暴露。
* **数据库后端可切**：SQLite（默认，零配置）↔ MySQL（`MEMLENS_DB_URL`）。
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import platform
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, Response)
from fastapi.staticfiles import StaticFiles

from memlens.core import image_probe
from memlens.core import symbols as symbols_mod
from memlens.engines import registry as engine_registry
from memlens.pipeline.deep import DeepAnalyzer
from memlens.storage.db import DataStore

HERE = Path(__file__).resolve().parent
STATIC_DIR = HERE / "static"

#: 默认数据库：环境变量优先，否则工作目录下的 SQLite
DEFAULT_DB_URL = os.environ.get("MEMLENS_DB_URL", "")
#: 建案时先算的**快速指纹**字节数（前 8 MB）——完整 SHA-256 放后台算
FAST_HASH_LIMIT = 8 << 20

#: 后台"补全任务"（深度探测 + 完整 SHA-256）的限流参数
#: ⚠ 实测教训：不限流时，每建一个案就有一个线程去读整个镜像算 SHA-256，
#:   几个案子叠在一起会把**所有后续请求**拖慢一个数量级
#:   （probe 1 ms → 241 ms、create_case 11 ms → 617 ms，用户感知是"越用越卡"）。
#:   所以：**全局最多 1 个补全任务在跑** + 同一案件只补一次 + 延迟 3 秒再启动。
ENRICH_DELAY = 3.0
_ENRICH_SEM = threading.Semaphore(1)
_ENRICH_LOCK = threading.Lock()
_ENRICHING: set[str] = set()


def _with_timeout(url: str, seconds: int = 5) -> str:
    """
    给 SQLAlchemy URL 加上连接超时。

    为什么必须加：MySQL 连不上时，PyMySQL 默认会**长时间重试**，
    表现为"双击软件没反应、一直转圈"—— 用户根本不知道是数据库的问题。
    5 秒连不上就直接回退到本地 SQLite，并在日志里说明。
    """
    if not url.startswith("mysql"):
        return url
    sep = "&" if "?" in url else "?"
    if "connect_timeout=" in url:
        return url
    return f"{url}{sep}connect_timeout={seconds}"


def _rulepack_summary() -> dict[str, Any]:
    """规则包摘要（health / /api/rulepack 共用）。"""
    try:
        from memlens.core import rulepack as rp
        return rp.summary()
    except Exception as exc:
        return {"error": str(exc)}


def _project_root() -> Path:
    """
    MemLens 的"可写根目录"（工作目录 / 数据库 / 缓存都在它下面）。

    优先级：`MEMLENS_HOME` 环境变量 → 源码目录的上一级 → 打包后 exe 所在目录。
    ⚠ 打包成 exe 时 `__file__` 在 `_MEIPASS`（临时解包目录）里，
    那里是**只读**的，绝不能往那儿写 work/ 与数据库。
    """
    env = os.environ.get("MEMLENS_HOME")
    if env:
        return Path(env).resolve()
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    # memlens/web/app.py → memlens/web → memlens → <项目根>
    return Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------ 事件总线


class EventBus:
    """
    把后台线程产生的事件转给 WebSocket 客户端。

    ## 为什么用 `queue.Queue` 而不是 `asyncio.Queue`（实测踩过，事件会**丢第一条**）

    深度分析在**后台线程**里跑，它要往订阅者的队列里塞消息。
    `asyncio.Queue` **不是线程安全的**：
    * `publish()` 若在事件循环线程外调用 `put_nowait()`，它会 `Event.set()` 唤醒等待者，
      而 `Event.set()` 内部要 `loop.call_soon()` —— **从别的线程调 `call_soon` 不安全**，
      唤醒可能丢失 ⇒ **客户端收不到第一条事件**。
    * 症状很隐蔽：日志里第一条 progress 明明发了，浏览器却只看到第二条，
      表现为"进度条一开始不动，隔 2 秒才跳"。

    ⇒ 改成**标准库的 `queue.Queue`（真正线程安全）**：
    生产者（任意线程）`put`，消费者（事件循环协程）用 `asyncio.to_thread(q.get, ...)`
    取。这样**完全不依赖事件循环**，也就没有竞态。
    """

    def __init__(self) -> None:
        import queue as _q
        self._subs: dict[str, list[Any]] = {}
        self._lock = threading.Lock()
        self._qmod = _q

    def subscribe(self, case_id: str) -> Any:
        q = self._qmod.Queue(maxsize=4000)
        with self._lock:
            self._subs.setdefault(case_id, []).append(q)
        return q

    def unsubscribe(self, case_id: str, q: Any) -> None:
        with self._lock:
            lst = self._subs.get(case_id)
            if lst and q in lst:
                lst.remove(q)

    def publish(self, case_id: str, kind: str, payload: Any) -> None:
        with self._lock:
            queues = list(self._subs.get(case_id, ()))
        if not queues:
            return
        message = {"type": kind, "payload": payload}
        for q in queues:
            # ★ `queue.Queue.put_nowait` 是**线程安全**的：
            #   生产者可以是任意线程（深度分析跑在后台线程里），
            #   消费者（事件循环协程）用 `asyncio.to_thread(q.get, ...)` 取。
            #   用 `asyncio.Queue` 会在跨线程 put 时丢掉唤醒信号 ⇒ 客户端收不到第一条事件。
            try:
                q.put_nowait(message)
            except Exception:
                pass


# ------------------------------------------------------------------ 应用状态


class AppState:
    """进程级状态：数据库、工作目录、引擎实例、运行中的分析。"""

    def __init__(self) -> None:
        self.root = _project_root()
        self.workdir = self.root / "work"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.store = self._open_store()
        # ★ v1.3：规则包（方案 FR-21）——阈值/白名单/词表外置，离线可换、可回滚
        from memlens.core import rulepack
        self.rulepacks = rulepack.configure(self.workdir)
        self.engines: dict[str, Any] = {}
        self.bus = EventBus()
        self.runs: dict[str, dict[str, Any]] = {}
        self.cancel_events: dict[str, threading.Event] = {}
        self._engine_lock = threading.Lock()
        # 引擎自检结果缓存（★ 首屏速度的关键，见 engine_status 的注释）
        self._status_cache: list[dict[str, Any]] | None = None
        self._status_at: float = 0.0
        self._status_lock = threading.Lock()
        self._status_refreshing = False

    # ------------------------------------------------------------ 数据库
    def _open_store(self) -> DataStore:
        url = DEFAULT_DB_URL
        if url:
            try:
                store = DataStore.from_url(_with_timeout(url))
                print(f"[MemLens] 数据库后端：{store.backend}（{url}）")
                return store
            except Exception as exc:
                print(f"[MemLens] 数据库连接失败（{exc}），回退到本地 SQLite")
        db = self.workdir / "memlens.db"
        store = DataStore(db)
        print(f"[MemLens] 数据库后端：{store.backend}（{db}）")
        return store

    def switch_db(self, url: str) -> str:
        """切换数据库后端（会重建表）。返回新后端名。"""
        new = DataStore.from_url(url)
        self.store.close()
        self.store = new
        self.store.kv_set("db_url", url)
        return new.backend

    # ------------------------------------------------------------ 引擎
    def get_engines(self) -> dict[str, Any]:
        with self._engine_lock:
            if self.engines:
                return self.engines
            # ★ 引擎清单**从注册表枚举**，不写死名字 ——
            #   否则新增引擎（如 container 容器引擎）永远不出现在 /api/health 里。
            #   旧引擎需要额外 kwargs，按名字分支传参。
            for name in engine_registry.installed():
                try:
                    self.engines[name] = engine_registry.get(
                        name,
                        **({"cache_dir": str(self.workdir / "vol3" / "cache"),
                            "symbols_dir": str(self.workdir / "vol3" / "symbols")}
                           if name == "memprocfs" else
                           {"cache_dir": str(self.workdir / "vol3" / "cache")}
                           if name == "vol3" else {}),
                    )
                except TypeError:
                    self.engines[name] = engine_registry.get(name)
                except Exception as exc:
                    print(f"[MemLens] 引擎 {name} 初始化失败：{exc}")
            return self.engines

    def engine_status(self, *, max_age: float = 60.0, background: bool = True) -> list[dict[str, Any]]:
        """
        引擎自检结果（**带缓存**）。

        ## 为什么必须缓存

        `Volatility3Adapter.available()` 会**真的跑一次 `vol.py --help` 子进程**
        （实测 0.8 s）。旧版 `/api/health` 每次都调它 ⇒
        前端每次刷新页面都要多等近 1 秒；首屏串行请求时更明显。

        现在：
        * 缓存 60 s；
        * 过期时**先返回旧值**，同时后台线程刷新（`background=True`）；
        * 启动后由 `prewarm()` 预先把缓存填好，首屏直接命中。

        `background=False` 时同步重算（给"我想立刻看到真实状态"的场景用）。
        """
        with self._status_lock:
            fresh = (self._status_cache is not None
                     and (time.time() - self._status_at) < max_age)
            if fresh:
                return self._status_cache
            if background and not self._status_refreshing:
                self._status_refreshing = True
                threading.Thread(target=self._refresh_status, daemon=True).start()
            return self._status_cache or []

    def _refresh_status(self) -> None:
        out: list[dict[str, Any]] = []
        for name, eng in self.get_engines().items():
            try:
                ok, why = eng.available()
            except Exception as exc:
                ok, why = False, f"自检异常：{exc}"
            out.append({
                "name": name, "display": getattr(eng, "display", name),
                "available": bool(ok), "detail": str(why),
            })
        with self._status_lock:
            self._status_cache = out
            self._status_at = time.time()
            self._status_refreshing = False

    def prewarm(self) -> None:
        """
        启动后**后台**预热（不阻塞首屏）：
        引擎自检 + 插件清单枚举（vol3 首次要跑一次 `--help` 并落盘缓存）。
        """
        def _work() -> None:
            try:
                self._refresh_status()
            except Exception:
                pass
            for name, eng in self.get_engines().items():
                try:
                    eng.list_plugins()
                except Exception:
                    pass
        threading.Thread(target=_work, daemon=True, name="memlens-prewarm").start()


STATE = AppState()


# ------------------------------------------------------------------ FastAPI


def create_app() -> FastAPI:
    # ★ 用现代的 **lifespan** 而不是 `@app.on_event("startup")`：
    #   新版 FastAPI 已弃用 on_event（且在某些启动路径下不触发），
    #   而它本来只负责做两件事：预热引擎 + 绑定事件循环。
    #   现在事件总线**不再依赖事件循环**（用线程安全的 queue.Queue），
    #   lifespan 里只剩"预热"这一件事，行为更确定。
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        STATE.get_engines()
        # ★ 后台预热（引擎自检 + 插件清单），**不阻塞首屏**
        STATE.prewarm()
        yield

    app = FastAPI(title="MemLens", version="1.2.0", lifespan=lifespan,
                  description="MemLens 内存取证工作台 · 全栈 Web 后端 + 工具箱（按需按钮）")

    # ------------------------------------------------------------ 静态资源
    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.middleware("http")
    async def _cache_static(request, call_next):
        """
        静态资源加长缓存（前端资源只有 ~57 KB，但每次刷新重下会让"打开慢"被放大）。
        API 一律不缓存。
        """
        response = await call_next(request)
        path = request.url.path
        if path.startswith("/static/"):
            response.headers["Cache-Control"] = "public, max-age=300"
        elif path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/favicon.ico")
    def favicon() -> Any:
        """站点图标（顺带消掉浏览器自动请求 favicon 产生的 404）。"""
        for cand in (HERE.parent.parent / "memlens.ico",
                     HERE.parent.parent.parent / "memlens.ico",
                     Path(sys.executable).resolve().parent / "memlens.ico"):
            try:
                if cand.is_file():
                    return FileResponse(str(cand), media_type="image/x-icon")
            except OSError:
                continue
        return Response(status_code=204)

    @app.get("/", response_class=HTMLResponse)
    def index() -> Any:
        f = STATIC_DIR / "index.html"
        if not f.is_file():
            return HTMLResponse("<h1>MemLens</h1><p>前端资源缺失</p>", status_code=500)
        return HTMLResponse(f.read_text(encoding="utf-8"))

    # ------------------------------------------------------------ 基础信息
    @app.get("/api/sysstat")
    def sysstat() -> dict[str, Any]:
        """
        底部状态栏用的轻量系统状态（CPU / 内存 / 本进程占用）。

        CPU 走 GetSystemTimes 的**两次采样做差**，首次调用没有基准 →
        `cpu_percent` 为 null，UI 显示「—」（前端每 2 秒轮询，第二次就有值）。
        """
        try:
            from memlens.core import sysstat as _ss
            return _ss.snapshot()
        except Exception as exc:                     # 状态栏永远不该拖垮界面
            return {"cpu_percent": None, "mem": None, "self_mb": None,
                    "error": f"{type(exc).__name__}: {exc}"}

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        from memlens.storage.models import metadata
        return {
            "ok": True,
            "app": "MemLens",
            "version": "1.8.0",
            "python": platform.python_version(),
            "platform": platform.platform(),
            "database": {
                "backend": STATE.store.backend,
                "url": STATE.store.url,
                "tables": len(metadata.tables),
            },
            "workdir": str(STATE.workdir),
            "engines": STATE.engine_status(),
            # ★ v1.3：健康检查里直接给出规则包版本（结论可复现的前提）
            "rulepack": _rulepack_summary(),
        }

    @app.get("/api/engines")
    def engines() -> dict[str, Any]:
        out = []
        for name, eng in STATE.get_engines().items():
            try:
                plugins = [
                    {"name": p.name, "display": p.display, "category": p.category,
                     "kind": p.kind.value}
                    for p in eng.list_plugins()
                ]
            except Exception as exc:
                plugins = []
                name_err = str(exc)
            else:
                name_err = ""
            out.append({
                "name": name, "display": getattr(eng, "display", name),
                "plugins": plugins, "error": name_err,
            })
        return {"engines": out}

    # ------------------------------------------------------------ 案件
    @app.get("/api/cases")
    def list_cases() -> dict[str, Any]:
        return {"cases": STATE.store.list_cases()}

    @app.post("/api/cases")
    def create_case(payload: dict[str, Any]) -> dict[str, Any]:
        """
        打开一个证据文件 → 建案。

        ★ **这里必须"立即返回"**（用户报"打开很慢"的第二根因）：
          旧版做两件重活：
            ① `probe_image(deep=True)` —— 要扫 **192 MiB** 指纹窗口（实测 2.1 s / 2 GB 文件）；
            ② `create_case()` 里的**全文件 SHA-256** —— 实测 3.1 s / 2 GB，
               16 GB 镜像就是 **~25 s**（界面上一个转圈，什么反馈都没有）。
          现在：
            · 建案只做**魔数级探测**（瞬时）与**前 8 MB 快速指纹**；
            · **深度探测 + 完整 SHA-256 放后台线程**，算完回填案件表。
            · 前端立刻拿到 case_id 并开始分析，用户马上看到进度。
        """
        path = str(payload.get("path") or "").strip()
        if not path:
            raise HTTPException(400, "缺少 path")
        p = Path(path)
        if not p.is_file():
            raise HTTPException(400, f"文件不存在：{path}")
        name = str(payload.get("name") or p.name)
        import time as _t
        _t0 = _t.time()

        # 只做魔数级探测（不扫指纹窗口，瞬时）
        probe = image_probe.probe_image(str(p), deep=False)
        _t1 = _t.time()
        case_id = STATE.store.create_case(
            name, str(p),
            container=probe.container.value,
            os_type=probe.os_type.value,
            os_confidence=probe.os_confidence,
            hash_limit=FAST_HASH_LIMIT,      # ★ 只哈希前 8 MB，先给一个快速指纹
        )
        # 系统画像的"镜像层"先占位
        # ★ scan_bytes=False：字节兜底要读 256–512 MB，放在这里会让"打开文件"卡 3.6 秒；
        #   这一步留给分析阶段（那时已经在后台跑、有进度条可看）。
        from memlens.pipeline import sysprofile as sp
        prof = sp.build_profile(
            probe_os=probe.os_type.value,
            image_path=str(p),
            image_size=probe.size,
            container=probe.container.value,
            scan_bytes=False,
        )
        try:
            STATE.store.set_system_profile(case_id, prof.to_dict(), {})
        except Exception:
            pass

        # ---------- 后台补全：深度探测 + 完整 SHA-256 ----------
        # ★ **限流 + 去重 + 延迟**（实测踩过）：
        #   每次建案都直接起一个线程读整个文件算 SHA-256 ⇒ 连开 4 个案子就有 4 个
        #   线程同时抢磁盘，实测**后续请求被拖慢一个数量级**
        #   （probe 从 1 ms 涨到 241 ms、create_case 从 11 ms 涨到 617 ms，
        #     用户感知就是"越用越卡"）。
        #   现在：全局信号量限制**同时最多 1 个**补全任务 + 同一案件只补一次
        #        + 延迟 3 秒启动（让前面的即时操作先跑完）。
        def _enrich() -> None:
            os_type = probe.os_type.value
            container = probe.container.value
            try:
                deep = image_probe.probe_image(str(p), deep=True)
                os_type = deep.os_type.value
                container = deep.container.value
                STATE.store.update_case(
                    case_id,
                    container=container,
                    os_type=os_type,
                    os_confidence=deep.os_confidence,
                )
            except Exception:
                pass
            try:
                from memlens.storage.db import sha256_file

                full = sha256_file(str(p))
                STATE.store.update_case(case_id, image_sha256=full)
            except Exception:
                pass
            try:
                from memlens.pipeline import sysprofile as sp

                prof2 = sp.build_profile(
                    probe_os=os_type,
                    image_path=str(p),
                    image_size=p.stat().st_size,
                    container=container,
                    scan_bytes=False,     # 后台线程也别抢磁盘（分析阶段会算）
                )
                STATE.store.set_system_profile(case_id, prof2.to_dict(), {})
            except Exception:
                pass
            STATE.bus.publish(case_id, "case_updated", {"case_id": case_id})
            with _ENRICH_LOCK:
                _ENRICHING.discard(case_id)

        def _delayed() -> None:
            import time as _t
            _t.sleep(ENRICH_DELAY)
            if case_id not in _ENRICHING:
                return
            with _ENRICH_SEM:
                _enrich()

        with _ENRICH_LOCK:
            if case_id in _ENRICHING:
                return {"case_id": case_id, "note": "该案件正在补全中", "probe": {}}
            _ENRICHING.add(case_id)
        # ★ v1.3：审计留痕（方案 5.4）——建案属重点操作
        try:
            STATE.store.add_audit(actor="operator", action="open_case",
                                  target=str(p), case_id=case_id,
                                  after_hash=case_id,
                                  detail=f"建案：{name}（{probe.container.value}/{probe.os_type.value}）")
        except Exception:
            pass
        threading.Thread(target=_delayed, daemon=True, name="memlens-enrich").start()

        return {
            "case_id": case_id,
            "probe": {
                "container": probe.container.value,
                "container_confidence": probe.container_confidence,
                "os_type": probe.os_type.value,
                "os_confidence": probe.os_confidence,
                "summary": probe.summary(),
                "evidence": [{"source": e.source, "detail": e.detail} for e in probe.evidence],
            },
            "note": "深度探测与完整 SHA-256 正在后台计算（稍后自动回填）",
            # 耗时分解（诊断用：probe / create_case / 总计，单位毫秒）
            "timing_ms": {
                "probe": round((_t1 - _t0) * 1000, 1),
                "create_case": round((_t.time() - _t1) * 1000, 1),
                "total": round((_t.time() - _t0) * 1000, 1),
            },
        }

    @app.get("/api/cases/{case_id}")
    def case_detail(case_id: str) -> dict[str, Any]:
        case = STATE.store.get_case(case_id)
        if not case:
            raise HTTPException(404, "案件不存在")
        payload = {
            "case": case,
            "stats": STATE.store.stats(case_id),
            "profile": STATE.store.get_system_profile(case_id),
            "artifacts": STATE.store.list_artifacts(case_id),
            "findings": STATE.store.list_findings(case_id),
        }
        # ★ 结论速览：把散在各个页签的证据聚合成"一句话 + flag + 下一步"，
        #   前端概览页直接渲染它 —— 用户双击打开就能看到结论，而不是自己翻页签拼。
        try:
            from memlens.core.verdict import build as build_verdict
            payload["verdict"] = build_verdict(STATE.store, case_id)
        except Exception as exc:            # 结论算不出来也不能拖垮详情接口
            payload["verdict"] = {"error": str(exc)}
        return payload

    @app.get("/api/cases/{case_id}/verdict")
    def case_verdict(case_id: str, format: str = "json") -> Any:
        """一页纸结论（json / md / text），可下载贴报告。"""
        from memlens.core.verdict import build as build_verdict, to_json, to_markdown, to_text
        if not STATE.store.get_case(case_id):
            raise HTTPException(404, "案件不存在")
        v = build_verdict(STATE.store, case_id)
        fmt = (format or "json").lower()
        if fmt == "md":
            return PlainTextResponse(to_markdown(v),
                                    headers={"Content-Disposition":
                                             f'attachment; filename="verdict_{case_id}.md"'})
        if fmt == "text":
            return PlainTextResponse(to_text(v))
        return v

    @app.delete("/api/cases/{case_id}")
    def delete_case(case_id: str) -> dict[str, Any]:
        from sqlalchemy import delete
        from memlens.storage import models as M
        with STATE.store.engine.begin() as conn:
            for tbl in (M.records, M.artifacts, M.findings, M.timeline_events,
                        M.iocs, M.dict_hits, M.flags, M.notes, M.system_profile):
                conn.execute(delete(tbl).where(tbl.c.case_id == case_id))
            conn.execute(delete(M.cases).where(M.cases.c.case_id == case_id))
        return {"ok": True}

    # ------------------------------------------------------------ 分析
    @app.post("/api/cases/{case_id}/analyze")
    def start_analysis(case_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        case = STATE.store.get_case(case_id)
        if not case:
            raise HTTPException(404, "案件不存在")
        payload = payload or {}
        run_id = uuid.uuid4().hex[:12]
        cancel = threading.Event()
        STATE.cancel_events[run_id] = cancel
        STATE.runs[run_id] = {"state": "running", "phase": "start", "percent": 0.0,
                              "started_at": time.time()}

        def worker() -> None:
            def on_event(kind: str, data: Any) -> None:
                STATE.bus.publish(case_id, kind, data)
                if kind == "progress":
                    STATE.runs[run_id].update({
                        "phase": data.get("phase"), "percent": data.get("percent"),
                    })

            try:
                analyzer = DeepAnalyzer(
                    STATE.store, STATE.workdir,
                    engines=STATE.get_engines(),
                    cancel_event=cancel,
                    on_event=on_event,
                    run_id=run_id,
                )
                res = analyzer.analyze(case["image_path"], case_id=case_id, reuse_case=True)
                STATE.runs[run_id].update({
                    "state": res.status, "percent": 100.0,
                    "summary": res.to_dict(),
                })
                STATE.bus.publish(case_id, "done", res.to_dict())
            except Exception as exc:                       # pragma: no cover
                STATE.runs[run_id].update({"state": "failed", "error": str(exc)})
                STATE.bus.publish(case_id, "error", {"message": str(exc)})
            finally:
                STATE.cancel_events.pop(run_id, None)

        # ★ v1.3：审计留痕
        try:
            STATE.store.add_audit(actor="operator", action="analyze",
                                  target=case["image_path"], case_id=case_id,
                                  after_hash=case.get("image_sha256") or "",
                                  detail=f"启动深度分析 run={run_id}")
        except Exception:
            pass
        threading.Thread(target=worker, name=f"memlens-deep-{run_id}", daemon=True).start()
        return {"run_id": run_id, "state": "running"}

    @app.get("/api/runs/{run_id}")
    def run_state(run_id: str) -> dict[str, Any]:
        return STATE.runs.get(run_id, {"state": "unknown"})

    @app.post("/api/runs/{run_id}/cancel")
    def cancel_run(run_id: str) -> dict[str, Any]:
        ev = STATE.cancel_events.get(run_id)
        if ev is None:
            raise HTTPException(404, "运行不存在或已结束")
        ev.set()
        return {"ok": True}

    # ------------------------------------------------------------ 结果读取
    @app.get("/api/cases/{case_id}/artifacts")
    def artifacts(case_id: str) -> dict[str, Any]:
        return {"artifacts": STATE.store.list_artifacts(case_id)}

    @app.get("/api/cases/{case_id}/records")
    def records(
        case_id: str,
        artifact_id: str | None = None,
        keyword: str | None = None,
        limit: int = Query(200, ge=1, le=5000),
        offset: int = Query(0, ge=0),
        order_by: str = "row_no",
    ) -> dict[str, Any]:
        rows = STATE.store.query_records(
            artifact_id=artifact_id, case_id=case_id, keyword=keyword,
            limit=limit, offset=offset, order_by=order_by)
        return {"rows": rows, "count": len(rows)}

    @app.get("/api/cases/{case_id}/findings")
    def findings(case_id: str, severity: str | None = None) -> dict[str, Any]:
        return {"findings": STATE.store.list_findings(case_id, severity=severity)}

    @app.get("/api/cases/{case_id}/timeline")
    def timeline(
        case_id: str,
        limit: int = Query(500, ge=1, le=20000),
        offset: int = Query(0, ge=0),
        category: str | None = None,
        keyword: str | None = None,
        order: str = "asc",
    ) -> dict[str, Any]:
        rows = STATE.store.query_timeline(
            case_id, limit=limit, offset=offset, category=category,
            keyword=keyword, order=order)
        return {"events": rows, "count": len(rows)}

    @app.get("/api/cases/{case_id}/iocs")
    def iocs(case_id: str, kind: str | None = None,
                    limit: int = Query(1000, ge=1, le=20000)) -> dict[str, Any]:
        return {"iocs": STATE.store.list_iocs(case_id, kind=kind, limit=limit)}

    @app.get("/api/cases/{case_id}/dict_hits")
    def dict_hits(case_id: str, limit: int = Query(2000, ge=1, le=20000)) -> dict[str, Any]:
        return {"hits": STATE.store.list_dict_hits(case_id, limit=limit)}

    @app.get("/api/cases/{case_id}/flags")
    def flags(case_id: str) -> dict[str, Any]:
        return {"flags": STATE.store.list_flags(case_id)}

    @app.get("/api/cases/{case_id}/notes")
    def notes(case_id: str) -> dict[str, Any]:
        return {"notes": STATE.store.list_notes(case_id)}

    @app.post("/api/cases/{case_id}/notes")
    def add_note(case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = str(payload.get("body") or "").strip()
        if not body:
            raise HTTPException(400, "笔记内容为空")
        nid = STATE.store.add_note(case_id, body, tags=str(payload.get("tags") or ""))
        return {"note_id": nid}

    @app.get("/api/cases/{case_id}/profile")
    def profile(case_id: str) -> dict[str, Any]:
        return {"profile": STATE.store.get_system_profile(case_id)}

    @app.get("/api/cases/{case_id}/report")
    def report(case_id: str, fmt: str = "md") -> Any:
        from memlens import report as report_mod
        try:
            if fmt == "html":
                text = report_mod.build_html(STATE.store, case_id)
                # ★ v1.3：报告导出属四类重点操作，单独留痕
                try:
                    STATE.store.add_audit(actor="operator", action="export_report",
                                          target=f"{case_id}.html", case_id=case_id,
                                          critical=True,
                                          after_hash=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
                                          detail="导出 HTML 报告")
                except Exception:
                    pass
                return HTMLResponse(text)
            text = report_mod.build_markdown(STATE.store, case_id)
            try:
                STATE.store.add_audit(actor="operator", action="export_report",
                                      target=f"{case_id}.md", case_id=case_id,
                                      critical=True,
                                      after_hash=hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
                                      detail="导出 Markdown 报告")
            except Exception:
                pass
            return PlainTextResponse(text)
        except Exception as exc:
            raise HTTPException(500, f"报告生成失败：{exc}")

    @app.get("/api/cases/{case_id}/export/{artifact_id}.csv")
    def export_csv(case_id: str, artifact_id: str) -> Any:
        out = STATE.workdir / case_id / f"artifact_{artifact_id}.csv"
        out.parent.mkdir(parents=True, exist_ok=True)
        n = STATE.store.export_records_csv(out, artifact_id=artifact_id)
        if not n:
            raise HTTPException(404, "该产物没有可导出的记录")
        return FileResponse(out, filename=f"{artifact_id}.csv", media_type="text/csv")

    @app.get("/api/cases/{case_id}/export/all.csv")
    def export_all_csv(case_id: str) -> Any:
        out = STATE.workdir / case_id / "all_records.csv"
        out.parent.mkdir(parents=True, exist_ok=True)
        n = STATE.store.export_records_csv(out, case_id=case_id)
        if not n:
            raise HTTPException(404, "该案件没有可导出的记录")
        return FileResponse(out, filename=f"{case_id}.csv", media_type="text/csv")

    # ------------------------------------------------------------ 文件详情（未知/失败产物可点进来查）
    def _head_entropy(data: bytes) -> float:
        import math as _math
        if len(data) < 2:
            return 0.0
        counts: dict[int, int] = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        n = len(data)
        ent = 0.0
        for c in counts.values():
            pr = c / n
            ent -= pr * _math.log2(pr)
        return ent

    @app.get("/api/cases/{case_id}/file-info")
    def file_info(case_id: str, plugin: str = "") -> dict[str, Any]:
        """
        一个"这个文件到底是什么"的兜底详情（对应"？？？"场景）：

        工具解析失败 / 容器未知时，用户至少能看到：
          · 文件头 64 字节 hex（魔数）
          · SHA-256 / 大小 / 熵
          · 容器探测结论 + 全部证据行
          · static.profile 的画像（类型/编译语言/加壳/危险 API）
          · 失败产物的原始错误信息
        这些字段**即使引擎失败也一定有**，保证"点得进去、看得到"。
        """
        case = STATE.store.get_case(case_id)
        if not case:
            raise HTTPException(404, "案件不存在")
        image = case.get("image_path") or ""
        p = Path(image)
        info: dict[str, Any] = {
            "case_id": case_id, "name": case.get("name"),
            "path": str(p), "exists": p.is_file(), "size": case.get("image_size"),
            "sha256": case.get("image_sha256"),
            "probe": {}, "profile": {}, "raw_output": None, "error": case.get("state"),
        }
        # ① 文件头 64 字节（魔数判断"它到底是什么"）
        try:
            with open(p, "rb") as f:
                head = f.read(64)
            info["head_hex"] = head.hex()
            info["head_text"] = "".join(chr(b) if 32 <= b < 127 else "·" for b in head)
            info["head_entropy"] = round(_head_entropy(head), 3)
        except OSError:
            pass
        # ② 容器探测（重跑一次浅探测，拿全部证据行）
        try:
            probe = image_probe.probe_image(str(p), deep=False)
            info["probe"] = {
                "container": probe.container.value,
                "confidence": probe.container_confidence,
                "os_type": probe.os_type.value,
                "evidence": [f"[{e.source}] {e.detail}" for e in probe.evidence],
                "warnings": list(probe.warnings),
            }
        except Exception as exc:
            info["probe"]["error"] = str(exc)
        # ③ static 引擎画像（任何文件都能出：类型/哈希/熵/加壳/危险 API）
        try:
            eng = STATE.get_engines().get("static")
            if eng is not None:
                meta = next((x for x in eng.list_plugins() if x.name == "static.profile"), None)
                if meta is not None:
                    rows = list(eng.analyze_file(str(p), meta))
                    info["profile"] = rows[:200]
        except Exception as exc:
            info["profile"] = {"error": str(exc)}
        # ④ 指定插件（若有）的产物详情：状态 / 行数 / 原始输出 / 错误
        if plugin:
            arts = [a for a in STATE.store.list_artifacts(case_id) if a.get("plugin") == plugin]
            if arts:
                a = arts[-1]
                raw = None
                if a.get("output_path") and Path(a["output_path"]).is_file():
                    try:
                        raw = Path(a["output_path"]).read_text(
                            encoding="utf-8", errors="replace")[:20000]
                    except OSError:
                        raw = None
                info["raw_output"] = raw
                info["artifact"] = {
                    "status": a.get("status"), "rows": a.get("row_count"),
                    "duration_ms": a.get("duration_ms"), "error": a.get("error"),
                    "engine": a.get("engine"),
                }
        return info

    # ------------------------------------------------------------ 工具（按需）
    TOOL_PLUGINS: dict[str, tuple[str, str]] = {
        # 工具键 → (引擎, 插件)。结果全部落进现有证据模型，「产物」页可见。
        "sysinfo": ("memprocfs", "mprocfs.sysinfo"),
        "users": ("memprocfs", "mprocfs.users"),
        "envs": ("memprocfs", "mprocfs.envs"),
        "files": ("memprocfs", "mprocfs.files"),
        "flag": ("memstrings", "memstrings.flag"),
        "process_dump": ("memprocfs", "mprocfs.dump_process"),
    }

    # ------------------------------------------------ 跨产物检索
    @app.post("/api/search")
    def do_search(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        跨产物检索：证据表 records / 检测器结论 findings / 时间线 timeline。

        body:
            case_id  案件（空 = 全部案件）
            query    检索式。支持：
                        "带空格"   精确短语
                        key:value  按字段过滤（records 的列名，如 pid:1234）
                        -word      排除
                        /regex/    正则
            scopes   逗号分隔，默认 records,findings,timeline
            regex    是否按正则解释
            limit    返回条数上限
        """
        from memlens.core.search import (Query, search, scan_container,
                                         scan_bytes)
        body = payload or {}
        limit = int(body.get("limit") or 200)

        # ── 容器内检索（在加密卷/镜像里直接查内容，不落盘）──
        container = str(body.get("container") or "").strip()
        if container:
            from memlens.core.exfat import ExFat
            from memlens.core.veracrypt_volume import VeraCryptVolume
            from memlens.formats.ewf import EwfReader
            from memlens.formats.vmdk import VmdkDisk

            q = Query(str(body.get("query") or ""), regex=bool(body.get("regex")))
            vol = VeraCryptVolume(container, str(body.get("password") or ""))
            hits: list[dict[str, Any]] = []
            try:
                fs = ExFat(vol)
                target = str(body.get("target") or "").strip()
                ents = fs.list_dir(fs.root_cluster)
                if target:
                    ents = [e for e in ents if e["name"].lower() == target.lower()]
                for e in ents:
                    if e["is_dir"]:
                        continue
                    for h in scan_container(vol, fs, e, q, source=e["name"],
                                            case_id=str(body.get("case_id") or ""),
                                            limit=limit - len(hits)):
                        hits.append(h.to_dict())
                    if len(hits) >= limit:
                        break
            finally:
                vol.close()
            return {"query": q.raw, "parsed": q.describe(),
                    "scopes": ["container"], "count": len(hits),
                    "elapsed": 0.0, "hits": hits[:limit]}

        try:
            return search(
                STATE.store, str(body.get("case_id") or ""),
                str(body.get("query") or ""),
                scopes=[x.strip() for x in
                        str(body.get("scopes") or
                            "records,findings,timeline").split(",") if x.strip()],
                regex=bool(body.get("regex")),
                limit=limit,
            )
        except Exception as exc:
            raise HTTPException(400, f"检索失败：{type(exc).__name__}: {exc}")

    # ------------------------------------------------ 取证容器（非内存镜像检材）
    @app.post("/api/container/analyze")
    def container_analyze(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        取证容器分析：加密卷 / EWF / VMDK / pcapng / APK。

        body:
            target   目标文件路径
            kind     identify | files | crypto | extract | traffic | apk
            password 加密卷口令（可选）
            path     要提取的卷内路径（kind=extract 时）
            traffic  interfaces | bluetooth | rename | hid（kind=traffic 时）
        """
        from memlens.engines.container import ContainerEngine, identify_container

        body = payload or {}
        target = str(body.get("target") or "").strip()
        kind = str(body.get("kind") or "identify").strip()
        if not target:
            raise HTTPException(400, "缺少 target（目标文件路径）")
        if not Path(target).exists():
            raise HTTPException(400, f"文件不存在：{target}")

        if kind == "identify":
            return {"kind": kind, "info": identify_container(target), "rows": []}

        eng = ContainerEngine(workdir=STATE.workdir)
        plugin = {
            "files": "container.files",
            "crypto": "container.crypto",
            "extract": "container.extract",
            "apk": "mobile.apk",
            "xfs": "container.xfs",
            "xfs_read": "container.xfs_read",
            "traffic": {"interfaces": "traffic.interfaces",
                        "bluetooth": "traffic.bluetooth",
                        "rename": "traffic.ble_rename",
                        "hid": "traffic.hid"}.get(
                            str(body.get("traffic") or "interfaces"), "traffic.interfaces"),
        }.get(kind)
        if not plugin:
            raise HTTPException(400, f"未知 kind：{kind}")
        params = {"password": str(body.get("password") or ""),
                  "path": str(body.get("path") or ""),
                  "lv": str(body.get("lv") or "root"),
                  "scan": str(body.get("scan") or "1"),
                  "ino": str(body.get("ino") or ""),
                  "mode": str(body.get("mode") or ""),
                  "limit": str(body.get("limit") or ""),
                  "list": str(body.get("list") or "")}
        try:
            meta = next(p for p in eng.list_plugins() if p.name == plugin)
            spec = eng.build_run(meta, target, params)
            rows = list(eng.parse_records(spec, "", ""))
        except Exception as exc:
            raise HTTPException(400, f"{type(exc).__name__}: {exc}")
        return {"kind": kind, "plugin": plugin, "target": target, "rows": rows}

    @app.post("/api/browser/scan")
    def browser_scan(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        检测所有浏览器历史 + 境外 IP / 风险分析（可视化入口，按需触发）。

        body: {appdata?, all_drives?, browser?, profile?, since?, until?,
               keyword?, limit?, ip_map?, resolve?}
        返回：sources（发现的历史库）、visits（访问记录）、report（境外IP风险报告）。
        """
        from memlens.core import browser_history as bh, browser_report as br
        payload = payload or {}
        appdata = str(payload.get("appdata") or "").strip() or None
        all_drives = bool(payload.get("all_drives"))
        src = (bh.discover_in_appdata(appdata) if appdata
               else bh.sources_report(all_drives=all_drives))
        visits = bh.collect(
            browser=str(payload.get("browser") or "all"),
            profile=str(payload.get("profile") or ""),
            since=payload.get("since"), until=payload.get("until"),
            keyword=str(payload.get("keyword") or ""),
            limit=int(payload.get("limit") or 0),
            all_drives=all_drives, appdata=appdata)
        ip_map = {str(k).lower(): str(v) for k, v in (payload.get("ip_map") or {}).items()}
        report = br.build_report(visits, ip_map=ip_map,
                                 resolve=bool(payload.get("resolve")))
        return {
            "sources": [{"browser": s["browser"], "profile": s["profile"],
                         "path": s["path"], "size_mb": s["size_mb"]} for s in src],
            "visits": [v.as_dict() for v in visits],
            "report": report,
        }

    @app.post("/api/url-analyze")
    def url_analyze_route(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """URL / 境外 IP 分析（可视化入口）。body: {urls: [], ip_map?, resolve?}。"""
        from memlens.core import url_analyze as ua
        payload = payload or {}
        urls = payload.get("urls") or []
        ip_map = {str(k).lower(): str(v) for k, v in (payload.get("ip_map") or {}).items()}
        items = ua.analyze_urls(urls, resolve=bool(payload.get("resolve")), ip_map=ip_map)
        return {"items": [it.as_dict() for it in items], "stats": ua.risk_stats(items)}

    @app.post("/api/scanner/parse")
    def scanner_parse(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """解析扫描器 result.txt（[url]/[title]/[finger]/[icmp]）。body: {text} 或 {path}。"""
        from memlens.core import url_analyze as ua
        payload = payload or {}
        text = str(payload.get("text") or "")
        if not text and payload.get("path"):
            with open(str(payload["path"]), encoding="utf-8-sig", errors="ignore") as f:
                text = f.read()
        if not text:
            raise HTTPException(400, "缺少 text 或 path")
        return ua.parse_scanner_output(text)

    @app.post("/api/web-log/analyze")
    def web_log_analyze(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """网站访问日志分析（攻击者IP/可疑请求/一句话木马）。body: {text} 或 {path}。"""
        from memlens.core import web_log_analyze as wl
        payload = payload or {}
        text = str(payload.get("text") or "")
        if not text and payload.get("path"):
            with open(str(payload["path"]), encoding="utf-8-sig", errors="ignore") as f:
                text = f.read()
        if not text:
            raise HTTPException(400, "缺少 text 或 path")
        return wl.analyze_access_log(text, keyword=str(payload.get("keyword") or ""))

    @app.post("/api/server/analyze")
    def server_analyze(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """服务器文件级取证（WP 0x05）。body: {kind, path? 或 text?, password?}。"""
        from memlens.core import server_forensics as sf
        import time as _t
        payload = payload or {}
        kind = str(payload.get("kind") or "")
        text = str(payload.get("text") or "")
        if not text and payload.get("path"):
            with open(str(payload["path"]), encoding="utf-8-sig", errors="ignore") as f:
                text = f.read()
        pw = str(payload.get("password") or "")
        if kind == "wtmp":
            r = sf.parse_wtmp(str(payload.get("path") or ""))
        elif kind == "passwd":
            r = sf.parse_passwd(text)
        elif kind == "trojan":
            r = sf.parse_trojan_config(text)
        elif kind == "php":
            r = sf.parse_php_encrypt(text, pw)
        elif kind == "sql":
            from datetime import datetime as _dt
            start = int(_dt(2016, 4, 1).timestamp())
            end = int(_dt(2025, 4, 1).timestamp())
            r = sf.parse_sql_orders(text, start, end)
            r["gap"] = sf.parse_sql_first_order_gap(text)
        else:
            raise HTTPException(400, "kind 应为 wtmp/passwd/trojan/php/sql")
        return r

    @app.post("/api/server/solve")
    def server_solve(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """服务器检材一键求解（WP 0x05）：打开容器 FS，全盘内容扫描并解析各题。
        body: {image, password, plain?}。返回 {xfs, results}。
        合成 FS 的 extent 不可信 ⇒ 用内容搜索定位文件（inode 路径不可靠）。"""
        from memlens.formats.xfs import open_server_fs
        from memlens.core import server_forensics as sf
        payload = payload or {}
        img = str(payload.get("image") or "")
        if not img:
            raise HTTPException(400, "缺少 image")
        x, meta = open_server_fs(img, str(payload.get("password") or ""))
        res = sf.solve_server_fs(x, password=str(payload.get("plain") or "sbwyz1"))
        return {"xfs": x.summary(), "lvm": {k: meta.get(k) for k in
                ("lvm_lv", "lvm_offset", "pv_offset")}, "results": res}

    @app.post("/api/tools/{tool}")
    def run_tool(tool: str, case_id: str = "", payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        按需执行单项工具（用户点按钮才触发，绝不随启动自动跑）。

        机制：走 TaskRunner 的同一套登记/落盘/入库，执行完通过事件总线
        （tool_done）通知前端；结果在「产物」页与记录抽屉里查看。
        """
        case = payload or {}
        case_id = str(case_id or case.get("case_id") or "").strip()
        if tool not in TOOL_PLUGINS:
            raise HTTPException(400, f"未知工具：{tool}（可选：{', '.join(sorted(TOOL_PLUGINS))}）")
        if not case_id:
            cases = STATE.store.list_cases()
            if not cases:
                raise HTTPException(400, "没有案件：请先打开一个证据文件")
            case_id = cases[0]["case_id"]
        store_case = STATE.store.get_case(case_id)
        if not store_case:
            raise HTTPException(404, "案件不存在")

        engine_name, plugin_name = TOOL_PLUGINS[tool]
        engine = STATE.get_engines().get(engine_name)
        if engine is None:
            raise HTTPException(500, f"引擎 {engine_name} 未注册")
        ok, why = engine.available()
        if not ok:
            # 引擎整体缺失（如 MemProcFS 未部署）→ 明确报给前端，而不是 500
            STATE.bus.publish(case_id, "log", {"text": f"[工具 {tool}] 引擎 {engine_name} 不可用：{why}"})
            return {"run_id": "", "state": "unavailable", "engine": engine_name,
                    "note": f"引擎 {engine_name} 不可用：{why}", "tool": tool}

        params: dict[str, Any] = dict(payload or {})
        params.pop("case_id", None)
        # 工具入口默认**跳过缓存**（用户点按钮就是要"现在再跑一次"）
        plugin = next((p for p in engine.list_plugins() if p.name == plugin_name), None)
        if plugin is None:
            raise HTTPException(404, f"插件 {plugin_name} 不在引擎清单中")

        from memlens.tasks.runner import TaskRunner
        import uuid as _uuid

        run_id = _uuid.uuid4().hex[:12]
        cancel = threading.Event()
        STATE.cancel_events[run_id] = cancel
        STATE.runs[run_id] = {"state": "running", "tool": tool, "percent": 0.0,
                              "started_at": time.time()}

        def worker() -> None:
            from memlens.tasks.runner import TaskRunner as _TR
            runner = _TR(STATE.store, engine, workdir=STATE.workdir / "artifacts")
            try:
                res = runner.run_plugin(
                    case_id, plugin, params or None,
                    cache=False,                      # 工具调用总是新跑一次
                    cancel_event=cancel,
                    timeout=_timeout_for_tool(tool),
                    on_line=lambda line, _t=tool: STATE.bus.publish(case_id, "log", {"text": f"[{_t}] {line}"}),
                )
                STATE.runs[run_id].update({"state": res.status, "percent": 100.0,
                                            "result": dataclasses.asdict(res) if hasattr(res, "__dataclass_fields__") else dict(res.__dict__)})
                STATE.bus.publish(case_id, "tool_done", {
                    "tool": tool, "case_id": case_id, "status": res.status,
                    "rows": res.rows, "error": res.error, "run_id": run_id,
                    "artifact_id": res.artifact_id,
                })
            except Exception as exc:
                STATE.runs[run_id].update({"state": "failed", "error": str(exc)})
                STATE.bus.publish(case_id, "tool_error", {"tool": tool, "message": str(exc)})
            finally:
                STATE.cancel_events.pop(run_id, None)

        threading.Thread(target=worker, name=f"memlens-tool-{tool}-{run_id}", daemon=True).start()
        return {"run_id": run_id, "state": "running",
                "note": f"工具 {tool} 已启动（{engine_name}:{plugin_name}），完成后自动刷新「产物」页"}

    def _timeout_for_tool(tool: str) -> float:
        return 1800.0 if tool in ("flag", "process_dump") else 900.0

    # ------------------------------------------------------------ 本机浏览器历史（按需）
    @app.get("/api/browser-history")
    def browser_history(browser: str = "all", profile: str = "",
                        since: str | None = None, until: str | None = None,
                        keyword: str = "", limit: int = 0,
                        top: int = 12, show: int = 20,
                        sources_only: bool = False,
                        all_drives: bool = False) -> dict[str, Any]:
        """
        本机浏览器历史采集（**按需触发**：只有前端点按钮/主动调本接口才读）。

        只读副本、不联网、不上传。返回：来源探测 + 摘要 + 最近记录；
        用 `/api/browser-history.csv` 拿全量 CSV。

        `all_drives=true`：全驱动器扫描（C–Z 常见浏览器目录），用于本机取证时
        查"这台机器装过哪些浏览器 / 数据盘里藏了哪些历史"。
        """
        from memlens.core import browser_history as bh
        src = bh.sources_report(all_drives=all_drives)
        if sources_only or not src:
            return {"sources": src, "total": 0, "summary": None, "visits": [],
                    "all_drives": all_drives}
        visits = bh.collect(browser=browser, profile=profile, since=since,
                            until=until, keyword=keyword, limit=limit,
                            all_drives=all_drives)
        if not visits:
            return {"sources": src, "total": 0, "summary": None, "visits": [],
                    "all_drives": all_drives}
        return {
            "sources": src,
            "total": len(visits),
            "summary": bh.summarize(visits),
            "visits": [v.as_dict() for v in visits[:show]],
            "all_drives": all_drives,
        }

    @app.get("/api/browser-history.csv")
    def browser_history_csv(browser: str = "all", profile: str = "",
                            since: str | None = None, until: str | None = None,
                            keyword: str = "", limit: int = 0,
                            all_drives: bool = False) -> Any:
        """全量导出 CSV（UTF-8-SIG，Excel 直接打开）。"""
        from memlens.core import browser_history as bh
        import io as _io
        visits = bh.collect(browser=browser, profile=profile, since=since,
                            until=until, keyword=keyword, limit=limit,
                            all_drives=all_drives)
        buf = _io.StringIO()
        import csv as _csv
        w = _csv.writer(buf)
        cols = ["浏览器", "Profile", "访问时间", "标题", "URL", "访问类型", "累计次数"]
        if all_drives:
            cols.append("来源盘")
        w.writerow(cols)
        for v in visits:
            row = [v.browser, v.profile, v.visited_at, v.title, v.url,
                   v.transition, v.visit_count]
            if all_drives:
                row.append(v.source)
            w.writerow(row)
        return PlainTextResponse("\ufeff" + buf.getvalue(),
                                 headers={"Content-Disposition":
                                          'attachment; filename="browser_history.csv"'})

    # ------------------------------------------------------------ 五维判定（FR-01~FR-07）
    @app.post("/api/cases/{case_id}/dimensions")
    def run_dimensions(case_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        跑五维判定（违规跨境访问检测模块）。

        `usage`：`check`（检查用法三档）/ `forensic`（取证用法 A/B/C 级）
        `allow_direction`：是否启用访问方向维度（方案要求默认关闭、需单独授权）
        """
        from memlens.detectors.base import DetectionContext
        from memlens.dimensions import evaluate

        case = STATE.store.get_case(case_id)
        if not case:
            raise HTTPException(404, "案件不存在")
        body = payload or {}
        usage = str(body.get("usage") or "check").lower()
        allow_dir = bool(body.get("allow_direction", False))
        try:
            ctx = DetectionContext(STATE.store, case_id)
            verdict = evaluate(ctx, usage=usage, allow_direction=allow_dir)
        except Exception as exc:
            raise HTTPException(500, f"五维判定失败：{exc}")
        STATE.store.save_dimension_results(case_id, verdict)
        try:
            STATE.store.add_audit(actor="operator", action="dimension_eval",
                                  target=case_id, case_id=case_id, critical=True,
                                  detail=f"五维判定（{usage}，总分 {verdict.total:.3f}，"
                                         f"{verdict.tier if usage == 'check' else verdict.level}）")
        except Exception:
            pass
        return verdict.to_dict()

    @app.get("/api/cases/{case_id}/dimensions")
    def get_dimensions(case_id: str) -> dict[str, Any]:
        """取上次五维判定结果。"""
        rows = STATE.store.list_dimension_results(case_id)
        if not rows:
            return {"dimensions": [], "total": 0.0, "usage": "", "tier": "",
                    "level": "", "level_cap": "", "notes": [],
                    "rulepack_version": "", "rulepack_sha256": ""}
        first = rows[0]
        return {
            "dimensions": rows,
            "total": first.get("total", 0.0),
            "usage": first.get("usage", ""),
            "tier": first.get("tier", ""),
            "level": first.get("level", ""),
            "level_cap": first.get("overall_level_cap", ""),
            "rulepack_version": first.get("rulepack_version", ""),
            "rulepack_sha256": first.get("rulepack_sha256", ""),
            "notes": [],
        }

    # ------------------------------------------------------------ 规则包（FR-21）
    @app.get("/api/rulepack")
    def rulepack_info() -> dict[str, Any]:
        """当前生效规则包 + 目录里的全部版本（离线，不联网）。"""
        from memlens.core import rulepack as rp
        return {"current": rp.summary(), "packs": rp.manager().list_packs()}

    @app.post("/api/rulepack/import")
    def rulepack_import(payload: dict[str, Any]) -> dict[str, Any]:
        """导入离线规则包（文件路径 + 是否立即激活）。"""
        from memlens.core import rulepack as rp
        path = str(payload.get("path") or "").strip()
        if not path:
            raise HTTPException(400, "缺少 path（规则包 JSON 的绝对路径）")
        activate = bool(payload.get("activate", True))
        try:
            pk = rp.manager().import_pack(path, activate=activate)
        except Exception as exc:
            raise HTTPException(400, f"规则包导入失败：{exc}")
        STATE.store.upsert_rule_pack(pk.to_dict())
        STATE.store.add_audit(actor="operator", action="rulepack_import",
                              target=path, critical=True,
                              after_hash=pk.sha256,
                              detail=f"导入规则包 {pk.version}")
        return {"ok": True, "activated": activate, "pack": pk.to_dict()}

    @app.post("/api/rulepack/activate")
    def rulepack_activate(payload: dict[str, Any]) -> dict[str, Any]:
        """切换生效版本 / 回滚到历史版本。"""
        from memlens.core import rulepack as rp
        pack_id = str(payload.get("pack_id") or "").strip()
        if not pack_id:
            raise HTTPException(400, "缺少 pack_id")
        try:
            pk = rp.manager().rollback(pack_id)
        except Exception as exc:
            raise HTTPException(400, f"切换失败：{exc}")
        STATE.store.upsert_rule_pack(pk.to_dict())
        STATE.store.add_audit(actor="operator", action="rulepack_activate",
                              target=pack_id, critical=True,
                              after_hash=pk.sha256,
                              detail=f"生效规则包切换为 {pk.version}")
        return {"ok": True, "pack": pk.to_dict()}

    # ------------------------------------------------------------ 审计与缺口（FR-19 / 表 9）
    @app.get("/api/cases/{case_id}/audit")
    def case_audit(case_id: str, limit: int = Query(500, ge=1, le=5000),
                   critical_only: bool = False) -> dict[str, Any]:
        """审计记录 + 哈希链校验结果（方案 5.4）。"""
        rows = STATE.store.list_audit(case_id=case_id, limit=limit,
                                      critical_only=critical_only)
        chain = STATE.store.verify_audit_chain(case_id=case_id)
        return {"entries": rows, "chain": chain}

    @app.get("/api/cases/{case_id}/gaps")
    def case_gaps(case_id: str, dimension: str | None = None,
                  status: str | None = None) -> dict[str, Any]:
        """缺口清单（方案表 9：缺失维度 / 原因 / 建议补证）。"""
        rows = STATE.store.list_gaps(case_id, dimension=dimension, status=status)
        return {"gaps": rows, "count": len(rows)}

    # ------------------------------------------------------------ 服务端文件浏览
    @app.get("/api/vmscan")
    def vm_scan(paths: str = "", depth: int = 4, deep: bool = False,
                max_gb: float = 8.0) -> dict[str, Any]:
        """
        虚拟机取证扫描（只读）：VM 资产发现 + .vmx 配置取证 + 磁盘里的 flag/私钥。

        这是**内存之外**的取证盲区：VM 配置里常有明文口令/共享文件夹/剪贴板开关，
        磁盘里常躺 flag 与私钥。返回结构与 CLI `vmscan` 一致。
        """
        from memlens.core import vmscan as vm
        raw = [p for p in (paths or "").split(";") if p.strip()]
        if not raw:
            raw = [str(Path.home())]
        vms = vm.discover(raw, max_depth=max(1, min(int(depth), 8)))
        disk_hits: list = []
        for v in vms:
            if v.config:
                v.findings.extend(vm.parse_vmware_config(v.config))
            if deep and v.disks:
                for d in v.disks:
                    disk_hits.extend(vm.scan_disk_for_secrets(
                        [d], max_bytes=int(float(max_gb) * (1 << 30))))
        return {"summary": vm.summarize(vms, disk_hits),
                "next_steps": vm.next_steps(vms, disk_hits)}

    @app.get("/api/fs/list")
    def fs_list(path: str = "") -> dict[str, Any]:
        """服务端文件浏览（工具跑在本机，因此可以直接浏览本机磁盘）。"""
        try:
            p = Path(path) if path else Path.home()
            if not p.exists():
                raise HTTPException(400, f"路径不存在：{path}")
            if p.is_file():
                p = p.parent
            entries = []
            try:
                for child in sorted(p.iterdir(), key=lambda x: (x.is_file(), x.name.lower())):
                    try:
                        st = child.stat()
                    except OSError:
                        continue
                    entries.append({
                        "name": child.name,
                        "path": str(child),
                        "is_dir": child.is_dir(),
                        "size": 0 if child.is_dir() else st.st_size,
                        "mtime": st.st_mtime,
                    })
            except PermissionError:
                raise HTTPException(403, "无权限访问该目录")
            drives = []
            if os.name == "nt":
                for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                    root = f"{letter}:\\"
                    if os.path.exists(root):
                        drives.append(root)
            return {
                "path": str(p),
                "parent": str(p.parent) if p.parent != p else None,
                "entries": entries,
                "drives": drives,
            }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(500, str(exc))

    # ------------------------------------------------------------ WebSocket
    @app.websocket("/ws/case/{case_id}")
    async def ws_case(websocket: WebSocket, case_id: str) -> None:
        await websocket.accept()
        q = STATE.bus.subscribe(case_id)
        try:
            await websocket.send_json({"type": "hello", "payload": {"case_id": case_id}})
            import time as _time
            last_ping = _time.time()
            while True:
                # ★ 用 `asyncio.to_thread` 从**线程安全队列**取消息：
                #   生产者在后台线程（分析线程），消费者在这里（事件循环协程）。
                #   直接 `await q.get()`（asyncio.Queue）会丢第一条事件 —— 已实测。
                try:
                    message = await asyncio.to_thread(q.get, True, 1.0)
                except Exception:
                    # 队列空：只是心跳检查，**不要每次都发 ping**
                    # （否则前端每秒收到一条心跳，白白刷屏）
                    if _time.time() - last_ping > 20:
                        last_ping = _time.time()
                        await websocket.send_json({"type": "ping", "payload": {}})
                    continue
                await websocket.send_json(message)
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            STATE.bus.unsubscribe(case_id, q)

    # ------------------------------------------------------------ 镜像挂载 / 雕刻 / 哈希（新增）
    import uuid as _uuid

    _MOUNTS: dict[str, Any] = {}

    @app.post("/api/mount/open")
    def mount_open(payload: dict[str, Any]) -> dict[str, Any]:
        from memlens.formats.mount import ImageMount
        path = payload.get("path", "")
        if not path:
            raise HTTPException(400, "缺少 path")
        try:
            m = ImageMount.open(path, payload.get("password", ""))
        except Exception as exc:
            raise HTTPException(400, f"打开失败：{type(exc).__name__}: {exc}")
        mid = _uuid.uuid4().hex[:12]
        _MOUNTS[mid] = m
        return {"id": mid, **m.summary()}

    @app.get("/api/mount/{mid}")
    def mount_get(mid: str) -> dict[str, Any]:
        m = _MOUNTS.get(mid)
        if m is None:
            raise HTTPException(404, "挂载不存在")
        return {"id": mid, **m.summary()}

    @app.delete("/api/mount/{mid}")
    def mount_close(mid: str) -> dict[str, Any]:
        _MOUNTS.pop(mid, None)
        return {"ok": True}

    @app.get("/api/mount/{mid}/tree")
    def mount_tree(mid: str, vol: int = 1, limit: int = 2000) -> dict[str, Any]:
        m = _MOUNTS.get(mid)
        if m is None:
            raise HTTPException(404, "挂载不存在")
        v = next((x for x in m.volumes if x.index == vol), None)
        if v is None:
            raise HTTPException(404, f"卷 {vol} 不存在")
        return {"vol": vol, "fs": v.fs_type, "summary": v.summary(),
                "tree": v.tree(max_entries=limit)}

    @app.get("/api/mount/{mid}/read")
    def mount_read(mid: str, vol: int = 1, path: str = "") -> Any:
        m = _MOUNTS.get(mid)
        if m is None:
            raise HTTPException(404, "挂载不存在")
        v = next((x for x in m.volumes if x.index == vol), None)
        if v is None:
            raise HTTPException(404, f"卷 {vol} 不存在")
        try:
            data = v.read(path)
        except Exception as exc:
            raise HTTPException(400, f"读取失败：{exc}")
        return Response(content=data, media_type="application/octet-stream")

    @app.post("/api/mount/{mid}/extract")
    def mount_extract(mid: str, payload: dict[str, Any]) -> dict[str, Any]:
        m = _MOUNTS.get(mid)
        if m is None:
            raise HTTPException(404, "挂载不存在")
        vol = int(payload.get("vol", 1))
        v = next((x for x in m.volumes if x.index == vol), None)
        if v is None:
            raise HTTPException(404, f"卷 {vol} 不存在")
        path = payload.get("path", "")
        out = payload.get("out", "")
        if not out:
            out = str(_project_root() / "work" / "extracted" / f"{mid}_{path.replace('/', '_')}")
        try:
            dst = v.extract(path, out)
        except Exception as exc:
            raise HTTPException(400, f"提取失败：{exc}")
        return {"path": str(dst), "size": dst.stat().st_size}

    @app.post("/api/mount/{mid}/carve")
    def mount_carve(mid: str, payload: dict[str, Any]) -> dict[str, Any]:
        m = _MOUNTS.get(mid)
        if m is None:
            raise HTTPException(404, "挂载不存在")
        vol = int(payload.get("vol", 1))
        v = next((x for x in m.volumes if x.index == vol), None)
        if v is None:
            raise HTTPException(404, f"卷 {vol} 不存在")
        names = [x.strip() for x in (payload.get("rules") or "").split(",") if x.strip()]
        hits = v.carve(names, offset=int(payload.get("offset", 0) or 0),
                       length=int(payload.get("length", 0) or 0))
        return {"vol": vol, "hits": hits, "count": len(hits)}

    @app.get("/api/mount/{mid}/search")
    def mount_search(mid: str, vol: int = 0, keyword: str = "",
                     encodings: str = "", limit: int = 200) -> dict[str, Any]:
        m = _MOUNTS.get(mid)
        if m is None:
            raise HTTPException(404, "挂载不存在")
        from memlens.core.fulltext import search_image
        encs = [x.strip() for x in encodings.split(",") if x.strip()] or None
        hits = search_image(m, keyword, vol, encs, limit)
        return {"keyword": keyword, "hits": hits, "count": len(hits)}

    @app.post("/api/evidence")
    def evidence_add(payload: dict[str, Any]) -> dict[str, Any]:
        from memlens.core.evidence import EvidenceStore
        path = payload.get("path", "")
        if not path:
            raise HTTPException(400, "缺少 path")
        try:
            from memlens.formats.mount import ImageMount
            m = ImageMount.open(path, payload.get("password", ""))
            store = EvidenceStore(str(_project_root() / "work" / "evidence.json"))
            rec = store.add(path, kind=m.kind, size=m.size,
                            volumes=[v.summary() for v in m.volumes],
                            note=payload.get("note", ""))
        except Exception as exc:
            raise HTTPException(400, f"登记失败：{exc}")
        return rec

    @app.get("/api/evidence")
    def evidence_list() -> dict[str, Any]:
        from memlens.core.evidence import EvidenceStore
        store = EvidenceStore(str(_project_root() / "work" / "evidence.json"))
        return {"records": store.list()}

    @app.get("/api/evidence/verify")
    def evidence_verify() -> dict[str, Any]:
        from memlens.core.evidence import EvidenceStore
        store = EvidenceStore(str(_project_root() / "work" / "evidence.json"))
        ok, info = store.verify()
        return {"ok": ok, "info": info}

    @app.post("/api/carve")
    def carve_any(payload: dict[str, Any]) -> dict[str, Any]:
        from memlens.formats.mount import ImageMount
        path = payload.get("path", "")
        if not path:
            raise HTTPException(400, "缺少 path")
        try:
            m = ImageMount.open(path, payload.get("password", ""))
        except Exception as exc:
            raise HTTPException(400, f"打开失败：{exc}")
        if payload.get("vol"):
            v = next((x for x in m.volumes if x.index == int(payload["vol"])), None)
            if v is None:
                raise HTTPException(404, f"卷 {payload['vol']} 不存在")
            hits = v.carve([x.strip() for x in (payload.get("rules") or "").split(",") if x.strip()],
                           offset=int(payload.get("offset", 0) or 0),
                           length=int(payload.get("length", 0) or 0))
        else:
            from memlens.core.carver import carve_region
            fh = open(path, "rb")
            def _r(off, n):
                fh.seek(off)
                return fh.read(n)
            hits = [{"rule": h.rule, "start": h.start, "end": h.end, "size": h.size,
                     "note": h.note} for h in carve_region(
                         _r, 0, os.path.getsize(path),
                         [x.strip() for x in (payload.get("rules") or "").split(",") if x.strip()])]
        return {"hits": hits, "count": len(hits)}

    @app.post("/api/hash")
    def hash_file_route(payload: dict[str, Any]) -> dict[str, Any]:
        from memlens.core.hashing import hash_file
        path = payload.get("path", "")
        if not path:
            raise HTTPException(400, "缺少 path")
        algos = [a.strip() for a in (payload.get("algos") or "").split(",") if a.strip()] or None
        try:
            h = hash_file(path, algos)
        except Exception as exc:
            raise HTTPException(400, f"哈希失败：{exc}")
        return h

    return app


app = create_app()


# ------------------------------------------------------------------ 启动器


def serve(host: str = "127.0.0.1", port: int = 8765, *, open_browser: bool = True) -> int:
    """启动本地服务（桌面端入口用）。"""
    import threading
    import webbrowser

    try:
        import uvicorn
    except ImportError:
        print("未安装 uvicorn。请执行：python -m pip install \"uvicorn[standard]\" fastapi")
        return 127

    url = f"http://{host}:{port}/"
    print(f"[MemLens] 取证控制台：{url}")
    print("[MemLens] 按 Ctrl+C 退出")

    if open_browser:
        def _open() -> None:
            import time as _t
            _t.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass
        threading.Thread(target=_open, daemon=True).start()

    try:
        uvicorn.run(app, host=host, port=port, log_level="warning", access_log=False)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="MemLens Web 服务")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    sys.exit(serve(args.host, args.port, open_browser=not args.no_browser))
