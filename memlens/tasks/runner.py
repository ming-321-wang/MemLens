"""
MemLens · 任务执行器

一次"跑插件"的完整生命周期（这是整个工具的干路，务必稳定）：

    build_run → 登记 artifact(running) → 落盘原始输出 → 解析记录 → 批量入库
              → 标记 artifact(ok/failed) → 回传结果摘要

关键工程约定：
  * **原始输出必须落盘**（证据保全 + 可复现 + 便于排错），落盘文件再算一次 SHA-256；
  * **shell=False、参数数组**（永不拼接 shell 字符串）；
  * **失败要让上层知道**：returncode != 0 或解析异常 → status=failed + error 字段，
    绝不返回"空结果 + 成功状态"来假装没事；
  * 支持**取消**（协作式）与**超时**（强制 terminate）。
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from memlens.engines.base import EngineAdapter, OutputKind, PluginMeta, RunSpec
from memlens.storage.db import DataStore, sha256_file


@dataclasses.dataclass
class ExecutionResult:
    """一次执行的对外摘要。"""

    artifact_id: str
    plugin: str
    status: str                  # ok / failed / partial / cancelled
    rows: int = 0
    duration_ms: int = 0
    output_path: str | None = None
    error: str | None = None
    stderr_tail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class TaskCancelled(RuntimeError):
    pass


class TaskRunner:
    """绑定一个引擎与一个案件的数据流执行器。"""

    def __init__(
        self,
        store: DataStore,
        engine: EngineAdapter,
        *,
        workdir: str | os.PathLike,
        encoding: str = "utf-8",
    ) -> None:
        self.store = store
        self.engine = engine
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.encoding = encoding

    # ------------------------------------------------------------------ 路径


# ------------------------------------------------------------------ 路径
    # ------------------------------------------------------------------ 路径
    def _artifact_dir(self, case_id: str) -> Path:
        d = self.workdir / case_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    @staticmethod
    def _builtin_kwargs(fn: Callable[..., Any],
                        cancel_event: threading.Event | None,
                        on_progress: Callable[[int, int], None] | None = None,
                        total: int = 0,
                        on_line: Callable[[str], None] | None = None) -> dict[str, Any]:
        """
        内置引擎的可选能力协商。

        `analyze_file(path, plugin)` 是最小签名；支持长任务的内置引擎
        （如镜像字节扫描、MemProcFS 虚拟盘取证）可以额外声明
        `progress` / `cancel` / `log` 三个关键字参数，
        这里只传它**真正接受**的那些，因此老引擎零改动也能继续跑。

        `log` 的意义：MemProcFS 这类引擎的"过程信息"（启动、取证阶段、收获产物）
        必须能回传到界面日志里 —— 否则几十分钟的收集期用户在界面上什么都看不到，
        只会以为工具卡死了。
        """
        import inspect

        out: dict[str, Any] = {}
        try:
            params = inspect.signature(fn).parameters
        except (TypeError, ValueError):
            return out
        has_var_kw = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
        if "progress" in params or has_var_kw:
            # 字节扫描这类长任务的进度必须能回传界面，否则几 GB 镜像又是"看着像卡死"
            out["progress"] = (
                (lambda done, _t=total: on_progress(int(done), int(_t)))
                if on_progress else None
            )
        if "cancel" in params or has_var_kw:
            out["cancel"] = (lambda: bool(cancel_event and cancel_event.is_set()))
        if "log" in params or has_var_kw:
            out["log"] = (lambda text: on_line(str(text))) if on_line else None
        return out

    # ------------------------------------------------------------------ 执行
    @staticmethod
    def _accepts_params(fn) -> bool:
        """这个内置引擎的 analyze_file 是否接受第三个位置参数（params）？"""
        import inspect

        try:
            params = inspect.signature(fn).parameters
        except (TypeError, ValueError):
            return True
        if any(p.kind is inspect.Parameter.VAR_POSITIONAL for p in params.values()):
            return True
        positional = [
            p for p in params.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        return len(positional) >= 3

    def run_plugin(
        self,
        case_id: str,
        plugin: PluginMeta,
        params: dict[str, Any] | None = None,
        *,
        on_line: Callable[[str], None] | None = None,
        cancel_event: threading.Event | None = None,
        timeout: float | None = None,
        cache: bool = True,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> ExecutionResult:
        """
        执行一个插件并入库。

        Args:
            case_id: 案件 ID（必须已存在于 cases 表）
            plugin: 插件元信息
            params: 引擎参数（renderer / extra / offline / output_dir / timeout）
            on_line: 收到引擎 stderr/stdout 一行的回调（用于 GUI 实时输出）
            cancel_event: 置位后协作式取消（会 terminate 子进程）
            timeout: 秒；超时强制终止
            cache: True 时，若同参数产物已成功入库则直接返回（不重复跑）
        """
        case = self.store.get_case(case_id)
        if case is None:
            raise KeyError(f"案件不存在：{case_id}")

        # ---------- 缓存命中 ----------
        if cache:
            prev = self.store.find_artifact(case_id, self.engine.name, plugin.name, params)
            if prev and prev["status"] == "ok":
                return ExecutionResult(
                    artifact_id=prev["artifact_id"], plugin=plugin.name, status="ok",
                    rows=int(prev["row_count"] or 0), duration_ms=int(prev["duration_ms"] or 0),
                    output_path=prev["output_path"],
                )

        spec = self.engine.build_run(plugin, case["image_path"], params)
        artifact_id = self.store.start_artifact(
            case_id, self.engine.name, plugin.name,
            category=plugin.category, kind=plugin.kind.value, params=params, argv=spec.argv,
        )

        started = time.time()

        # ---- 分支：内置引擎（不走子进程，直接返回记录）----
        if hasattr(self.engine, "analyze_file"):
            try:
                image_size = os.path.getsize(case["image_path"])
            except OSError:
                image_size = 0
            call_kwargs = self._builtin_kwargs(self.engine.analyze_file, cancel_event,
                                               on_progress=on_progress, total=image_size,
                                               on_line=on_line)
            # ⚠ 内置引擎的 `analyze_file` 签名**不统一**：
            #     memstrings → (path, plugin, params=None, **kw)
            #     static    → (image, plugin)              ← 没有 params！
            #   以前这里硬传三个位置参数 ⇒ 静态引擎的 9 个插件**全部**报
            #   `analyze_file() takes 3 positional arguments but 4 were given`
            #   ⇒ 在"一键深度分析"里静态分析（PE/ELF/字符串/熵/依赖）**整层失效**，
            #   而且这个失败被记成普通 failed，不会有人注意到。
            #   现在按签名协商：只传它真正接受的参数。
            args = [case["image_path"], plugin]
            if self._accepts_params(self.engine.analyze_file):
                args.append(params)
            try:
                rows = self.store.add_records(
                    artifact_id,
                    self.engine.analyze_file(*args, **call_kwargs),
                )
                status = "ok" if rows else "partial"
                if rows == 0:
                    error = "未解析出任何记录（该产物为空，或镜像里没有对应数据）"
                else:
                    error = None
            except Exception as exc:
                status, rows, error = "failed", 0, f"解析失败：{exc}"
            duration_ms = int((time.time() - started) * 1000)
            self.store.finish_artifact(
                artifact_id, status=status, row_count=rows,
                duration_ms=duration_ms, error=error,
            )
            return ExecutionResult(
                artifact_id=artifact_id, plugin=plugin.name, status=status, rows=rows,
                duration_ms=duration_ms, error=error,
            )

        out_path = self._artifact_dir(case_id) / f"{artifact_id}_{plugin.name.replace('.', '_')}.jsonl"

        stdout_chunks: list[str] = []
        stderr_lines: list[str] = []
        cancelled = False
        error: str | None = None

        try:
            proc = subprocess.Popen(
                spec.argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding=self.encoding,
                errors="replace",
                bufsize=1,
                env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", **(spec.env or {})},
                shell=False,          # 永不使用 shell
            )
            stdout_lock = threading.Lock()

            def pump_stdout() -> None:
                assert proc.stdout is not None
                for line in proc.stdout:
                    with stdout_lock:
                        stdout_chunks.append(line)

            def pump_stderr() -> None:
                assert proc.stderr is not None
                for line in proc.stderr:
                    stderr_lines.append(line)
                    if on_line:
                        try:
                            on_line(line.rstrip("\n"))
                        except Exception:
                            pass

            t_out = threading.Thread(target=pump_stdout, daemon=True)
            t_err = threading.Thread(target=pump_stderr, daemon=True)
            t_out.start()
            t_err.start()

            # 等待（支持取消与超时）
            deadline = (started + timeout) if timeout else None
            while proc.poll() is None:
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    break
                if deadline and time.time() > deadline:
                    proc.kill()
                    error = f"执行超时（>{timeout:.0f}s）"
                    break
                time.sleep(0.1)

            t_out.join(timeout=5)
            t_err.join(timeout=5)
            returncode = proc.returncode if proc.returncode is not None else -1
            stdout = "".join(stdout_chunks)

            # 原始输出落盘（证据保全）
            try:
                out_path.write_text(stdout, encoding="utf-8")
                output_sha = sha256_file(out_path)
            except Exception as exc:
                output_sha = None
                error = error or f"原始输出落盘失败：{exc}"

            rows = 0
            if cancelled:
                status = "cancelled"
            elif returncode != 0:
                status = "failed"
                # ★ 诊断必须用**完整** stderr：vol3 的有效报错常在中间，
                #   只取尾部 400 字符会正好截掉它、只剩进度刷屏。
                error = error or _describe_failure(self.engine, returncode,
                                                  "".join(stderr_lines),
                                                  full_stderr="".join(stderr_lines))
            else:
                try:
                    if plugin.kind.is_tabular:
                        rows = self.store.add_records(artifact_id, self.engine.parse_records(spec, stdout, "".join(stderr_lines)))
                        status = "ok" if rows else "partial"
                        if rows == 0:
                            error = "引擎执行成功但未解析出任何记录（可能镜像不含该数据结构）"
                    else:
                        status = "ok"
                except Exception as exc:
                    status = "failed"
                    error = f"结果解析失败：{exc}"

        except Exception as exc:  # Popen 本身失败
            status, rows, error, output_sha = "failed", 0, f"启动引擎失败：{exc}", None

        duration_ms = int((time.time() - started) * 1000)
        self.store.finish_artifact(
            artifact_id, status=status, row_count=rows,
            output_path=str(out_path) if out_path.exists() else None,
            output_sha256=output_sha, duration_ms=duration_ms, error=error,
        )
        return ExecutionResult(
            artifact_id=artifact_id, plugin=plugin.name, status=status, rows=rows,
            duration_ms=duration_ms, output_path=str(out_path) if out_path.exists() else None,
            error=error, stderr_tail="".join(stderr_lines)[-600:],
        )

    # ------------------------------------------------------------- 批量执行
    def run_plugins(
        self,
        case_id: str,
        plugins: Sequence[PluginMeta],
        params: dict[str, Any] | None = None,
        *,
        on_event: Callable[[str, Any], None] | None = None,
        cancel_event: threading.Event | None = None,
        timeout: float | None = None,
        cache: bool = True,
    ) -> list[ExecutionResult]:
        """顺序执行多个插件（顺序执行更可控：并发跑多个 vol3 会互相抢 IO 与内存）。"""
        results: list[ExecutionResult] = []
        for idx, plugin in enumerate(plugins, 1):
            if cancel_event is not None and cancel_event.is_set():
                break
            if on_event:
                on_event("start", {"index": idx, "total": len(plugins), "plugin": plugin.name,
                                   "display": plugin.display})
            res = self.run_plugin(
                case_id, plugin, params, cancel_event=cancel_event, timeout=timeout,
                cache=cache,
                on_line=(lambda line, _p=plugin: on_event("line", {"plugin": _p.name, "line": line})) if on_event else None,
            )
            results.append(res)
            if on_event:
                on_event("done", {"index": idx, "total": len(plugins), "result": res})
        return results



# ------------------------------------------------------------------ 失败归一化
def _describe_failure(engine: Any, returncode: int, stderr_text: str,
                      *, full_stderr: str = "") -> str:
    """
    把引擎失败翻译成**归一化的失败原因**。

    为什么必须归一化（实测踩过）：
      · vol3 每个插件的 stderr 尾巴都带 `Progress: 23.33` 这类实时进度，
        逐插件看去是"几十个不同的错误"，实际是**同一个根因**（符号表缺失）。
      · 归一化后，缺口清单能把同一根因合并成一条「N 个产物受影响」，
        而不是让清单被几十条重复项冲垮；
      · 报告里的失败说明也从"一堆 stderr"变成"一句人话 + 可执行建议"。
    """
    text = full_stderr or stderr_text or ""
    diagnose = getattr(engine, "diagnose_failure", None)
    if callable(diagnose):
        try:
            hit = diagnose(text)
        except Exception:
            hit = None
        if hit:
            title, advice, _retry = hit
            first = (advice or "").splitlines()[0] if advice else ""
            return f"{title}" + (f"｜{first}" if first else "")
    # fallback：剥掉 Progress 刷屏与换行噪音，只留最后一行有信息量的内容
    lines = [ln.strip() for ln in (stderr_text or text).splitlines() if ln.strip()]
    lines = [ln for ln in lines if not ln.lower().startswith("progress:")]
    tail = lines[-1][:200] if lines else ""
    return f"引擎返回码 {returncode}" + (f"；{tail}" if tail else "")

