# -*- coding: utf-8 -*-
"""
验证打包产物是否真正可用（不是"能生成 exe"就算成功）。

五项检查：
  1. 产物结构：MemLens.exe + _internal 都存在
  2. 关键数据文件：schema.sql / memlens.ico / vol3 插件 是否被打进去
  3. **子进程模式**：`MemLens.exe --vol3-entry --help` 能打印 Volatility 3 版本
     —— 这是打包最容易失效的一环（sys.executable 在 frozen 下指向 exe）
  4. GUI 启动：offscreen 模式起进程，存活 N 秒不崩即视为通过
  5. 报告体积与文件数
"""
import os
import subprocess
import sys
import time
from pathlib import Path

DIST = Path(r"D:\MemLens\dist\MemLens")
EXE = DIST / "MemLens.exe"
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'OK  ' if cond else 'FAIL'} {name}" + (f"   [{detail}]" if detail else ""))


print("=" * 74)
print("1. 产物结构")
print("=" * 74)
check("MemLens.exe 存在", EXE.is_file(),
      f"{EXE.stat().st_size/1048576:.1f} MiB" if EXE.is_file() else "缺失")
internal = DIST / "_internal"
check("_internal 目录存在", internal.is_dir())
if internal.is_dir():
    files = list(internal.rglob("*"))
    nfile = sum(1 for f in files if f.is_file())
    total = sum(f.stat().st_size for f in files if f.is_file())
    print(f"       _internal: {nfile} 文件 / {total/1048576:.1f} MiB")
    # 整包体积
    allf = [f for f in DIST.rglob("*") if f.is_file()]
    print(f"       整包: {len(allf)} 文件 / "
          f"{sum(f.stat().st_size for f in allf)/1048576:.1f} MiB")

print()
print("=" * 74)
print("2. 关键数据文件")
print("=" * 74)
if internal.is_dir():
    schema = list(internal.rglob("schema.sql"))
    check("schema.sql 已打包", bool(schema),
          str(schema[0].relative_to(internal)) if schema else "缺失")
    ico = list(internal.rglob("memlens.ico"))
    check("memlens.ico 已打包", bool(ico))
    vol3dir = list(internal.rglob("volatility3"))
    check("volatility3 目录已打包", bool(vol3dir),
          str(vol3dir[0].relative_to(internal)) if vol3dir else "缺失")
    # vol3 插件数量（应 >100 个 windows/linux/mac 插件）
    win_plugins = list(internal.rglob("windows/*.pyd")) + list(internal.rglob("windows/*.pyc"))
    print(f"       vol3 windows 插件(.pyd/.pyc): {len(win_plugins)}")
    pyside = list(internal.rglob("PySide6"))
    check("PySide6 已打包", bool(pyside))
    # 精简效果：检查是否排除了 QtWebEngine
    webeng = list(internal.rglob("*WebEngine*"))
    check("QtWebEngine 已排除（精简生效）", len(webeng) == 0,
          f"仍残留 {len(webeng)} 个" if webeng else "无残留")

print()
print("=" * 74)
print("3. 子进程模式（打包后 vol3 调用链的关键）")
print("=" * 74)
if EXE.is_file():
    try:
        r = subprocess.run([str(EXE), "--vol3-entry", "--help"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=180,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = (r.stdout or "") + (r.stderr or "")
        ver = ""
        for line in out.splitlines():
            if "Volatility 3 Framework" in line:
                ver = line.strip()
                break
        check("exe 可作 vol3 入口（--vol3-entry）", bool(ver), ver or f"rc={r.returncode}")
        if not ver:
            print("      输出片段:", out[:400].replace("\n", " | "))
    except subprocess.TimeoutExpired:
        check("exe --vol3-entry 未超时", False, "180s 超时")
    except Exception as e:
        check("exe --vol3-entry 可调用", False, f"{type(e).__name__}: {e}")

print()
print("=" * 74)
print("4. GUI 启动（offscreen）")
print("=" * 74)
if EXE.is_file():
    env = dict(os.environ)
    env["QT_QPA_PLATFORM"] = "offscreen"
    try:
        p = subprocess.Popen([str(EXE)], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        time.sleep(18)
        alive = p.poll() is None
        if alive:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        err = b""
        try:
            err = p.stderr.read() or b""
        except Exception:
            pass
        check("GUI 进程存活 18s（未崩溃）", alive,
              "" if alive else f"退出码 {p.returncode}")
        if err:
            print("      stderr:", err.decode("utf-8", "replace")[:500].replace("\n", " | "))
    except Exception as e:
        check("GUI 可启动", False, f"{type(e).__name__}: {e}")

print()
print("=" * 74)
print(f"通过 {len(PASS)} / 失败 {len(FAIL)}")
if FAIL:
    print("失败项：", FAIL)
