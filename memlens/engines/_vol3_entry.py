"""
Volatility 3 的薄入口脚本。

为什么要它：pip 安装 volatility3 后在 Windows 上生成的入口是 `vol.py.exe`，
不同版本/安装方式下文件名可能变化；用 `python <本文件>` 调 `volatility3.cli:main`
可以完全绕过这个差异，且保证使用的是 MemLens 自己虚拟环境里的解释器。
"""

import sys


def main() -> int:
    try:
        from volatility3.cli import main as vol_main
    except ImportError as exc:  # pragma: no cover
        sys.stderr.write(
            f"[MemLens] 无法导入 volatility3：{exc}\n"
            f"请在 MemLens 的虚拟环境里执行：python -m pip install volatility3\n"
        )
        return 127
    result = vol_main()
    return int(result) if isinstance(result, int) else 0


if __name__ == "__main__":
    sys.exit(main())
