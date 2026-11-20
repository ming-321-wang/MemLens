"""MemLens · Web 层（FastAPI 后端 + 纯前端 SPA）。"""

from __future__ import annotations

__all__ = ["create_app", "serve"]


def create_app():
    from memlens.web.app import create_app as _create
    return _create()


def serve(host: str = "127.0.0.1", port: int = 8765, *, open_browser: bool = True) -> int:
    from memlens.web.app import serve as _serve
    return _serve(host, port, open_browser=open_browser)
