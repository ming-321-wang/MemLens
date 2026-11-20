# -*- coding: utf-8 -*-
"""MemLens · 证据登记与保管链（新增 · CarveScope 同类能力）

轻量 JSON 证据清单（work/evidence.json）：登记镜像/检材 → 记容器类型、大小、
卷摘要、四算法哈希，并把每条记录哈希**链**到上一条（篡改自检）。

    EvidenceStore(path)     —— 读写 evidence.json
    add(...)                —— 登记一条（计算哈希 + 链式哈希）
    list()                  —— 全部记录
    verify()                —— 校验整条保管链（返回 (ok, 断点)）
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from memlens.core.hashing import hash_file, hash_bytes

DEFAULT_EVIDENCE = "work/evidence.json"


class EvidenceStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"version": 1, "records": [], "head_hash": ""}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {"version": 1, "records": [], "head_hash": ""}

    def _save(self, doc: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(doc, ensure_ascii=False, indent=2),
                             encoding="utf-8")

    @staticmethod
    def _record_hash(rec: dict[str, Any]) -> str:
        payload = {k: v for k, v in rec.items() if k != "rec_hash"}
        return hash_bytes(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"))["sha256"]

    def add(self, path: str, kind: str = "", size: int = 0,
            volumes: list[dict[str, Any]] | None = None,
            note: str = "", algos: list[str] | None = None) -> dict[str, Any]:
        """登记一条证据：计算哈希，链到上一条，写回。"""
        h = hash_file(path, algos)
        doc = self._load()
        prev_hash = doc.get("head_hash", "")
        rec = {
            "id": str(len(doc["records"]) + 1),
            "path": str(path),
            "kind": kind,
            "size": size,
            "volumes": volumes or [],
            "hashes": h,
            "note": note,
            "prev_hash": prev_hash,
            "registered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        rec["rec_hash"] = self._record_hash(rec)
        doc["records"].append(rec)
        doc["head_hash"] = rec["rec_hash"]
        self._save(doc)
        return rec

    def list(self) -> list[dict[str, Any]]:
        return self._load()["records"]

    def verify(self) -> tuple[bool, dict[str, Any]]:
        """校验保管链：逐条重算 rec_hash 并比对 prev 链接。"""
        doc = self._load()
        recs = doc["records"]
        for i, rec in enumerate(recs):
            calc = self._record_hash(rec)
            if calc != rec.get("rec_hash"):
                return False, {"id": rec["id"], "reason": f"记录哈希不符 {calc[:12]}≠{rec.get('rec_hash','')[:12]}"}
            if i == 0:
                if rec.get("prev_hash", "") != "":
                    return False, {"id": rec["id"], "reason": "首条 prev_hash 非空"}
            else:
                if rec.get("prev_hash") != recs[i - 1].get("rec_hash"):
                    return False, {"id": rec["id"], "reason": "链断裂"}
        if doc.get("head_hash", "") != (recs[-1]["rec_hash"] if recs else ""):
            return False, {"id": "-", "reason": "head_hash 与末条不符"}
        return True, {"count": len(recs)}


__all__ = ["EvidenceStore", "DEFAULT_EVIDENCE"]
