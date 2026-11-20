"""
MemLens · 数据访问层（跨方言：SQLite / MySQL）

## 变更说明（v1.0）

v0.10 之前这里直接用 `sqlite3`，写死了 `?` 占位符、`AUTOINCREMENT`、
`executescript`、`TEXT`（MySQL 只有 64 KB）等 SQLite 方言细节。
本版把存储层换成 **SQLAlchemy Core**：

* 同一套模型同时跑 **SQLite（默认）** 与 **MySQL（可选）**；
* `records.data` 在 MySQL 上用 `LONGTEXT`（否则一行大记录会被静默截断）；
* 新增 **系统画像 / 时间线 / IOC / 词典命中 / 旗标 / 分析批次 / 笔记** 七张表，
  让"分析出来的所有信息"都有地方落，而不是只落日志。

## 对上层的契约（保持不变，老代码零改动）

`DataStore` 的方法签名与语义**完全沿用** v0.10：
`create_case / get_case / list_cases / find_artifact / start_artifact /
finish_artifact / list_artifacts / add_records / query_records /
records_of_plugin / records_with_source / count_records / export_records_csv /
add_finding / list_findings / clear_findings / stats`。

`store.conn` 仍可用（兼容老脚本的 `store.conn.execute("...?...")`），
内部会把 `?` 占位符翻译成 SQLAlchemy 的命名参数，因此 **SQLite 与 MySQL 都能跑**。
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

import sqlalchemy as sa
from sqlalchemy import and_, delete, func, insert, or_, select, update

from memlens.core import timebase
from memlens.storage import models as M


# ---------------------------------------------------------------- 兼容旧代码

def _find_schema() -> Path:
    """定位 schema.sql（保留给老工具脚本；新代码用 SQLAlchemy metadata）。"""
    here = Path(__file__).resolve().parent
    cands = [here / "schema.sql"]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        cands.append(Path(meipass) / "memlens" / "storage" / "schema.sql")
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        cands.append(exe_dir / "memlens" / "storage" / "schema.sql")
    for c in cands:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return cands[0]


SCHEMA_PATH = _find_schema()

#: 从异构记录里抽取"通用列"的候选键名（小写、去掉空格/下划线后比较）
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "pid": ("pid", "processid", "procid", "process", "pid_"),
    "ppid": ("ppid", "parentpid", "parentprocessid", "parent"),
    "name": ("imagefilename", "imagename", "name", "process", "processname",
             "owner", "filename", "service", "task", "module"),
    "ts": ("createtime", "created", "starttime", "time", "timestamp",
           "lastwritetime", "modified", "date"),
    "remote": ("foreignaddr", "remoteaddr", "remote", "dst", "destination", "peer"),
}


def _norm_key(key: str) -> str:
    return "".join(ch for ch in key.lower() if ch.isalnum())


def now_iso() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")


def sha256_file(path: str | os.PathLike, *, chunk: int = 1 << 20, limit: int | None = None) -> str:
    """
    计算文件哈希（大文件可分块；limit 用于只哈希前 N 字节的快速指纹场景）。

    ⚠ 真实踩过的坑（v1.0 修）：原实现写成
        `fp.read(chunk if chunk is None else min(chunk, limit - read))`
    —— 当 `limit is None`（**全文件哈希**，这才是默认路径）时，
    `min(chunk, None - read)` 直接抛
    `TypeError: unsupported operand type(s) for -: 'NoneType' and 'int'`。
    症状极具迷惑性：
      * `create_case` 里被 `except` 吞掉 → 案件的 `image_sha256` **静默为空**；
      * TaskRunner 落盘原始输出时抛 → 所有产物的 `output_path` 都是空
        （等于"证据保全"这一环整个失效）。
    现在按 limit 是否为 None 分支处理。
    """
    h = hashlib.sha256()
    read = 0
    with open(path, "rb") as fp:
        while True:
            if limit is not None and read >= limit:
                break
            want = chunk if limit is None else min(chunk, limit - read)
            block = fp.read(want)
            if not block:
                break
            h.update(block)
            read += len(block)
    return h.hexdigest()


def params_hash(engine: str, plugin: str, params: dict[str, Any] | None) -> str:
    """参数指纹：用于"同参数不重复执行"的缓存判定。"""
    payload = json.dumps({"engine": engine, "plugin": plugin, "params": params or {}},
                         sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


#: 来源偏移的候选键名（文件偏移 / 日志事件号 / 记录号）
OFFSET_ALIASES: tuple[str, ...] = (
    "offset", "offsethex", "fileoffset", "filenameoffset", "byteoffset",
    "address", "va", "eventid", "eventrecordid", "recordid", "recordnumber",
    "eventno", "logoffset", "position",
)


def extract_common_fields(record: dict[str, Any]) -> dict[str, Any]:
    """
    从一条异构记录里抽出通用索引列。

    策略：把记录的所有键归一化后，与 FIELD_ALIASES 中的候选名逐一比对；
    命中即取该键的值（并做类型转换：pid/ppid → int，其余 → 截断字符串）。

    ★ v1.3：同时抽取**方案 3.2 要求的中间证据表五必填字段**——
      发生时间（UTC 归一 + 原始表示 + 偏移量 + 换算留痕）、来源偏移、原始值哈希。
    """
    normalized: dict[str, Any] = {}
    for k, v in record.items():
        normalized.setdefault(_norm_key(str(k)), v)

    out: dict[str, Any] = {}
    for target, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                value = normalized[alias]
                break
        else:
            value = None
        if value in (None, "", "-"):
            value = None
        if target in ("pid", "ppid") and value is not None:
            try:
                value = int(str(value).split(".")[0])
            except (TypeError, ValueError):
                value = None
        if isinstance(value, str):
            value = value.strip()[:256]
        out[target] = value

    # ── 时间：统一归一到 UTC，并保留原始表示与偏移量（方案 5.3）──
    raw_ts = out.get("ts")
    tv = timebase.normalize(raw_ts, epoch=_epoch_for_field(normalized))
    if tv.ok:
        out["ts"] = tv.raw[:128] or None
        out["ts_utc"] = timebase.to_utc_iso_dt(tv.utc)
        out["ts_raw"] = tv.raw[:128]
        out["tz_offset"] = tv.offset
        out["tz_name"] = tv.tz_name[:64]
        out["tz_assumption"] = tv.assumption[:32]
        out["tz_note"] = tv.note[:256]
    else:
        out["ts_utc"] = None
        out["ts_raw"] = None
        out["tz_offset"] = None
        out["tz_name"] = None
        out["tz_assumption"] = None
        out["tz_note"] = None

    # ── 来源偏移（文件偏移 / 日志事件号）──
    offset = None
    for alias in OFFSET_ALIASES:
        if alias in normalized and normalized[alias] not in (None, "", "-"):
            offset = str(normalized[alias])[:64]
            break
    out["source_offset"] = offset

    # ── 原始值哈希（对该行"代表值"取哈希，保证可复核）──
    out["raw_value_hash"] = _value_hash(record)
    return out


def _epoch_for_field(normalized: dict[str, Any]) -> str | None:
    """按字段名判定纪元（浏览器 / FILETIME 等），不靠量级猜。"""
    for key, epoch in (("visittime", "webkit"), ("lastvisittime", "webkit"),
                       ("visitdate", "unix_us"), ("filetime", "filetime")):
        if key in normalized:
            return epoch
    return None


def _value_hash(record: dict[str, Any]) -> str | None:
    """
    原始值哈希：对该行中"最具代表性"的值取 SHA-256 前 16 位。

    代表值的选取顺序：偏移量 → 名称 → 时间 → 整行 JSON。
    这样同一份镜像、同一插件、同一行，重复分析得到的哈希**完全一致**
    （方案验收指标「同一输入两次运行零差异」）。
    """
    if not isinstance(record, dict) or not record:
        return None
    cand = None
    for k in ("Name", "ImageFileName", "name", "Process", "Url", "url",
              "Key", "Service", "Filename"):
        v = record.get(k)
        if v not in (None, ""):
            cand = f"{k}={v}"
            break
    if cand is None:
        cand = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(str(cand).encode("utf-8", "replace")).hexdigest()[:16]


# ---------------------------------------------------------------- 旧式 conn 兼容层

class _Row(dict):
    """兼容 sqlite3.Row 的字典式行（支持 `row["col"]` 与 `row.get`）。"""

    def __getitem__(self, key: str) -> Any:  # type: ignore[override]
        return dict.__getitem__(self, key)


class _LegacyCursor:
    """`store.conn.execute(...)` 的返回值：支持 fetchone / fetchall / lastrowid。"""

    def __init__(self, result: Any) -> None:
        self._result = result
        self.lastrowid: int | None = None
        self.rowcount: int = -1
        try:
            self.lastrowid = getattr(result, "lastrowid", None)
            self.rowcount = getattr(result, "rowcount", -1)
        except Exception:
            pass

    def fetchone(self) -> dict[str, Any] | None:
        try:
            row = self._result.fetchone()
        except Exception:
            return None
        if row is None:
            return None
        if isinstance(row, dict):
            return _Row(row)
        try:
            return _Row(row._mapping)
        except AttributeError:
            return _Row(dict(row))

    def fetchall(self) -> list[dict[str, Any]]:
        try:
            rows = self._result.fetchall()
        except Exception:
            return []
        out = []
        for r in rows:
            if isinstance(r, dict):
                out.append(_Row(r))
                continue
            try:
                out.append(_Row(r._mapping))
            except AttributeError:
                out.append(_Row(dict(r)))
        return out

    def __iter__(self):
        return iter(self.fetchall())


class _LegacyConn:
    """
    兼容层：让老脚本里的 `store.conn.execute("SELECT ... WHERE x=?", (v,))`
    在 SQLite 与 MySQL 上都能跑（把 `?` 翻译成 SQLAlchemy 命名参数）。
    """

    def __init__(self, store: "DataStore") -> None:
        self._store = store

    def execute(self, sql: str, params: Sequence[Any] | dict[str, Any] | None = None) -> _LegacyCursor:
        if isinstance(params, dict):
            bound = dict(params)
            text_sql = sql
        else:
            seq = list(params or ())
            parts = sql.split("?")
            if len(parts) - 1 != len(seq):
                # 数量不匹配时按原样尝试（保持旧行为：报参数错误而不是静默错位）
                bound = {f"p{i+1}": v for i, v in enumerate(seq)}
                text_sql = "".join(
                    p + (f":p{i+1}" if i < len(seq) else "") for i, p in enumerate(parts[:-1])
                ) + parts[-1]
            else:
                bound = {f"p{i+1}": v for i, v in enumerate(seq)}
                text_sql = "".join(
                    p + (f":p{i+1}" if i < len(seq) else "") for i, p in enumerate(parts[:-1])
                ) + parts[-1]
        with self._store.engine.begin() as conn:
            res = conn.execute(sa.text(text_sql), bound)
            # 需要把结果带出事务：先物化
            if res.returns_rows:
                rows = [dict(r._mapping) for r in res]
                return _LegacyCursor(_Materialized(rows))
            return _LegacyCursor(res)

    def commit(self) -> None:
        self._store.commit()

    def rollback(self) -> None:
        self._store.rollback()

    def close(self) -> None:
        pass

    def executescript(self, script: str) -> None:
        for stmt in script.split(";"):
            stmt = stmt.strip()
            if not stmt or stmt.startswith("--"):
                continue
            self.execute(stmt)

    def cursor(self) -> "_LegacyConn":
        return self


class _Materialized:
    """把已取出的行包装成可 fetch 的结果对象。"""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self._idx = 0

    def fetchone(self) -> dict[str, Any] | None:
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    def fetchall(self) -> list[dict[str, Any]]:
        rest = self._rows[self._idx:]
        self._idx = len(self._rows)
        return rest


# ---------------------------------------------------------------- DataStore


class DataStore:
    """统一证据模型的门面（SQLite / MySQL 通用）。"""

    def __init__(self, db_path: str | os.PathLike, *, url: str | None = None,
                 echo: bool = False, **engine_kw: Any) -> None:
        """
        Args:
            db_path: SQLite 文件路径（`url` 给了就忽略它）
            url:     完整 SQLAlchemy URL，例如
                     `mysql+pymysql://user:pw@127.0.0.1:3306/memlens?charset=utf8mb4`
                     `sqlite:///D:/MemLens/work/memlens.db`
        """
        self.db_path = Path(db_path)
        if url:
            self.url = url
        else:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.url = f"sqlite:///{self.db_path.as_posix()}"

        self.engine = sa.create_engine(self.url, echo=echo, future=True, **engine_kw)
        self._legacy = _LegacyConn(self)
        self.init_schema()

    # ---------------------------------------------------------- 构造辅助
    @classmethod
    def from_url(cls, url: str, **kw: Any) -> "DataStore":
        """按 SQLAlchemy URL 打开（MySQL 走这条）。"""
        backend = url.split(":", 1)[0]
        path = Path(url.rsplit("/", 1)[-1]) if "sqlite" in backend else Path("memlens.db")
        return cls(path, url=url, **kw)

    @property
    def backend(self) -> str:
        """sqlite / mysql / postgresql …"""
        return self.engine.dialect.name

    @property
    def conn(self) -> _LegacyConn:
        """兼容层：老脚本的 `store.conn.execute(...)`。"""
        return self._legacy

    # ------------------------------------------------------------------ 基础
    def init_schema(self) -> None:
        M.create_all(self.engine)
        # 轻量迁移：给旧库补上新增的列（create_all 不会 ALTER 已存在的表）
        try:
            changed = M.migrate(self.engine)
            if changed:
                print(f"[MemLens] 数据库已升级，新增列：{', '.join(changed)}")
        except Exception as exc:
            print(f"[MemLens] 数据库迁移跳过：{exc}")
        # SQLite 专有性能设置（MySQL 无意义，故加方言判断）
        if self.engine.dialect.name == "sqlite":
            with self.engine.begin() as conn:
                conn.exec_driver_sql("PRAGMA journal_mode=WAL")
                conn.exec_driver_sql("PRAGMA synchronous=NORMAL")

    def commit(self) -> None:
        """兼容层用（SQLAlchemy 2.x 走 autocommit-per-transaction）。"""
        return None

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        try:
            self.engine.dispose()
        except Exception:
            pass

    def __enter__(self) -> "DataStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------ cases
    def create_case(
        self,
        name: str,
        image_path: str,
        *,
        container: str = "",
        os_type: str = "",
        os_confidence: float = 0.0,
        notes: str = "",
        hash_limit: int | None = None,
        allow_missing: bool = False,
    ) -> str:
        """
        建案件（自动计算镜像哈希；大镜像可用 hash_limit 只算前若干字节的快速指纹）。

        allow_missing=True 时允许目标文件不存在（用于自测/回放已归档案件）。
        """
        path = os.path.abspath(image_path)
        if not allow_missing:
            st = os.stat(path)
        else:
            try:
                st = os.stat(path)
            except OSError:
                class _Stub:  # 文件不在时的占位
                    st_size = 0
                    st_mtime = 0
                st = _Stub()
        case_id = uuid.uuid4().hex[:12]
        try:
            digest = sha256_file(path, limit=hash_limit)
            digest_note = "" if hash_limit is None else f"(前{hash_limit}字节)"
        except Exception:
            digest, digest_note = None, ""
        row = {
            "case_id": case_id,
            "name": name,
            "image_path": path,
            "image_sha256": (digest + digest_note) if digest else None,
            "image_size": st.st_size,
            "image_mtime": _dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "container": container,
            "os_type": os_type,
            "os_confidence": os_confidence,
            "notes": notes,
            "state": "created",
            "created_at": now_iso(),
            "updated_at": now_iso(),
        }
        with self.engine.begin() as conn:
            conn.execute(insert(M.cases).values(**row))
        return case_id

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(M.cases).where(M.cases.c.case_id == case_id)
            ).first()
            return dict(row._mapping) if row else None

    def list_cases(self) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(M.cases).order_by(M.cases.c.created_at.desc())
            ).all()
            return [dict(r._mapping) for r in rows]

    def update_case(self, case_id: str, **fields: Any) -> None:
        """更新案件字段（状态推进用）。"""
        if not fields:
            return
        fields["updated_at"] = now_iso()
        with self.engine.begin() as conn:
            conn.execute(update(M.cases).where(M.cases.c.case_id == case_id).values(**fields))

    # --------------------------------------------------------------- artifacts
    def find_artifact(self, case_id: str, engine: str, plugin: str, params: dict | None) -> dict | None:
        ph = params_hash(engine, plugin, params)
        with self.engine.connect() as conn:
            row = conn.execute(
                select(M.artifacts).where(
                    and_(M.artifacts.c.case_id == case_id,
                         M.artifacts.c.engine == engine,
                         M.artifacts.c.plugin == plugin,
                         M.artifacts.c.params_hash == ph)
                )
            ).first()
            return dict(row._mapping) if row else None

    def start_artifact(
        self, case_id: str, engine: str, plugin: str, *,
        category: str = "", kind: str = "table",
        params: dict | None = None, argv: Sequence[str] | None = None,
    ) -> str:
        """登记一次执行（状态 running）。同参数重复执行会覆盖旧记录（级联删掉旧 records）。"""
        ph = params_hash(engine, plugin, params)
        with self.engine.begin() as conn:
            old = conn.execute(
                select(M.artifacts.c.artifact_id).where(
                    and_(M.artifacts.c.case_id == case_id,
                         M.artifacts.c.engine == engine,
                         M.artifacts.c.plugin == plugin,
                         M.artifacts.c.params_hash == ph)
                )
            ).first()
            if old:
                conn.execute(delete(M.records).where(M.records.c.artifact_id == old[0]))
                conn.execute(delete(M.artifacts).where(M.artifacts.c.artifact_id == old[0]))
            artifact_id = uuid.uuid4().hex[:12]
            conn.execute(insert(M.artifacts).values(
                artifact_id=artifact_id, case_id=case_id, engine=engine, plugin=plugin,
                category=category, kind=kind, params_hash=ph,
                params_json=json.dumps(params or {}, ensure_ascii=False, default=str),
                argv_json=json.dumps(list(argv or []), ensure_ascii=False),
                status="running", started_at=now_iso(),
            ))
        return artifact_id

    def finish_artifact(
        self, artifact_id: str, *, status: str, row_count: int = 0,
        output_path: str | None = None, output_sha256: str | None = None,
        duration_ms: int | None = None, error: str | None = None,
    ) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                update(M.artifacts).where(M.artifacts.c.artifact_id == artifact_id).values(
                    status=status, row_count=row_count, output_path=output_path,
                    output_sha256=output_sha256, duration_ms=duration_ms,
                    error=error, finished_at=now_iso(),
                )
            )

    def list_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(M.artifacts).where(M.artifacts.c.case_id == case_id)
                .order_by(M.artifacts.c.started_at)
            ).all()
            return [dict(r._mapping) for r in rows]

    # ----------------------------------------------------------------- records
    def add_records(self, artifact_id: str, records: Iterable[dict[str, Any]], *, batch: int = 2000) -> int:
        """批量写入记录（返回写入条数）。JSON 用 ensure_ascii=False 保留中文可读性。"""
        buf: list[dict[str, Any]] = []
        row_no = 0
        total = 0
        for rec in records:
            common = extract_common_fields(rec)
            buf.append({
                "artifact_id": artifact_id,
                "row_no": row_no,
                "data": json.dumps(rec, ensure_ascii=False, default=str),
                "ts": common.get("ts"),
                "pid": common.get("pid"),
                "ppid": common.get("ppid"),
                "name": common.get("name"),
                "remote": common.get("remote"),
                # ★ v1.3：方案 3.2 中间证据表五必填字段
                "ts_utc": common.get("ts_utc"),
                "ts_raw": common.get("ts_raw"),
                "tz_offset": common.get("tz_offset"),
                "tz_name": common.get("tz_name"),
                "tz_assumption": common.get("tz_assumption"),
                "tz_note": common.get("tz_note"),
                "source_offset": common.get("source_offset"),
                "raw_value_hash": common.get("raw_value_hash"),
            })
            row_no += 1
            if len(buf) >= batch:
                total += self._flush_records(buf)
                buf.clear()
        if buf:
            total += self._flush_records(buf)
        return total

    def _flush_records(self, buf: list[dict[str, Any]]) -> int:
        with self.engine.begin() as conn:
            conn.execute(insert(M.records), buf)
        return len(buf)

    def query_records(
        self, *, artifact_id: str | None = None, case_id: str | None = None,
        keyword: str | None = None, limit: int = 500, offset: int = 0,
        order_by: str = "row_no",
    ) -> list[dict[str, Any]]:
        """按产物/案件查询记录，支持关键词模糊过滤（跨 data 全文 + name/pid）。"""
        stmt = (select(M.records, M.artifacts.c.plugin.label("plugin"),
                       M.artifacts.c.engine.label("engine"))
                .join(M.artifacts, M.artifacts.c.artifact_id == M.records.c.artifact_id))
        conds = []
        if artifact_id:
            conds.append(M.records.c.artifact_id == artifact_id)
        if case_id:
            conds.append(M.artifacts.c.case_id == case_id)
        if keyword:
            like = f"%{keyword}%"
            conds.append(or_(M.records.c.data.like(like), M.records.c.name.like(like)))
        if conds:
            stmt = stmt.where(and_(*conds))
        allowed = {"row_no": M.records.c.row_no, "pid": M.records.c.pid,
                   "ts": M.records.c.ts, "name": M.records.c.name}
        stmt = stmt.order_by(allowed.get(order_by, M.records.c.row_no)).limit(limit).offset(offset)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        out = []
        for r in rows:
            d = dict(r._mapping)
            try:
                d["parsed"] = json.loads(d["data"])
            except Exception:
                d["parsed"] = {}
            out.append(d)
        return out

    def records_of_plugin(self, case_id: str, plugin_like: str, *, limit: int = 200_000,
                          include_unfinished: bool = False) -> list[dict[str, Any]]:
        """
        取某个（类）插件产物的全部记录，直接返回解析后的 dict 列表。

        供检测器使用：plugin_like 用 SQL LIKE 语法，如 `%psscan%`。
        默认只取执行成功的产物（status in ok/partial），避免把失败的空结果当数据。
        """
        stmt = (select(M.records.c.data)
                .join(M.artifacts, M.artifacts.c.artifact_id == M.records.c.artifact_id)
                .where(and_(M.artifacts.c.case_id == case_id,
                            M.artifacts.c.plugin.like(plugin_like))))
        if not include_unfinished:
            stmt = stmt.where(M.artifacts.c.status.in_(["ok", "partial"]))
        stmt = stmt.order_by(M.records.c.row_no).limit(limit)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        out: list[dict[str, Any]] = []
        for r in rows:
            try:
                out.append(json.loads(r[0]))
            except Exception:
                continue
        return out

    def records_with_source(self, case_id: str, *, limit: int = 400_000,
                            include_unfinished: bool = False,
                            skip_plugins: Sequence[str] = ()) -> list[tuple[dict[str, Any], str]]:
        """
        取案件全部记录，并同时返回每条记录来自哪个插件。
        """
        stmt = (select(M.records.c.data.label("data"), M.artifacts.c.plugin.label("plugin"))
                .join(M.artifacts, M.artifacts.c.artifact_id == M.records.c.artifact_id)
                .where(M.artifacts.c.case_id == case_id))
        if not include_unfinished:
            stmt = stmt.where(M.artifacts.c.status.in_(["ok", "partial"]))
        for pfx in skip_plugins:
            stmt = stmt.where(M.artifacts.c.plugin.notlike(f"{pfx}%"))
        stmt = stmt.order_by(M.artifacts.c.started_at, M.records.c.row_no).limit(limit)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        out: list[tuple[dict[str, Any], str]] = []
        for r in rows:
            try:
                out.append((json.loads(r[0]), r[1]))
            except Exception:
                continue
        return out

    def count_records(self, *, artifact_id: str | None = None, case_id: str | None = None) -> int:
        with self.engine.connect() as conn:
            if artifact_id:
                c = conn.execute(
                    select(func.count()).select_from(M.records)
                    .where(M.records.c.artifact_id == artifact_id)
                ).scalar()
            elif case_id:
                c = conn.execute(
                    select(func.count()).select_from(M.records)
                    .join(M.artifacts, M.artifacts.c.artifact_id == M.records.c.artifact_id)
                    .where(M.artifacts.c.case_id == case_id)
                ).scalar()
            else:
                c = conn.execute(select(func.count()).select_from(M.records)).scalar()
        return int(c or 0)

    def export_records_csv(self, path: str | os.PathLike, *, artifact_id: str | None = None,
                           case_id: str | None = None) -> int:
        """
        导出 CSV。

        注意（工程教训）：字段里出现 NUL 字节时标准 csv 模块会抛
        `need to escape, but no escapechar set` —— 这里统一做二进制安全清洗，
        并对 writer 指定 escapechar，从根上避免"导出即丢结果"。
        """
        import csv

        rows = self.query_records(artifact_id=artifact_id, case_id=case_id, limit=1_000_000)
        if not rows:
            return 0
        keys: list[str] = []
        for r in rows:
            for k in r["parsed"].keys():
                if k not in keys:
                    keys.append(str(k))
        with open(path, "w", newline="", encoding="utf-8-sig") as fp:
            writer = csv.writer(fp, escapechar="\\", quoting=csv.QUOTE_MINIMAL)
            writer.writerow(keys)
            for r in rows:
                line = []
                for k in keys:
                    v = r["parsed"].get(k)
                    if isinstance(v, (bytes, bytearray)):
                        v = v.hex()
                    elif isinstance(v, (list, dict)):
                        v = json.dumps(v, ensure_ascii=False, default=str)
                    text = "" if v is None else str(v)
                    line.append(text.replace("\x00", "\\x00").replace("\r", "\\r").replace("\n", "\\n"))
                writer.writerow(line)
        return len(rows)

    # ---------------------------------------------------------------- findings
    def add_finding(
        self, case_id: str, *, title: str, detector: str = "", rule_id: str | None = None,
        description: str = "", severity: str = "medium", confidence: float = 0.0,
        sources: Sequence[str] | None = None, evidence: dict | None = None,
        category: str | None = None,
    ) -> int:
        with self.engine.begin() as conn:
            res = conn.execute(insert(M.findings).values(
                case_id=case_id, rule_id=rule_id, detector=detector, title=title,
                description=description, severity=severity, confidence=confidence,
                sources=json.dumps(list(sources or []), ensure_ascii=False),
                evidence=json.dumps(evidence or {}, ensure_ascii=False, default=str),
                category=category, status="open", created_at=now_iso(),
            ))
            return int(res.inserted_primary_key[0]) if res.inserted_primary_key else 0

    def list_findings(self, case_id: str, *, severity: str | None = None) -> list[dict[str, Any]]:
        stmt = select(M.findings).where(M.findings.c.case_id == case_id)
        if severity:
            stmt = stmt.where(M.findings.c.severity == severity)
        stmt = stmt.order_by(M.findings.c.confidence.desc(), M.findings.c.finding_id)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        out = []
        for r in rows:
            d = dict(r._mapping)
            for k in ("sources", "evidence"):
                try:
                    d[k] = json.loads(d[k]) if d[k] else ([] if k == "sources" else {})
                except Exception:
                    d[k] = [] if k == "sources" else {}
            out.append(d)
        return out

    def clear_findings(self, case_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(delete(M.findings).where(M.findings.c.case_id == case_id))

    # ------------------------------------------------------------ 系统画像
    def set_system_profile(self, case_id: str, profile: dict[str, Any],
                           sources: dict[str, Any] | None = None,
                           full: dict[str, Any] | None = None) -> None:
        """
        写入/覆盖系统画像（只写非空字段，避免把已有值洗成空）。

        Args:
            profile: **扁平**的字段表（`os_version` / `ram_total_bytes` / …），
                     会被写进对应的列，方便 SQL 直接查。
            sources: 字段 → 来源说明。
            full:    完整画像（含 fields/users/extra/warnings），
                     存进 `profile_json`；不传则用 profile 本身。
        """
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(M.system_profile).where(M.system_profile.c.case_id == case_id)
            ).first()
            current = dict(existing._mapping) if existing else {}
            merged = {k: v for k, v in current.items() if v not in (None, "")}
            for k, v in (profile or {}).items():
                if v not in (None, ""):
                    merged[k] = v
            merged["case_id"] = case_id
            merged["profile_json"] = json.dumps(full if full is not None else profile,
                                                ensure_ascii=False, default=str)
            merged["sources_json"] = json.dumps(sources or {}, ensure_ascii=False, default=str)
            merged["updated_at"] = now_iso()
            cols = {c.name for c in M.system_profile.c}
            values = {k: v for k, v in merged.items() if k in cols}
            if existing:
                conn.execute(update(M.system_profile)
                             .where(M.system_profile.c.case_id == case_id).values(**values))
            else:
                conn.execute(insert(M.system_profile).values(**values))

    def get_system_profile(self, case_id: str) -> dict[str, Any]:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(M.system_profile).where(M.system_profile.c.case_id == case_id)
            ).first()
            if not row:
                return {}
            d = dict(row._mapping)
            for k in ("profile_json", "sources_json"):
                try:
                    d[k] = json.loads(d[k]) if d[k] else {}
                except Exception:
                    d[k] = {}
            return d

    # ---------------------------------------------------------------- 五维判定结果
    def save_dimension_results(self, case_id: str, verdict: Any) -> int:
        """
        保存五维判定结果（方案表 9「判定结果」）。

        会先清掉该案件旧的维度结果（同参数不重复累积），
        再写入各维得分 + 汇总（总分/档位/等级/上限）+ 规则包版本。
        """
        dims = list(getattr(verdict, "dimensions", []) or [])
        with self.engine.begin() as conn:
            conn.execute(delete(M.dimension_results)
                         .where(M.dimension_results.c.case_id == case_id))
            if not dims:
                return 0
            rows = []
            ts = now_iso()
            for d in dims:
                dd = d.to_dict() if hasattr(d, "to_dict") else dict(d)
                rows.append({
                    "case_id": case_id,
                    "dimension": dd.get("dimension", ""),
                    "fr": dd.get("fr", ""),
                    "score": float(dd.get("score") or 0.0),
                    "state": dd.get("state", ""),
                    "level_cap": dd.get("level_cap", ""),
                    "usage": getattr(verdict, "usage", "check"),
                    "tier": getattr(verdict, "tier", ""),
                    "level": getattr(verdict, "level", ""),
                    "total": float(getattr(verdict, "total", 0.0) or 0.0),
                    "overall_level_cap": getattr(verdict, "level_cap", ""),
                    "evidence_refs_json": json.dumps(dd.get("evidence_refs") or [], ensure_ascii=False),
                    "sources_used_json": json.dumps(dd.get("sources_used") or [], ensure_ascii=False),
                    "sources_missing_json": json.dumps(dd.get("sources_missing") or [], ensure_ascii=False),
                    "findings_json": json.dumps(dd.get("findings") or [], ensure_ascii=False),
                    "gaps_json": json.dumps(dd.get("gaps") or [], ensure_ascii=False),
                    "rulepack_version": getattr(verdict, "rulepack_version", ""),
                    "rulepack_sha256": getattr(verdict, "rulepack_sha256", ""),
                    "created_at": ts,
                })
            conn.execute(insert(M.dimension_results), rows)
        return len(rows)

    def list_dimension_results(self, case_id: str) -> list[dict[str, Any]]:
        stmt = select(M.dimension_results).where(M.dimension_results.c.case_id == case_id)
        stmt = stmt.order_by(M.dimension_results.c.result_id.asc())
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        out = []
        for r in rows:
            d = dict(r._mapping)
            for k in ("evidence_refs_json", "sources_used_json",
                      "sources_missing_json", "findings_json", "gaps_json"):
                try:
                    d[k.replace("_json", "")] = json.loads(d[k]) if d.get(k) else []
                except Exception:
                    d[k.replace("_json", "")] = []
            out.append(d)
        return out

    def clear_dimension_results(self, case_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(delete(M.dimension_results)
                         .where(M.dimension_results.c.case_id == case_id))

    # ---------------------------------------------------------------- 审计（保管链）
    def add_audit(self, *, actor: str, action: str, target: str = "",
                  case_id: str | None = None, before_hash: str = "",
                  after_hash: str = "", detail: str = "",
                  critical: bool = False) -> dict[str, Any]:
        """
        追加一条审计记录并接上哈希链。

        方案 5.4：每条记录的哈希包含**前一条的哈希**，
        任意一条被改动，后续全部校验失败。

        Returns: 写入的记录（含 entry_hash / prev_hash）
        """
        ts = timebase.utc_now_iso()
        with self.engine.begin() as conn:
            prev = conn.execute(
                select(M.audit_log.c.entry_hash).order_by(M.audit_log.c.audit_id.desc()).limit(1)
            ).first()
            prev_hash = prev[0] if prev and prev[0] else ""
            payload = "|".join([
                actor or "", action or "", target or "", ts or "",
                case_id or "", before_hash or "", after_hash or "",
                detail or "", prev_hash or "",
            ])
            entry_hash = hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()
            row = {
                "case_id": case_id,
                "actor": actor[:128],
                "action": action[:64],
                "target": target[:512],
                "ts_utc": ts,
                "before_hash": before_hash[:128],
                "after_hash": after_hash[:128],
                "prev_hash": prev_hash[:128],
                "entry_hash": entry_hash,
                "critical": bool(critical),
                "detail": detail,
                "created_at": ts,
            }
            res = conn.execute(insert(M.audit_log), [row])
            try:
                pk = res.inserted_primary_key
                if pk:
                    row["audit_id"] = int(pk[0])
            except Exception:
                pass
        return row

    def list_audit(self, *, case_id: str | None = None, limit: int = 500,
                   critical_only: bool = False) -> list[dict[str, Any]]:
        stmt = select(M.audit_log)
        if case_id:
            stmt = stmt.where(M.audit_log.c.case_id == case_id)
        if critical_only:
            stmt = stmt.where(M.audit_log.c.critical.is_(True))
        stmt = stmt.order_by(M.audit_log.c.audit_id.desc()).limit(limit)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [dict(r._mapping) for r in rows]

    def verify_audit_chain(self, *, case_id: str | None = None) -> dict[str, Any]:
        """
        校验审计哈希链完整性。

        Returns: {"ok": bool, "total": n, "broken_at": audit_id | None, "detail": str}
        """
        # ★ 哈希链是**全局**的（每条记录的哈希包含前一条的哈希），
        #   所以校验必须走**全部记录**，不能按案件过滤——
        #   否则第一条被过滤掉的记录会让后续全部对不上（实测踩过）。
        stmt = select(M.audit_log).order_by(M.audit_log.c.audit_id.asc())
        with self.engine.connect() as conn:
            rows = [dict(r._mapping) for r in conn.execute(stmt).all()]
        case_rows = [r for r in rows
                     if case_id is None or (r.get("case_id") or "") == case_id]
        prev = ""
        for r in rows:
            payload = "|".join([
                r.get("actor") or "", r.get("action") or "", r.get("target") or "",
                r.get("ts_utc") or "", r.get("case_id") or "",
                r.get("before_hash") or "", r.get("after_hash") or "",
                r.get("detail") or "", prev or "",
            ])
            expect = hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()
            if (r.get("prev_hash") or "") != prev or (r.get("entry_hash") or "") != expect:
                return {"ok": False, "total": len(rows),
                        "case_total": len(case_rows),
                        "broken_at": r.get("audit_id"),
                        "detail": f"第 {r.get('audit_id')} 条审计记录校验失败"}
            prev = r.get("entry_hash") or ""
        return {"ok": True, "total": len(rows),
                "case_total": len(case_rows),
                "broken_at": None, "detail": "哈希链完整"}

    # ---------------------------------------------------------------- 缺口清单
    def add_gaps(self, case_id: str, gaps: Iterable[dict[str, Any]]) -> int:
        """批量写入缺口（方案表 9：缺口是独立实体，须结构化存储）。"""
        rows = []
        for g in gaps:
            rows.append({
                "case_id": case_id,
                "scope": str(g.get("scope") or "source")[:32],
                "dimension": str(g.get("dimension") or "")[:64],
                "source": str(g.get("source") or "")[:256],
                "reason": str(g.get("reason") or "")[:512],
                "impact": str(g.get("impact") or "downgrade")[:32],
                "level_cap": str(g.get("level_cap") or "")[:32],
                "suggestion": g.get("suggestion") or "",
                "evidence_ref": str(g.get("evidence_ref") or "")[:512],
                "status": str(g.get("status") or "open")[:32],
                "created_at": now_iso(),
            })
        if not rows:
            return 0
        with self.engine.begin() as conn:
            conn.execute(insert(M.gaps), rows)
        return len(rows)

    def list_gaps(self, case_id: str, *, dimension: str | None = None,
                  status: str | None = None) -> list[dict[str, Any]]:
        stmt = select(M.gaps).where(M.gaps.c.case_id == case_id)
        if dimension:
            stmt = stmt.where(M.gaps.c.dimension == dimension)
        if status:
            stmt = stmt.where(M.gaps.c.status == status)
        stmt = stmt.order_by(M.gaps.c.gap_id.asc())
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [dict(r._mapping) for r in rows]

    def clear_gaps(self, case_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(delete(M.gaps).where(M.gaps.c.case_id == case_id))

    # ---------------------------------------------------------------- 规则包
    def upsert_rule_pack(self, pack: dict[str, Any]) -> str:
        """登记一个规则包（版本号 + 发布日期 + 阈值 + 白名单 + 词表 + 变更记录）。"""
        pack_id = str(pack.get("pack_id") or pack.get("version") or "")
        if not pack_id:
            raise ValueError("规则包缺少版本号（pack_id / version）")
        row = {
            "pack_id": pack_id,
            "version": str(pack.get("version") or pack_id)[:32],
            "published_at": str(pack.get("published_at") or "")[:32],
            "status": str(pack.get("status") or "active")[:32],
            "source_path": str(pack.get("source_path") or "")[:1024],
            "sha256": str(pack.get("sha256") or "")[:128],
            "thresholds_json": json.dumps(pack.get("thresholds") or {}, ensure_ascii=False, default=str),
            "whitelist_json": json.dumps(pack.get("whitelist") or {}, ensure_ascii=False, default=str),
            "wordlist_json": json.dumps(pack.get("wordlist") or {}, ensure_ascii=False, default=str),
            "change_log": pack.get("change_log") or "",
            "activated_at": now_iso(),
            "created_at": now_iso(),
        }
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(M.rule_packs.c.pack_id).where(M.rule_packs.c.pack_id == pack_id)
            ).first()
            if existing:
                conn.execute(update(M.rule_packs)
                             .where(M.rule_packs.c.pack_id == pack_id)
                             .values(**{k: v for k, v in row.items() if k != "pack_id"}))
            else:
                conn.execute(insert(M.rule_packs), [row])
        return pack_id

    def active_rule_pack(self) -> dict[str, Any]:
        """当前生效的规则包（没有则空 dict）。"""
        with self.engine.connect() as conn:
            row = conn.execute(
                select(M.rule_packs).where(M.rule_packs.c.status == "active")
                .order_by(M.rule_packs.c.activated_at.desc()).limit(1)
            ).first()
        if not row:
            return {}
        d = dict(row._mapping)
        for k in ("thresholds_json", "whitelist_json", "wordlist_json"):
            try:
                d[k.replace("_json", "")] = json.loads(d[k]) if d.get(k) else {}
            except Exception:
                d[k.replace("_json", "")] = {}
        return d

    def list_rule_packs(self) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(M.rule_packs).order_by(M.rule_packs.c.activated_at.desc())
            ).all()
        return [dict(r._mapping) for r in rows]

    # ---------------------------------------------------------------- 时间线
    def add_timeline_events(self, case_id: str, events: Iterable[dict[str, Any]]) -> int:
        """
        写入时间线事件。

        ★ v1.3：时间一律以 **UTC** 入库（`ts` 存 UTC ISO 串），
        同时保留 `ts_local`（按原始偏移还原的目标机本地时间）与换算留痕，
        满足方案 5.3「统一 UTC 存储 + 保留原始时区与偏移量」。
        """
        rows = []
        for ev in events:
            rows.append({
                "case_id": case_id,
                "ts": ev.get("ts_utc") or ev.get("ts"),
                "ts_utc": ev.get("ts_utc") or ev.get("ts"),
                "ts_local": ev.get("ts_local"),
                "ts_raw": ev.get("ts_raw"),
                "tz_offset": ev.get("tz_offset"),
                "tz_name": ev.get("tz_name"),
                "tz_assumption": ev.get("tz_assumption"),
                "ts_epoch": ev.get("ts_epoch"),
                "source": ev.get("source", "")[:128],
                "category": ev.get("category", "")[:64],
                "title": (ev.get("title") or "")[:512],
                "detail": ev.get("detail"),
                "ref_plugin": (ev.get("ref_plugin") or "")[:256],
                "ref_row": ev.get("ref_row"),
                "created_at": now_iso(),
            })
        if not rows:
            return 0
        with self.engine.begin() as conn:
            conn.execute(insert(M.timeline_events), rows)
        return len(rows)

    def clear_timeline(self, case_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(delete(M.timeline_events).where(M.timeline_events.c.case_id == case_id))

    def query_timeline(self, case_id: str, *, limit: int = 500, offset: int = 0,
                       category: str | None = None, keyword: str | None = None,
                       order: str = "asc") -> list[dict[str, Any]]:
        stmt = select(M.timeline_events).where(M.timeline_events.c.case_id == case_id)
        if category:
            stmt = stmt.where(M.timeline_events.c.category == category)
        if keyword:
            like = f"%{keyword}%"
            stmt = stmt.where(or_(M.timeline_events.c.title.like(like),
                                  M.timeline_events.c.detail.like(like)))
        col = M.timeline_events.c.ts if order == "asc" else M.timeline_events.c.ts.desc()
        stmt = stmt.order_by(col, M.timeline_events.c.event_id).limit(limit).offset(offset)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [dict(r._mapping) for r in rows]

    # ------------------------------------------------------------------ 情报
    def add_iocs(self, case_id: str, rows: Iterable[dict[str, Any]]) -> int:
        payload = []
        for r in rows:
            payload.append({
                "case_id": case_id,
                "kind": (r.get("kind") or "other")[:32],
                "value": (r.get("value") or "")[:1024],
                "context": r.get("context"),
                "severity": (r.get("severity") or "info")[:16],
                "score": float(r.get("score") or 0.0),
                "source": (r.get("source") or "")[:256],
                "hits": int(r.get("hits") or 1),
                "first_seen": now_iso(),
            })
        if not payload:
            return 0
        with self.engine.begin() as conn:
            conn.execute(insert(M.iocs), payload)
        return len(payload)

    def list_iocs(self, case_id: str, *, kind: str | None = None,
                  limit: int = 1000) -> list[dict[str, Any]]:
        stmt = select(M.iocs).where(M.iocs.c.case_id == case_id)
        if kind:
            stmt = stmt.where(M.iocs.c.kind == kind)
        stmt = stmt.order_by(M.iocs.c.score.desc(), M.iocs.c.ioc_id).limit(limit)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        return [dict(r._mapping) for r in rows]

    def add_dict_hits(self, case_id: str, rows: Iterable[dict[str, Any]]) -> int:
        payload = []
        for r in rows:
            payload.append({
                "case_id": case_id,
                "dictionary": (r.get("dictionary") or "")[:128],
                "entry_id": (r.get("entry_id") or "")[:256],
                "label": (r.get("label") or "")[:512],
                "category": (r.get("category") or "")[:128],
                "severity": (r.get("severity") or "info")[:16],
                "value": r.get("value"),
                "context": r.get("context"),
                "source": (r.get("source") or "")[:256],
                "created_at": now_iso(),
            })
        if not payload:
            return 0
        with self.engine.begin() as conn:
            conn.execute(insert(M.dict_hits), payload)
        return len(payload)

    def list_dict_hits(self, case_id: str, *, limit: int = 2000) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(M.dict_hits).where(M.dict_hits.c.case_id == case_id)
                .order_by(M.dict_hits.c.hit_id).limit(limit)
            ).all()
        return [dict(r._mapping) for r in rows]

    # ------------------------------------------------------------------ 旗标
    def add_flags(self, case_id: str, rows: Iterable[dict[str, Any]]) -> int:
        payload = []
        for r in rows:
            payload.append({
                "case_id": case_id,
                "value": (r.get("value") or "")[:1024],
                "kind": (r.get("kind") or "")[:32],
                "offset": r.get("offset"),
                "context": r.get("context"),
                "source": (r.get("source") or "")[:256],
                "confidence": float(r.get("confidence") or 0.0),
                "created_at": now_iso(),
            })
        if not payload:
            return 0
        with self.engine.begin() as conn:
            conn.execute(insert(M.flags), payload)
        return len(payload)

    def list_flags(self, case_id: str, *, limit: int = 1000) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(M.flags).where(M.flags.c.case_id == case_id)
                .order_by(M.flags.c.confidence.desc(), M.flags.c.flag_id).limit(limit)
            ).all()
        return [dict(r._mapping) for r in rows]

    # ------------------------------------------------------------- 分析批次
    def upsert_run(self, run_id: str, case_id: str, **fields: Any) -> None:
        """
        登记/更新一次分析批次。

        ⚠ 真实踩过的坑（v1.0 修）：`summary_json` / `plan_json` 是 **JSON_TEXT** 列，
        直接把 dict 塞进去会被 SQLAlchemy 拒绝
        （SQLite: "Error binding parameter ... type dict is not supported"；
        MySQL: "expected str, dict found"）。
        更糟的是这个异常发生在 `analyze()` 的**收尾代码**里（try 块之外），
        会把一次**已经跑完 110 个产物**的分析直接顶成"进程崩溃"：
        产物与发现项都在库里，但状态是 failed、报告没生成、还看不到任何错误信息。
        现在统一 JSON 编码。
        """
        allowed = {c.name for c in M.analysis_runs.c}
        vals: dict[str, Any] = {"run_id": run_id, "case_id": case_id}
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k in ("plan_json", "summary_json") and not isinstance(v, (str, bytes, type(None))):
                v = json.dumps(v, ensure_ascii=False, default=str)
            vals[k] = v
        with self.engine.begin() as conn:
            row = conn.execute(
                select(M.analysis_runs.c.run_id).where(M.analysis_runs.c.run_id == run_id)
            ).first()
            if row:
                conn.execute(update(M.analysis_runs)
                             .where(M.analysis_runs.c.run_id == run_id).values(**vals))
            else:
                vals.setdefault("started_at", now_iso())
                conn.execute(insert(M.analysis_runs).values(**vals))

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(M.analysis_runs).where(M.analysis_runs.c.run_id == run_id)
            ).first()
            if not row:
                return {}
            d = dict(row._mapping)
            for k in ("plan_json", "summary_json"):
                try:
                    d[k] = json.loads(d[k]) if d[k] else {}
                except Exception:
                    d[k] = {}
            return d

    def list_runs(self, case_id: str | None = None, *, limit: int = 50) -> list[dict[str, Any]]:
        stmt = select(M.analysis_runs)
        if case_id:
            stmt = stmt.where(M.analysis_runs.c.case_id == case_id)
        stmt = stmt.order_by(M.analysis_runs.c.started_at.desc()).limit(limit)
        with self.engine.connect() as conn:
            rows = conn.execute(stmt).all()
        out = []
        for r in rows:
            d = dict(r._mapping)
            for k in ("plan_json", "summary_json"):
                try:
                    d[k] = json.loads(d[k]) if d[k] else {}
                except Exception:
                    d[k] = {}
            out.append(d)
        return out

    # ------------------------------------------------------------------ 笔记
    def add_note(self, case_id: str, body: str, *, tags: str = "", author: str = "") -> int:
        with self.engine.begin() as conn:
            res = conn.execute(insert(M.notes).values(
                case_id=case_id, body=body, tags=tags, author=author, created_at=now_iso()))
            return int(res.inserted_primary_key[0]) if res.inserted_primary_key else 0

    def list_notes(self, case_id: str, *, limit: int = 500) -> list[dict[str, Any]]:
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(M.notes).where(M.notes.c.case_id == case_id)
                .order_by(M.notes.c.created_at.desc()).limit(limit)
            ).all()
        return [dict(r._mapping) for r in rows]

    # -------------------------------------------------------------------- KV
    def kv_get(self, key: str, default: Any = None) -> Any:
        with self.engine.connect() as conn:
            row = conn.execute(select(M.kv.c.v).where(M.kv.c.k == key)).first()
            if not row:
                return default
            try:
                return json.loads(row[0]) if row[0] else default
            except Exception:
                return default

    def kv_set(self, key: str, value: Any) -> None:
        with self.engine.begin() as conn:
            row = conn.execute(select(M.kv.c.k).where(M.kv.c.k == key)).first()
            payload = json.dumps(value, ensure_ascii=False, default=str)
            if row:
                conn.execute(update(M.kv).where(M.kv.c.k == key)
                             .values(v=payload, updated_at=now_iso()))
            else:
                conn.execute(insert(M.kv).values(k=key, v=payload, updated_at=now_iso()))

    # ------------------------------------------------------------------- 统计
    def stats(self, case_id: str) -> dict[str, Any]:
        arts = self.list_artifacts(case_id)
        findings = self.list_findings(case_id)
        by_cat: dict[str, int] = {}
        for f in findings:
            key = f.get("severity") or "unknown"
            by_cat[key] = by_cat.get(key, 0) + 1
        with self.engine.connect() as conn:
            n_tl = conn.execute(
                select(func.count()).select_from(M.timeline_events)
                .where(M.timeline_events.c.case_id == case_id)).scalar()
            n_ioc = conn.execute(
                select(func.count()).select_from(M.iocs)
                .where(M.iocs.c.case_id == case_id)).scalar()
            n_dict = conn.execute(
                select(func.count()).select_from(M.dict_hits)
                .where(M.dict_hits.c.case_id == case_id)).scalar()
            n_flag = conn.execute(
                select(func.count()).select_from(M.flags)
                .where(M.flags.c.case_id == case_id)).scalar()
        return {
            "artifacts": len(arts),
            "records": self.count_records(case_id=case_id),
            "findings": len(findings),
            "findings_by_severity": by_cat,
            "timeline": int(n_tl or 0),
            "iocs": int(n_ioc or 0),
            "dict_hits": int(n_dict or 0),
            "flags": int(n_flag or 0),
        }
