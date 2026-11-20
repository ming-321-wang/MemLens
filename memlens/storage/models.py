"""
MemLens · 数据模型（SQLAlchemy Core，跨方言可移植）

## 为什么用 SQLAlchemy 而不是手写两套 SQL

取证工具的"证据库"要同时能落在 **SQLite（默认、零配置、随 exe 走）** 和
**MySQL（多人/多机共享、可远程检索）** 上。两者在下面这些地方天然不同：

| 差异点 | SQLite | MySQL | 本模块的处理 |
|---|---|---|---|
| ���位符 | `?` | `%s` | SQLAlchemy 自动按方言编译 |
| 自增主键 | `INTEGER PRIMARY KEY AUTOINCREMENT` | `INT AUTO_INCREMENT` | `autoincrement=True` 自动翻译 |
| 大文本 | `TEXT`（无上限） | `TEXT` 只有 **64 KB** | `Text().with_variant(LONGTEXT, "mysql")` |
| 建表 | `executescript` | 需逐条 | `metadata.create_all()` 自动 |
| JSON | 无原生类型 | `JSON` 原生 | 统一存 **TEXT（JSON 字符串）**，两个方言行为一致 |
| 布尔 | 0/1 | TINYINT(1) | `Boolean` 自动翻译 |
| 浮点 | REAL | DOUBLE | `Float` 自动翻译 |

> ⚠️ **`records.data` 用 MySQL `TEXT` 会截断**：一行记录的 JSON 很容易超过 64 KB
> （进程命令行、模块列表、YARA 命中）。这是"同一套代码换 MySQL 就丢数据"的经典坑，
> 所以这里显式用 `LONGTEXT` 变体。

## 表的职责

```
cases ──┬── artifacts ─── records          （证据四层：案件→产物→行）
        ├── system_profile                  （系统画像：版本/内存/CPU/开机时间…）
        ├── findings                        （发现项）
        ├── iocs / dict_hits                （情报命中）
        ├── timeline_events                 （统一时间线）
        ├── notes                           （人工笔记）
        └── analysis_runs                   （分析批次与进度）
kv                                          （全局设置，如当前数据库后端）
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import (
    Boolean,
    Column,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
)
from sqlalchemy.dialects.mysql import LONGTEXT

# ---------------------------------------------------------------- 通用类型

#: JSON 统一存文本。MySQL 用 LONGTEXT（TEXT 64KB 不够），SQLite 用 TEXT。
JSON_TEXT = Text().with_variant(LONGTEXT, "mysql")

#: 哈希/路径等可能较长的字符串
STR256 = String(256)
STR512 = String(512)
STR1024 = String(1024)
CASE_ID = String(64)

metadata = MetaData()


# ---------------------------------------------------------------- 案件

cases = Table(
    "cases",
    metadata,
    Column("case_id", CASE_ID, primary_key=True),
    Column("name", STR256, nullable=False),
    Column("image_path", String(1024), nullable=False),
    Column("image_sha256", STR512),
    Column("image_size", sa.BigInteger),
    Column("image_mtime", String(64)),
    Column("container", String(64)),             # raw/lime/avml/aff4/ewf/vmdk/vmem/dmp
    Column("container_detail", String(512)),           # 容器细节（格式版本、块大小…）
    Column("os_type", String(64)),                     # windows/linux/darwin/unknown
    Column("os_confidence", Float),
    Column("notes", Text),
    Column("state", String(32), default="created"),    # created/probing/analyzing/done/failed
    Column("tool_version", String(32)),
    Column("created_at", String(32), nullable=False),
    Column("updated_at", String(32)),
)

Index("idx_cases_created", cases.c.created_at)

# ---------------------------------------------------------------- 产物

artifacts = Table(
    "artifacts",
    metadata,
    Column("artifact_id", String(64), primary_key=True),
    Column("case_id", CASE_ID, nullable=False),
    Column("engine", String(64), nullable=False),
    Column("plugin", String(256), nullable=False),
    Column("category", String(64)),
    Column("kind", String(32), nullable=False),        # table/text/file_set/scalar
    Column("params_hash", String(64), nullable=False),
    Column("params_json", JSON_TEXT),
    Column("argv_json", JSON_TEXT),
    Column("status", String(32), nullable=False),      # running/ok/failed/partial/cancelled
    Column("row_count", Integer, default=0),
    Column("output_path", String(1024)),
    Column("output_sha256", String(128)),
    Column("duration_ms", Integer),
    Column("error", Text),
    Column("started_at", String(32)),
    Column("finished_at", String(32)),
    # 注意：MySQL 的唯一索引里 TEXT 不可用，所以这里全部定长
    sa.UniqueConstraint("case_id", "engine", "plugin", "params_hash", name="uq_artifact"),
)

Index("idx_artifacts_case", artifacts.c.case_id)
Index("idx_artifacts_plugin", artifacts.c.plugin)

# ---------------------------------------------------------------- 记录

records = Table(
    "records",
    metadata,
    Column("record_id", Integer, primary_key=True, autoincrement=True),
    Column("artifact_id", String(64), nullable=False),
    Column("row_no", Integer),
    Column("data", JSON_TEXT, nullable=False),          # 该行完整 JSON
    Column("ts", String(64)),                           # 抽取：时间（UTC ISO，v1.3 起）
    Column("pid", Integer),
    Column("ppid", Integer),
    Column("name", String(512)),
    Column("remote", String(512)),
    # ── v1.3：方案 3.2「中间证据表五必填字段」补齐 ──────────────────
    #   证据编号：record_id 即编号（已在库，报告与判定引用它）
    #   发生时间（UTC）：ts_utc；原始时间与偏移量同时留存
    Column("ts_utc", String(40)),                       # 归一后的 UTC（ISO，Z 结尾）
    Column("ts_raw", String(128)),                      # 未改写的原始时间表示
    Column("tz_offset", Integer),                       # 原始时区偏移（秒）
    Column("tz_name", String(64)),                      # 原始时区标识（UTC+08:00 等）
    Column("tz_assumption", String(32)),                # 采用的假设（utc/local/explicit_*/epoch_known）
    Column("tz_note", String(256)),                    # 换算留痕
    Column("source_offset", String(64)),               # 来源偏移（文件偏移/日志事件号）
    Column("raw_value_hash", String(64)),               # 原始值哈希（SHA-256 前 16 位）
    Column("channel", String(32)),                     # 采集通道（image/online/browser/vmscan）
    Column("anti_cleanup", String(32)),                # 抗清理性（high/medium/low）
    Column("evidence_no", String(64)),                  # 对外证据编号（E-000001 形式）
)

Index("idx_records_artifact", records.c.artifact_id)
Index("idx_records_ts", records.c.ts)
Index("idx_records_ts_utc", records.c.ts_utc)
Index("idx_records_pid", records.c.pid)
Index("idx_records_name", records.c.name)
Index("idx_records_evidence_no", records.c.evidence_no)

# ---------------------------------------------------------------- 规则

rules = Table(
    "rules",
    metadata,
    Column("rule_id", String(128), primary_key=True),
    Column("name", STR256, nullable=False),
    Column("category", String(64)),
    Column("detector", String(128), nullable=False),
    Column("params_json", JSON_TEXT),
    Column("severity", String(16), default="medium"),
    Column("weight", Float, default=1.0),
    Column("reason", Text),
    Column("enabled", Boolean, default=True),
)

# ---------------------------------------------------------------- 发现项

findings = Table(
    "findings",
    metadata,
    Column("finding_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", CASE_ID, nullable=False),
    Column("rule_id", String(128)),
    Column("detector", String(128)),
    Column("title", String(512), nullable=False),
    Column("description", Text),
    Column("severity", String(16), default="medium"),
    Column("confidence", Float, default=0.0),
    Column("sources", JSON_TEXT),
    Column("evidence", JSON_TEXT),
    Column("category", String(64)),
    Column("status", String(32), default="open"),
    Column("created_at", String(32), nullable=False),
)

Index("idx_findings_case", findings.c.case_id)
Index("idx_findings_sev", findings.c.severity)

# ---------------------------------------------------------------- 系统画像

#: 系统画像：用户最关心的"系统信息 / 版本 / 内存大小"落在这里。
#: 一次一行（按 case_id 主键），profile_json 里放全部归一化字段与来源。
system_profile = Table(
    "system_profile",
    metadata,
    Column("case_id", CASE_ID, primary_key=True),
    Column("os_family", String(32)),        # windows / linux / darwin / unknown
    Column("os_name", String(256)),
    Column("os_version", String(256)),
    Column("build", String(128)),
    Column("architecture", String(64)),
    Column("kernel", String(512)),
    Column("hostname", String(256)),
    Column("username", String(256)),
    Column("cpu_model", String(512)),
    Column("cpu_cores", Integer),
    Column("ram_total_bytes", sa.BigInteger),
    Column("ram_free_bytes", sa.BigInteger),
    Column("ram_used_bytes", sa.BigInteger),
    Column("boot_time", String(64)),
    Column("uptime_seconds", sa.BigInteger),
    Column("timezone", String(128)),
    Column("install_date", String(64)),
    Column("machine_id", String(256)),
    Column("security_id", String(256)),
    Column("product_id", String(256)),
    Column("system_drive", String(32)),
    Column("registered_owner", String(256)),
    Column("organization", String(256)),
    Column("computer_name", String(256)),
    Column("domain", String(256)),
    Column("container", String(64)),
    Column("image_size", sa.BigInteger),
    Column("image_sha256", String(512)),
    Column("profile_json", JSON_TEXT),      # 全部字段（含未归一化的补充信息）
    Column("sources_json", JSON_TEXT),      # 每个字段来自哪个产物
    Column("updated_at", String(32)),
)

# ---------------------------------------------------------------- 时间线

timeline_events = Table(
    "timeline_events",
    metadata,
    Column("event_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", CASE_ID, nullable=False),
    Column("ts", String(64)),               # ★ v1.3：统一存 UTC ISO 串
    Column("ts_epoch", Float),
    # ── v1.3：原始时间与时区留存（方案 5.3）──
    Column("ts_utc", String(40)),           # UTC（与 ts 同值，便于显式引用）
    Column("ts_local", String(40)),         # 按原始偏移还原的目标机本地时间
    Column("ts_raw", String(128)),          # 未改写的原始时间表示
    Column("tz_offset", Integer),           # 原始时区偏移（秒）
    Column("tz_name", String(64)),          # 原始时区标识
    Column("tz_assumption", String(32)),    # 采用的假设
    Column("source", String(128)),          # 来自哪个插件
    Column("category", String(64)),         # 进程/网络/注册表/文件/线程/…
    Column("title", String(512)),
    Column("detail", Text),
    Column("ref_plugin", String(256)),
    Column("ref_row", Integer),
    Column("created_at", String(32)),
)

Index("idx_timeline_case", timeline_events.c.case_id)
Index("idx_timeline_ts", timeline_events.c.ts)

# ---------------------------------------------------------------- 情报

iocs = Table(
    "iocs",
    metadata,
    Column("ioc_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", CASE_ID, nullable=False),
    Column("kind", String(32)),             # ip/domain/url/email/path/registry/credential/other
    Column("value", String(1024)),
    Column("context", Text),
    Column("severity", String(16)),
    Column("score", Float),
    Column("source", String(256)),
    Column("hits", Integer, default=1),
    Column("first_seen", String(32)),
)

Index("idx_iocs_case", iocs.c.case_id)
Index("idx_iocs_kind", iocs.c.kind)

dict_hits = Table(
    "dict_hits",
    metadata,
    Column("hit_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", CASE_ID, nullable=False),
    Column("dictionary", String(128)),
    Column("entry_id", String(256)),
    Column("label", String(512)),
    Column("category", String(128)),
    Column("severity", String(16)),
    Column("value", Text),
    Column("context", Text),
    Column("source", String(256)),
    Column("created_at", String(32)),
)

Index("idx_dict_case", dict_hits.c.case_id)

# ---------------------------------------------------------------- 旗标

flags = Table(
    "flags",
    metadata,
    Column("flag_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", CASE_ID, nullable=False),
    Column("value", String(1024), nullable=False),
    Column("kind", String(32)),
    Column("offset", sa.BigInteger),
    Column("context", Text),
    Column("source", String(256)),
    Column("confidence", Float),
    Column("created_at", String(32)),
)

Index("idx_flags_case", flags.c.case_id)

# ---------------------------------------------------------------- 五维判定结果
#: 方案表 9「判定结果」：所属案件 / 维度或环节 / 得分 / 等级 / 依据证据项集合。
#: 与证据项**多对多**——判定结果存「依据证据项编号集合」字符串即可反查。
dimension_results = Table(
    "dimension_results",
    metadata,
    Column("result_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", CASE_ID, nullable=False),
    Column("dimension", String(64), nullable=False),   # tool_presence / channel_config / …
    Column("fr", String(16)),                          # 方案功能编号（FR-01…）
    Column("score", Float, default=0.0),
    Column("state", String(32)),                      # established/cleared/not_found/degraded/disabled
    Column("level_cap", String(16)),                  # 该维的结论等级上限（A/B/C）
    Column("usage", String(16)),                      # check / forensic
    Column("tier", String(16)),                       # 检查三档
    Column("level", String(8)),                       # 取证三级
    Column("total", Float, default=0.0),              # 加权总分
    Column("overall_level_cap", String(8)),           # 整体等级上限
    Column("evidence_refs_json", JSON_TEXT),          # 依据证据项编号集合
    Column("sources_used_json", JSON_TEXT),
    Column("sources_missing_json", JSON_TEXT),
    Column("findings_json", JSON_TEXT),
    Column("gaps_json", JSON_TEXT),
    Column("rulepack_version", String(32)),           # 所用规则包版本（可复现前提）
    Column("rulepack_sha256", String(128)),
    Column("created_at", String(32), nullable=False),
)

Index("idx_dimres_case", dimension_results.c.case_id)
Index("idx_dimres_dim", dimension_results.c.dimension)


# ---------------------------------------------------------------- 审计（保管链）
#: 方案 5.4：审计记录含 **操作人 / 动作 / 对象 / 时间 / 操作前后对象哈希** 五字段，
#: 记录之间以 **哈希链** 串联（每条记录的哈希包含前一条的哈希），
#: 任意一条被改动，后续全部校验失败。
audit_log = Table(
    "audit_log",
    metadata,
    Column("audit_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", CASE_ID),                        # 案件级留痕（可空 = 系统级操作）
    Column("actor", String(128)),                      # 操作人
    Column("action", String(64)),                      # 动作（open/analyze/export/rulepack/...）
    Column("target", String(512)),                     # 操作对象
    Column("ts_utc", String(40), nullable=False),      # 时间（UTC，统一基准）
    Column("before_hash", String(128)),                # 操作前对象哈希
    Column("after_hash", String(128)),                 # 操作后对象哈希
    Column("prev_hash", String(128)),                  # 前一条审计记录的哈希（链）
    Column("entry_hash", String(128), nullable=False), # 本条哈希 = H(prev_hash + payload)
    Column("critical", Boolean, default=False),        # 四类重点操作单独标记
    Column("detail", Text),                            # 备注
    Column("created_at", String(32)),
)

Index("idx_audit_case", audit_log.c.case_id)
Index("idx_audit_action", audit_log.c.action)
Index("idx_audit_ts", audit_log.c.ts_utc)


# ---------------------------------------------------------------- 缺口清单
#: 方案表 9：「缺口」是独立实体——缺失维度 / 缺失原因 / 建议补证，
#: **须结构化存储而非写在报告正文里**。
gaps = Table(
    "gaps",
    metadata,
    Column("gap_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", CASE_ID, nullable=False),
    Column("scope", String(32)),                 # 范围：dimension（维度）/ stage（阶段）/ source（数据源）
    Column("dimension", String(64)),             # 缺失的维度或环节（如 FR-03 运行痕迹）
    Column("source", String(256)),               # 缺失的数据源（插件名）
    Column("reason", String(512)),               # 缺失原因
    Column("impact", String(32)),                # 影响：none/downgrade/blocked
    Column("level_cap", String(32)),             # 该维结论上限（方案表 12 的降级路径）
    Column("suggestion", Text),                  # 建议怎么补
    Column("evidence_ref", String(512)),         # 关联证据编号
    Column("status", String(32), default="open"),  # open / resolved / accepted
    Column("created_at", String(32), nullable=False),
)

Index("idx_gaps_case", gaps.c.case_id)
Index("idx_gaps_dimension", gaps.c.dimension)


# ---------------------------------------------------------------- 规则包
#: 方案表 9：「规则包」含版本号 / 发布日期 / 阈值集合 / 白名单 / 域名词表 / 变更记录。
#: **报告须引用版本号，这是结论可复现的前提。**
rule_packs = Table(
    "rule_packs",
    metadata,
    Column("pack_id", String(64), primary_key=True),
    Column("version", String(32), nullable=False),
    Column("published_at", String(32)),           # 发布日期
    Column("status", String(32), default="active"),  # active / superseded / rolled_back
    Column("source_path", String(1024)),          # 离线包来源路径
    Column("sha256", String(128)),                # 规则包自身哈希
    Column("thresholds_json", JSON_TEXT),         # 阈值集合
    Column("whitelist_json", JSON_TEXT),          # 白名单
    Column("wordlist_json", JSON_TEXT),           # 词表（域名分类等）
    Column("change_log", Text),                   # 变更记录（理由 + 影响范围）
    Column("activated_at", String(32)),
    Column("created_at", String(32)),
)

Index("idx_rulepacks_version", rule_packs.c.version)


# ---------------------------------------------------------------- 批次 / 笔记 / KV

analysis_runs = Table(
    "analysis_runs",
    metadata,
    Column("run_id", String(64), primary_key=True),
    Column("case_id", CASE_ID, nullable=False),
    Column("kind", String(32)),            # deep / probe / custom
    Column("state", String(32)),           # running / ok / failed / cancelled
    Column("phase", String(128)),
    Column("progress", Float, default=0.0),
    Column("message", Text),
    Column("plan_json", JSON_TEXT),
    Column("summary_json", JSON_TEXT),
    Column("started_at", String(32)),
    Column("finished_at", String(32)),
)

Index("idx_runs_case", analysis_runs.c.case_id)

notes = Table(
    "notes",
    metadata,
    Column("note_id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", CASE_ID, nullable=False),
    Column("body", Text),
    Column("tags", String(512)),
    Column("author", String(128)),
    Column("created_at", String(32)),
)

Index("idx_notes_case", notes.c.case_id)

kv = Table(
    "kv",
    metadata,
    Column("k", String(128), primary_key=True),
    Column("v", JSON_TEXT),
    Column("updated_at", String(32)),
)


# ---------------------------------------------------------------- 便捷

def all_tables() -> tuple[Table, ...]:
    return tuple(metadata.sorted_tables)


def create_all(engine: sa.Engine) -> None:
    """建表（幂等）。两个方言都能用。"""
    metadata.create_all(engine)


def migrate(engine: sa.Engine) -> list[str]:
    """
    轻量迁移：给**已存在的旧表补上新增的列**。

    ## 为什么必须做

    `metadata.create_all()` 只会**建缺失的表**，**不会给已存在的表加列**。
    于是 v0.10 的 `work/memlens.db`（cases 表没有 `state`/`tool_version`/`updated_at`，
    也没有 system_profile / timeline_events / iocs …）在升级后一查就报
    `no such column: cases.state` —— 表现为"Web 端 500 / GUI 打不开"，
    而用户根本不知道自己只是升级了。

    ## 做法

    用 SQLAlchemy 的 Inspector 拿到每张表**实际存在的列**，
    与模型定义比对，缺哪个就 `ALTER TABLE ... ADD COLUMN`。
    两种方言都支持这条语法，因此 SQLite 与 MySQL 通用。

    Returns: 实际执行的变更描述列表（便于写进日志/报告）
    """
    inspector = sa.inspect(engine)
    changes: list[str] = []
    existing_tables = set(inspector.get_table_names())
    for table in metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        try:
            present = {c["name"] for c in inspector.get_columns(table.name)}
        except Exception:
            continue
        for col in table.columns:
            if col.name in present:
                continue
            ddl = col.type.compile(dialect=engine.dialect)
            sql = f'ALTER TABLE {table.name} ADD COLUMN {col.name} {ddl}'
            if not col.nullable and col.default is None:
                # 有 NOT NULL 又没默认值的列在存量表上会加不上去 → 放宽
                sql = f'ALTER TABLE {table.name} ADD COLUMN {col.name} {ddl} NULL'
            try:
                with engine.begin() as conn:
                    conn.exec_driver_sql(sql)
                changes.append(f"{table.name}.{col.name}")
            except Exception:
                pass
    return changes


def drop_all(engine: sa.Engine) -> None:
    metadata.drop_all(engine)
