-- MemLens 证据模型（SQLite）
--
-- 四层：cases（案件） → artifacts（一次插件执行/一件证据产物） → records（结构化行） → findings（发现项）
-- plus: rules（检测规则，可启停/可测试）
--
-- 设计要点：
--   1. records.data 用 JSON 承载异构列，同时抽出 5 个高频列建索引 → 既灵活又能查询；
--   2. artifacts 保留原始产物路径与原命令行 → 可复现、可追溯；
--   3. artifacts 对 (case_id, engine, plugin, params_hash) 唯一 → 天然实现"同参数不重复跑"的缓存；
--   4. findings 带 confidence/severity → 支持多规则聚合打分。

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id       TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    image_path    TEXT NOT NULL,
    image_sha256  TEXT,
    image_size    INTEGER,
    image_mtime   TEXT,
    container     TEXT,          -- probe 结论：raw/lime/windmp/vmem/...
    os_type       TEXT,          -- windows/linux/macos/unknown
    os_confidence REAL,
    notes         TEXT,
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id   TEXT PRIMARY KEY,
    case_id       TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    engine        TEXT NOT NULL,
    plugin        TEXT NOT NULL,
    category      TEXT,
    kind          TEXT NOT NULL,      -- table/text/file_set/scalar
    params_hash   TEXT NOT NULL,
    params_json   TEXT,
    argv_json     TEXT,               -- 实际执行的命令行（可复现）
    status        TEXT NOT NULL,      -- running/ok/failed/partial/cancelled
    row_count     INTEGER DEFAULT 0,
    output_path   TEXT,               -- 原始产物落盘路径（证据保全）
    output_sha256 TEXT,
    duration_ms   INTEGER,
    error         TEXT,
    started_at    TEXT,
    finished_at   TEXT,
    UNIQUE(case_id, engine, plugin, params_hash)
);

CREATE TABLE IF NOT EXISTS records (
    record_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    row_no      INTEGER,
    data        TEXT NOT NULL,        -- 该行的完整 JSON（列名→值）
    ts          TEXT,                 -- 抽取：时间
    pid         INTEGER,              -- 抽取：进程 ID
    ppid        INTEGER,              -- 抽取：父进程 ID
    name        TEXT,                 -- 抽取：进程名/文件名/服务名
    remote      TEXT                  -- 抽取：远端地址 ip:port
);

CREATE INDEX IF NOT EXISTS idx_records_artifact ON records(artifact_id);
CREATE INDEX IF NOT EXISTS idx_records_ts       ON records(ts);
CREATE INDEX IF NOT EXISTS idx_records_pid      ON records(pid);
CREATE INDEX IF NOT EXISTS idx_records_name     ON records(name);

CREATE TABLE IF NOT EXISTS rules (
    rule_id      TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    category     TEXT,                -- 隐藏进程/代码注入/持久化/凭据/异常时间线
    detector     TEXT NOT NULL,       -- 由哪个 detector 实现
    params_json  TEXT,                -- detector 的配置参数
    severity     TEXT DEFAULT 'medium',  -- info/low/medium/high/critical
    weight       REAL DEFAULT 1.0,
    reason       TEXT,
    enabled      INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    rule_id     TEXT,
    detector    TEXT,
    title       TEXT NOT NULL,
    description TEXT,
    severity    TEXT DEFAULT 'medium',
    confidence  REAL DEFAULT 0.0,
    sources     TEXT,                 -- JSON 数组：哪些证据源参与命中
    evidence    TEXT,                 -- JSON：命中字段/关联记录/上下文
    status      TEXT DEFAULT 'open',  -- open/confirmed/false_positive
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev  ON findings(severity);
