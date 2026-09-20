"""SQLite 数据层。

要点：**每个线程一条独立连接**（sqlite3 连接不能在多线程间共享），
开启 WAL 以便 web 进程与扫描子进程并发读写。跨进程写同一库必须走 WAL，
否则会出现 database is locked。
"""
from __future__ import annotations

import sqlite3
import threading
import time

from backend.config import DB_PATH

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    username             TEXT UNIQUE NOT NULL,
    password_hash        TEXT NOT NULL,
    display_name         TEXT DEFAULT '',
    must_change_password INTEGER DEFAULT 0,
    created_at           REAL NOT NULL
);

-- 刷新令牌：JWT 是有状态签发（access 短期 + refresh 长期），所以长期凭证必须落库才能吊销。
-- 存 sha256 哈希而不是明文 —— 数据库文件（data/*.db）在这台机器上是明文的，
-- 一旦被拷走，明文令牌等于直接可用的登录凭证；存哈希则拿到也没法用。
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT UNIQUE NOT NULL,   -- sha256(raw)，raw 只在 cookie 里存在
    username    TEXT NOT NULL,
    family      TEXT NOT NULL,          -- 会话家族：一次登录 = 一个 family，轮换时继承
    csrf        TEXT DEFAULT '',        -- 与本次登录绑定的 CSRF 令牌
    user_agent  TEXT DEFAULT '',
    ip          TEXT DEFAULT '',
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    revoked_at  REAL,                   -- 非空 = 已撤销（登出/轮换/检测到复用/改密）
    revoke_reason TEXT DEFAULT ''
);

-- 登录审计：既是合规要求，也是限流（防爆破）的数据来源
CREATE TABLE IF NOT EXISTS login_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT DEFAULT '',
    ip         TEXT DEFAULT '',
    success    INTEGER DEFAULT 0,
    reason     TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    ts         REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS repos (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    type             TEXT NOT NULL DEFAULT 'gitlab',
    url              TEXT NOT NULL,
    branch           TEXT NOT NULL DEFAULT 'main',
    username         TEXT DEFAULT '',
    password         TEXT DEFAULT '',
    ssh_key          TEXT DEFAULT '',
    local_path       TEXT DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'active',
    last_pull_at     REAL,
    last_pull_status TEXT DEFAULT '',
    last_pull_msg    TEXT DEFAULT '',
    created_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS skills (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    prompt      TEXT DEFAULT '',
    category    TEXT DEFAULT '通用',
    builtin     INTEGER DEFAULT 0,
    enabled     INTEGER DEFAULT 1,
    sort_order  INTEGER DEFAULT 100,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    repo_id         INTEGER NOT NULL,
    depth           TEXT NOT NULL DEFAULT 'standard',
    engine          TEXT NOT NULL DEFAULT 'codex',
    skill_names     TEXT DEFAULT '[]',
    schedule_type   TEXT NOT NULL DEFAULT 'manual',
    interval_seconds INTEGER DEFAULT 0,
    cron            TEXT DEFAULT '',
    run_at          REAL,
    enabled         INTEGER DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'pending',
    last_run_at     REAL,
    next_run_at     REAL,
    created_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT UNIQUE NOT NULL,
    task_id       INTEGER,
    repo_id       INTEGER,
    task_name     TEXT DEFAULT '',
    repo_name     TEXT DEFAULT '',
    depth         TEXT DEFAULT 'standard',
    engine        TEXT DEFAULT 'codex',
    skill_names   TEXT DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'queued',
    progress      INTEGER DEFAULT 0,
    stage         TEXT DEFAULT '',
    message       TEXT DEFAULT '',
    pid           INTEGER,
    workdir       TEXT DEFAULT '',
    error         TEXT DEFAULT '',
    started_at    REAL,
    finished_at   REAL,
    duration_ms   INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0,
    loc           INTEGER DEFAULT 0,
    sev_critical  INTEGER DEFAULT 0,
    sev_high      INTEGER DEFAULT 0,
    sev_medium    INTEGER DEFAULT 0,
    sev_low       INTEGER DEFAULT 0,
    report_md     TEXT DEFAULT '',
    ai_used       INTEGER DEFAULT 0,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     TEXT NOT NULL,
    skill      TEXT DEFAULT '',
    source     TEXT DEFAULT 'rule',
    severity   TEXT DEFAULT 'low',
    category   TEXT DEFAULT '',
    title      TEXT DEFAULT '',
    file       TEXT DEFAULT '',
    line       INTEGER DEFAULT 0,
    snippet    TEXT DEFAULT '',
    detail     TEXT DEFAULT '',
    advice     TEXT DEFAULT '',
    confidence TEXT DEFAULT 'medium'
);

CREATE TABLE IF NOT EXISTS run_logs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id  TEXT NOT NULL,
    ts      REAL NOT NULL,
    level   TEXT DEFAULT 'info',
    message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT DEFAULT ''
);

-- ============ Web 漏洞扫描（独立于代码审计，不使用任务队列）============

CREATE TABLE IF NOT EXISTS web_jobs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id        TEXT UNIQUE NOT NULL,
    name          TEXT DEFAULT '',
    targets       TEXT DEFAULT '[]',
    depth         TEXT DEFAULT 'standard',
    engine        TEXT DEFAULT 'codex',
    skill_names   TEXT DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'running',
    progress      INTEGER DEFAULT 0,
    stage         TEXT DEFAULT '',
    message       TEXT DEFAULT '',
    pid           INTEGER,
    error         TEXT DEFAULT '',
    started_at    REAL,
    finished_at   REAL,
    duration_ms   INTEGER DEFAULT 0,
    targets_total INTEGER DEFAULT 0,
    targets_done  INTEGER DEFAULT 0,
    requests_made INTEGER DEFAULT 0,
    sev_critical  INTEGER DEFAULT 0,
    sev_high      INTEGER DEFAULT 0,
    sev_medium    INTEGER DEFAULT 0,
    sev_low       INTEGER DEFAULT 0,
    sev_info      INTEGER DEFAULT 0,
    report_md     TEXT DEFAULT '',
    ai_used       INTEGER DEFAULT 0,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS web_findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     TEXT NOT NULL,
    target     TEXT DEFAULT '',
    skill      TEXT DEFAULT '',
    source     TEXT DEFAULT 'tool',
    severity   TEXT DEFAULT 'low',
    category   TEXT DEFAULT '',
    title      TEXT DEFAULT '',
    url        TEXT DEFAULT '',
    method     TEXT DEFAULT 'GET',
    param      TEXT DEFAULT '',
    payload    TEXT DEFAULT '',
    evidence   TEXT DEFAULT '',
    detail     TEXT DEFAULT '',
    advice     TEXT DEFAULT '',
    cwe        TEXT DEFAULT '',
    confidence TEXT DEFAULT 'medium'
);

CREATE TABLE IF NOT EXISTS web_skills (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    prompt      TEXT DEFAULT '',
    category    TEXT DEFAULT '通用',
    phase       TEXT DEFAULT 'scan',
    builtin     INTEGER DEFAULT 0,
    enabled     INTEGER DEFAULT 1,
    sort_order  INTEGER DEFAULT 100,
    created_at  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webfindings_job ON web_findings(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_runlogs_run  ON run_logs(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_task    ON runs(task_id);
CREATE INDEX IF NOT EXISTS idx_rt_username  ON refresh_tokens(username);
CREATE INDEX IF NOT EXISTS idx_rt_family    ON refresh_tokens(family);
CREATE INDEX IF NOT EXISTS idx_login_events ON login_events(username, ts);
"""


def conn() -> sqlite3.Connection:
    """取当前线程的连接（不存在则建立）。"""
    c = getattr(_local, "conn", None)
    if c is None:
        c = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA busy_timeout=30000")
        c.execute("PRAGMA foreign_keys=ON")
        _local.conn = c
    return c


def query(sql: str, params: tuple | list = ()) -> list[dict]:
    return [dict(r) for r in conn().execute(sql, params).fetchall()]


def query_one(sql: str, params: tuple | list = ()) -> dict | None:
    r = conn().execute(sql, params).fetchone()
    return dict(r) if r else None


def execute(sql: str, params: tuple | list = ()) -> sqlite3.Cursor:
    return conn().execute(sql, params)


def insert(table: str, data: dict) -> int:
    cols = ", ".join(data)
    ph = ", ".join("?" for _ in data)
    cur = conn().execute(f"INSERT INTO {table} ({cols}) VALUES ({ph})", tuple(data.values()))
    return int(cur.lastrowid or 0)


def update(table: str, pk: int, data: dict) -> None:
    sets = ", ".join(f"{k}=?" for k in data)
    conn().execute(f"UPDATE {table} SET {sets} WHERE id=?", (*data.values(), pk))


def init_db() -> None:
    c = conn()
    c.executescript(SCHEMA)
    # 老库升级：补齐可能缺失的列
    _ensure_columns(c, "users", {
        # token_version：改密/踢下线时 +1。JWT 是自包含的、签发后在有效期内无法收回，
        # 所以必须靠库里这个版本号来"让旧令牌立即失效"——每次校验比对 JWT 里的 tv 声明。
        "token_version": "INTEGER DEFAULT 0",
        "last_login_at": "REAL",
        "last_login_ip": "TEXT DEFAULT ''",
    })
    _ensure_columns(c, "tasks", {
        "skill_names": "TEXT DEFAULT '[]'",
        "interval_seconds": "INTEGER DEFAULT 0",
        "cron": "TEXT DEFAULT ''",
        "run_at": "REAL",
        "next_run_at": "REAL",
    })
    _ensure_columns(c, "runs", {
        "pid": "INTEGER", "workdir": "TEXT DEFAULT ''", "ai_used": "INTEGER DEFAULT 0",
        "message": "TEXT DEFAULT ''", "repo_name": "TEXT DEFAULT ''", "task_name": "TEXT DEFAULT ''",
    })
    # 旧版把会话明文存在 sessions 表里，且 token 有效期内无法吊销。
    # 迁到 JWT 双令牌后这张表已无人读取，直接删掉——留着等于把一批旧凭证继续摆在磁盘上。
    if c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions'").fetchone():
        c.execute("DROP TABLE sessions")
        print("[init] 已移除旧版 sessions 表（改用 JWT 双令牌）", flush=True)


def _ensure_columns(c: sqlite3.Connection, table: str, cols: dict) -> None:
    have = {r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, decl in cols.items():
        if name not in have:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def now() -> float:
    return time.time()


def get_setting(key: str, default: str = "") -> str:
    r = query_one("SELECT value FROM settings WHERE key=?", (key,))
    return r["value"] if r else default


def set_setting(key: str, value: str) -> None:
    execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def log_line(run_id: str, message: str, level: str = "info") -> None:
    execute("INSERT INTO run_logs (run_id, ts, level, message) VALUES (?,?,?,?)",
            (run_id, now(), level, message))
