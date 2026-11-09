"""SQLite store. One file (run/leblanc.db). Every number shown anywhere is computed from these tables."""
import json
import sqlite3
import threading
import time

from .config import DB_PATH

_LOCK = threading.RLock()

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS control (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS cells (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,              -- gen | scan_repair | blind_repair
  task_id TEXT NOT NULL, model TEXT NOT NULL, arm TEXT NOT NULL, rep INTEGER NOT NULL,
  base_cell TEXT,                  -- repair cells: the plain generation cell they repair
  ord INTEGER NOT NULL,            -- execution order (repetition outermost)
  status TEXT NOT NULL DEFAULT 'pending',   -- pending | leased | done | failed
  lease_until REAL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT,
  prompt_sent TEXT, added_text TEXT, added_chars INTEGER,
  response_text TEXT, finish_reason TEXT,
  extract TEXT,                    -- ok | no_code | syntax_error | truncated | not_needed | no_base
  code TEXT, code_stripped TEXT,
  rounds INTEGER,                  -- repair rounds actually used
  repair_outcome TEXT,             -- not_needed | fixed | not_converged | broke_extraction
  judge_status TEXT NOT NULL DEFAULT 'pending',  -- pending | done | error | na
  vuln_task INTEGER, vuln_raw INTEGER, vuln_bandit INTEGER, vuln_semgrep INTEGER, vuln_target INTEGER,
  n_findings INTEGER,
  test_status TEXT NOT NULL DEFAULT 'pending',   -- pending | done | na
  fp_result TEXT, sp_result TEXT, fp_detail TEXT, sp_detail TEXT,   -- published (strict) tests
  fpl_result TEXT, spl_result TEXT, fpl_detail TEXT, spl_detail TEXT, -- lenient tests (primary)
  tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0, tokens_reasoning INTEGER DEFAULT 0,
  cost_usd REAL DEFAULT 0, latency_s REAL DEFAULT 0, n_calls INTEGER DEFAULT 0,
  provider TEXT, created_at REAL, finished_at REAL
);
CREATE INDEX IF NOT EXISTS ix_cells_status ON cells(status, ord);
CREATE INDEX IF NOT EXISTS ix_cells_judge ON cells(judge_status);
CREATE INDEX IF NOT EXISTS ix_cells_test ON cells(test_status);
CREATE TABLE IF NOT EXISTS calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cell_id TEXT, round INTEGER, model TEXT, provider TEXT,
  ok INTEGER, http_status INTEGER, error TEXT,
  prompt_tokens INTEGER, completion_tokens INTEGER, reasoning_tokens INTEGER,
  cost_usd REAL, latency_s REAL, finish_reason TEXT, retries INTEGER,
  temperature REAL, created_at REAL
);
CREATE INDEX IF NOT EXISTS ix_calls_cell ON calls(cell_id);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cell_id TEXT, round INTEGER,     -- round 0 = the cell's final code; repair rounds keep their own
  which TEXT,                      -- stripped | raw
  tool TEXT, rule TEXT, cwes TEXT, severity TEXT, line INTEGER, message TEXT,
  on_scaffolding INTEGER, snippet TEXT
);
CREATE INDEX IF NOT EXISTS ix_find_cell ON findings(cell_id);
CREATE TABLE IF NOT EXISTS repair_rounds (
  cell_id TEXT, round INTEGER, code TEXT, n_findings INTEGER, findings_json TEXT,
  PRIMARY KEY (cell_id, round)
);
CREATE TABLE IF NOT EXISTS audit (
  finding_id INTEGER, annotator TEXT, label TEXT, note TEXT, ts REAL,
  PRIMARY KEY (finding_id, annotator)
);
CREATE TABLE IF NOT EXISTS audit_sample (finding_id INTEGER PRIMARY KEY, drawn_at REAL);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, level TEXT, msg TEXT);
"""


def connect(path=None):
    con = sqlite3.connect(path or DB_PATH, timeout=60, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=60000")
    return con


_CON = None


def db():
    global _CON
    if _CON is None:
        _CON = connect()
        with _LOCK:
            _CON.executescript(SCHEMA)
            cols = {r[1] for r in _CON.execute("PRAGMA table_info(cells)").fetchall()}
            for c in ("fpl_result", "spl_result", "fpl_detail", "spl_detail"):
                if c not in cols:
                    _CON.execute(f"ALTER TABLE cells ADD COLUMN {c} TEXT")
            _CON.commit()
    return _CON


def q(sql, args=()):
    with _LOCK:
        return [dict(r) for r in db().execute(sql, args).fetchall()]


def q1(sql, args=()):
    rows = q(sql, args)
    return rows[0] if rows else None


def x(sql, args=()):
    with _LOCK:
        cur = db().execute(sql, args)
        db().commit()
        return cur


def xmany(sql, rows):
    with _LOCK:
        db().executemany(sql, rows)
        db().commit()


def update_cell(cell_id, **fields):
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    x(f"UPDATE cells SET {cols} WHERE id=?", list(fields.values()) + [cell_id])


def event(msg, level="info"):
    x("INSERT INTO events(ts, level, msg) VALUES (?,?,?)", (time.time(), level, msg))


def get_control(key, default=None):
    r = q1("SELECT value FROM control WHERE key=?", (key,))
    return r["value"] if r else default


def set_control(key, value):
    x("INSERT INTO control(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      (key, value))


def set_meta(key, value):
    x("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      (key, json.dumps(value)))


def get_meta(key, default=None):
    r = q1("SELECT value FROM meta WHERE key=?", (key,))
    return json.loads(r["value"]) if r else default
