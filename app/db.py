"""SQLite storage (WAL mode) on the NVMe, never on the router."""
import sqlite3
import time
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS signups(
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT NOT NULL,
  password_enc BLOB,
  internet INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
  stage INTEGER NOT NULL DEFAULT 0,
  error TEXT,
  reason TEXT,
  created_at INTEGER NOT NULL,
  decided_by TEXT,
  decided_at INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS signups_active_user
  ON signups(username) WHERE status IN ('pending','approved');
CREATE TABLE IF NOT EXISTS guest_vouchers(
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  mac TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS guest_vouchers_mac ON guest_vouchers(mac, created_at);
CREATE TABLE IF NOT EXISTS login_tokens(
  token_hash TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  tier TEXT NOT NULL,
  mac TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX IF NOT EXISTS login_tokens_user ON login_tokens(username, used_at);
CREATE TABLE IF NOT EXISTS sessions(
  acct_session_id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  mac TEXT,
  ip TEXT,
  tier TEXT,
  start_at INTEGER NOT NULL,
  stop_at INTEGER,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT
);
"""


def now() -> int:
    return int(time.time())


@contextmanager
def conn():
    c = sqlite3.connect(config.S.db_path, timeout=10)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def init() -> None:
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)


def audit(c, actor: str, action: str, target: str = "", detail: str = "") -> None:
    c.execute(
        "INSERT INTO audit_log(ts, actor, action, target, detail) VALUES(?,?,?,?,?)",
        (now(), actor, action, target, detail[:500]),
    )
