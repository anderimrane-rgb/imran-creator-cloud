"""Portable database layer: SQLite for local dev/testing, PostgreSQL (Supabase/VPS) via DATABASE_URL."""
import json
import os
import sqlite3
from datetime import datetime, timezone

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
IS_POSTGRES = DATABASE_URL.startswith("postgres://") or DATABASE_URL.startswith("postgresql://")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLITE_PATH = os.environ.get("SQLITE_PATH", os.path.join(BASE_DIR, "cloud_control.db"))

DEFAULT_FEATURE_FLAGS = {
    "bulk_download": True,
    "profile_scraper": True,
    "watchlist": True,
    "ai_clipper": True,
    "auto_captions": True,
    "live_clipper": True,
    "full_context_mode": True,
    "ai_dubbing": True,
    "beta_features": False,
}

DEFAULT_CONFIG = {
    "trial_hours": 72,
    "min_supported_version": "2.0.0",
    "maintenance_mode": False,
    "maintenance_message": "",
    "announcement_banner": "",
    "purchase_url": "https://wa.me/923400724575?text=Hi%20Imran%2C%20I%20want%20to%20purchase%20an%20Imran%20Creator%20Suite%20license.",
    "offline_grace_hours": 24,
    "plans": [
        {"id": "monthly", "name": "Monthly Pass", "price_usd": 4, "price_pkr": 1100, "duration_days": 30, "max_devices": 1},
        {"id": "yearly", "name": "Yearly Pro", "price_usd": 29, "price_pkr": 7900, "duration_days": 365, "max_devices": 2},
        {"id": "lifetime", "name": "Lifetime VIP", "price_usd": 40, "price_pkr": 11000, "duration_days": None, "max_devices": 2},
    ],
    "feature_flags": DEFAULT_FEATURE_FLAGS,
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class DBConn:
    """Unified cursor wrapper supporting both SQLite (?) and PostgreSQL (%s)."""
    def __init__(self):
        if IS_POSTGRES:
            import psycopg2
            import psycopg2.extras
            self._conn = psycopg2.connect(DATABASE_URL)
            self._is_pg = True
            self._cursor_factory = psycopg2.extras.RealDictCursor
        else:
            os.makedirs(os.path.dirname(os.path.abspath(SQLITE_PATH)), exist_ok=True)
            self._conn = sqlite3.connect(SQLITE_PATH, timeout=30)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._is_pg = False
            self._cursor_factory = None

    def _adapt(self, sql: str) -> str:
        return sql.replace("?", "%s") if self._is_pg else sql

    def execute(self, sql: str, params=()):
        q = self._adapt(sql)
        if self._is_pg:
            cur = self._conn.cursor(cursor_factory=self._cursor_factory)
            cur.execute(q, params)
            return cur
        return self._conn.execute(q, params)

    def fetchone(self, sql: str, params=()):
        row = self.execute(sql, params).fetchone()
        return dict(row) if row is not None else None

    def fetchall(self, sql: str, params=()):
        rows = self.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def commit(self):
        self._conn.commit()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.commit()
        else:
            try:
                self._conn.rollback()
            except Exception:
                pass
        self.close()


def init_db():
    id_col = "SERIAL PRIMARY KEY" if IS_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
    with DBConn() as db:
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                hostname TEXT DEFAULT '',
                os_info TEXT DEFAULT '',
                app_version TEXT DEFAULT '2.0.0',
                status TEXT DEFAULT 'active',
                trial_started_at TEXT NOT NULL,
                trial_expires_at TEXT NOT NULL,
                first_ip TEXT DEFAULT '',
                last_ip TEXT DEFAULT '',
                last_seen_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS licenses (
                id {id_col},
                license_key TEXT UNIQUE NOT NULL,
                plan TEXT NOT NULL DEFAULT 'lifetime',
                status TEXT NOT NULL DEFAULT 'active',
                max_devices INTEGER NOT NULL DEFAULT 1,
                expires_at TEXT,
                customer_email TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS license_activations (
                id {id_col},
                license_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                activated_at TEXT NOT NULL,
                deactivated_at TEXT,
                active INTEGER NOT NULL DEFAULT 1
            )
        """)
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS releases (
                id {id_col},
                version TEXT UNIQUE NOT NULL,
                min_supported_version TEXT NOT NULL DEFAULT '2.0.0',
                download_url TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                signature TEXT NOT NULL,
                release_notes TEXT DEFAULT '',
                is_mandatory INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                file_size INTEGER DEFAULT 0,
                published_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS remote_config (
                cfg_key TEXT PRIMARY KEY,
                cfg_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        db.execute(f"""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id {id_col},
                event_type TEXT NOT NULL,
                device_id TEXT DEFAULT '',
                ip_addr TEXT DEFAULT '',
                details TEXT DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)

        # Seed default remote config if not present
        now = utc_now_iso()
        for k, v in DEFAULT_CONFIG.items():
            existing = db.fetchone("SELECT cfg_key FROM remote_config WHERE cfg_key = ?", (k,))
            if not existing:
                db.execute(
                    "INSERT INTO remote_config (cfg_key, cfg_value, updated_at) VALUES (?, ?, ?)",
                    (k, json.dumps(v), now),
                )


def get_all_config(db: DBConn) -> dict:
    rows = db.fetchall("SELECT cfg_key, cfg_value FROM remote_config")
    cfg = dict(DEFAULT_CONFIG)
    for r in rows:
        try:
            cfg[r["cfg_key"]] = json.loads(r["cfg_value"])
        except Exception:
            cfg[r["cfg_key"]] = r["cfg_value"]
    # Ensure all default feature flags exist
    ff = dict(DEFAULT_FEATURE_FLAGS)
    if isinstance(cfg.get("feature_flags"), dict):
        ff.update(cfg["feature_flags"])
    cfg["feature_flags"] = ff
    return cfg


def set_config_values(db: DBConn, updates: dict):
    now = utc_now_iso()
    for k, v in updates.items():
        val_str = json.dumps(v)
        existing = db.fetchone("SELECT cfg_key FROM remote_config WHERE cfg_key = ?", (k,))
        if existing:
            db.execute("UPDATE remote_config SET cfg_value = ?, updated_at = ? WHERE cfg_key = ?", (val_str, now, k))
        else:
            db.execute("INSERT INTO remote_config (cfg_key, cfg_value, updated_at) VALUES (?, ?, ?)", (k, val_str, now))


def log_event(db: DBConn, event_type: str, device_id: str = "", ip_addr: str = "", details: str = ""):
    db.execute(
        "INSERT INTO audit_logs (event_type, device_id, ip_addr, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (event_type, device_id or "", ip_addr or "", str(details or "")[:1000], utc_now_iso()),
    )
