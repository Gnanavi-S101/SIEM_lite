"""
SIEM Lite — Database Module
Thread-safe SQLite layer with connection pooling pattern.
All schema changes go here. No raw SQL anywhere else in the codebase.
"""

import sqlite3
import threading
import logging
from datetime import datetime
from config import DB_PATH

log = logging.getLogger(__name__)

_write_lock = threading.Lock()


# ── Connection Factory ─────────────────────────────────────────────────────────

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


# ── Schema Setup ───────────────────────────────────────────────────────────────

def setup() -> None:
    with _write_lock:
        conn = get_conn()
        try:
            c = conn.cursor()

            c.execute("""
                CREATE TABLE IF NOT EXISTS normal_logs (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp  TEXT    NOT NULL,
                    hostname   TEXT    NOT NULL DEFAULT 'unknown',
                    event_type TEXT    NOT NULL DEFAULT 'general',
                    user       TEXT    NOT NULL DEFAULT 'unknown',
                    ip         TEXT    NOT NULL DEFAULT 'unknown',
                    raw        TEXT    NOT NULL,
                    source_os  TEXT    NOT NULL DEFAULT 'linux',
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

            c.execute("""
                CREATE TABLE IF NOT EXISTS malicious_logs (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp    TEXT    NOT NULL,
                    hostname     TEXT    NOT NULL DEFAULT 'unknown',
                    event_type   TEXT    NOT NULL,
                    user         TEXT    NOT NULL DEFAULT 'unknown',
                    ip           TEXT    NOT NULL DEFAULT 'unknown',
                    raw          TEXT    NOT NULL,
                    reason       TEXT    NOT NULL,
                    severity     TEXT    NOT NULL DEFAULT 'medium',
                    rule         TEXT    NOT NULL DEFAULT 'unknown',
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # ── FIX: no UNIQUE on ip — we DELETE the row on unblock so
            #    insert_blocked_ip always inserts fresh, never needs ON CONFLICT.
            #    ip is still indexed for fast lookups.
            c.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip         TEXT    NOT NULL,
                    reason     TEXT    NOT NULL,
                    block_type TEXT    NOT NULL DEFAULT 'AUTO',
                    blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

            c.execute("""
                CREATE TABLE IF NOT EXISTS alert_dedup (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedup_key  TEXT    NOT NULL UNIQUE,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_normal_ip         ON normal_logs(ip)",
                "CREATE INDEX IF NOT EXISTS idx_normal_created     ON normal_logs(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_normal_event       ON normal_logs(event_type)",
                "CREATE INDEX IF NOT EXISTS idx_normal_raw         ON normal_logs(raw)",
                "CREATE INDEX IF NOT EXISTS idx_malicious_severity ON malicious_logs(severity)",
                "CREATE INDEX IF NOT EXISTS idx_malicious_rule     ON malicious_logs(rule)",
                "CREATE INDEX IF NOT EXISTS idx_malicious_created  ON malicious_logs(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_malicious_event    ON malicious_logs(event_type)",
                "CREATE INDEX IF NOT EXISTS idx_blocked_ip         ON blocked_ips(ip)",
                "CREATE INDEX IF NOT EXISTS idx_dedup_key          ON alert_dedup(dedup_key)",
            ]
            for idx in indexes:
                c.execute(idx)

            # Migration: if old schema had UNIQUE on ip + unblocked column,
            # recreate the table cleanly (safe — only runs once on existing DBs).
            try:
                cols = [row[1] for row in c.execute("PRAGMA table_info(blocked_ips)").fetchall()]
                if 'unblocked' in cols:
                    log.info("[DATABASE] Migrating blocked_ips schema — removing unblocked column")
                    c.execute("""
                        CREATE TABLE IF NOT EXISTS blocked_ips_new (
                            id         INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip         TEXT    NOT NULL,
                            reason     TEXT    NOT NULL,
                            block_type TEXT    NOT NULL DEFAULT 'AUTO',
                            blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    c.execute("""
                        INSERT INTO blocked_ips_new (ip, reason, block_type, blocked_at)
                        SELECT ip, reason, block_type, blocked_at
                        FROM blocked_ips
                        WHERE unblocked = 0
                    """)
                    c.execute("DROP TABLE blocked_ips")
                    c.execute("ALTER TABLE blocked_ips_new RENAME TO blocked_ips")
                    c.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip)")
                    log.info("[DATABASE] Migration complete")
            except Exception as mig_exc:
                log.warning("[DATABASE] Migration check failed (safe to ignore): %s", mig_exc)

            conn.commit()
            log.info("[DATABASE] Schema ready")
        finally:
            conn.close()


# ── Deduplication Helpers ──────────────────────────────────────────────────────

def is_duplicate_alert(dedup_key: str) -> bool:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT 1 FROM alert_dedup WHERE dedup_key=?", (dedup_key,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def register_alert(dedup_key: str) -> None:
    with _write_lock:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO alert_dedup (dedup_key) VALUES (?)",
                (dedup_key,)
            )
            conn.commit()
        finally:
            conn.close()


def clear_dedup_keys_for_ip(ip: str) -> None:
    """
    Remove ALL alert_dedup entries referencing this IP.
    Covers brute_force:{ip}:*, sudo_failure:*:{ip}:*, ml_anomaly:*,
    first_time_ip:{ip}:*, off_hours:{ip}:* — i.e. anything with the IP
    anywhere in the key.  Idempotent, safe to call multiple times.
    """
    with _write_lock:
        conn = get_conn()
        try:
            deleted = conn.execute(
                "DELETE FROM alert_dedup WHERE dedup_key LIKE ?",
                (f"%{ip}%",)
            ).rowcount
            conn.commit()
            log.info("[DATABASE] Cleared %d dedup keys for IP: %s", deleted, ip)
        finally:
            conn.close()


# ── Write Operations ───────────────────────────────────────────────────────────

def insert_normal_log(
    timestamp: str,
    hostname: str,
    event_type: str,
    user: str,
    ip: str,
    raw: str,
    source_os: str = 'linux'
) -> None:
    with _write_lock:
        conn = get_conn()
        try:
            conn.execute("""
                INSERT INTO normal_logs
                    (timestamp, hostname, event_type, user, ip, raw, source_os)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, hostname, event_type, user, ip, raw, source_os))
            conn.commit()
        finally:
            conn.close()


def insert_malicious_log(
    timestamp: str,
    hostname: str,
    event_type: str,
    user: str,
    ip: str,
    raw: str,
    reason: str,
    severity: str,
    rule: str
) -> None:
    with _write_lock:
        conn = get_conn()
        try:
            conn.execute("""
                INSERT INTO malicious_logs
                    (timestamp, hostname, event_type, user, ip,
                     raw, reason, severity, rule)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, hostname, event_type, user, ip,
                  raw, reason, severity, rule))
            conn.commit()
        finally:
            conn.close()


def insert_blocked_ip(ip: str, reason: str, block_type: str = 'AUTO') -> None:
    """
    Insert a new blocked IP record.
    Always inserts fresh — callers must call unblock_ip (which DELETEs)
    before re-blocking the same IP so history is clean.
    """
    with _write_lock:
        conn = get_conn()
        try:
            now_local = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn.execute("""
                INSERT INTO blocked_ips (ip, reason, block_type, blocked_at)
                VALUES (?, ?, ?, ?)
            """, (ip, reason, block_type, now_local))
            conn.commit()
            log.info("[DATABASE] Blocked IP recorded: %s (%s)", ip, block_type)
        finally:
            conn.close()


def unblock_ip(ip: str) -> None:
    """
    DELETES the blocked_ips row for this IP and clears all its dedup keys
    in a single transaction.  Deletion (vs setting unblocked=1) means the
    next insert_blocked_ip call always creates a clean new row — no conflict,
    no stale state, guaranteed re-block works every time.
    """
    with _write_lock:
        conn = get_conn()
        try:
            deleted = conn.execute(
                "DELETE FROM blocked_ips WHERE ip=?", (ip,)
            ).rowcount
            # Clear dedup keys in same transaction — no race window
            conn.execute(
                "DELETE FROM alert_dedup WHERE dedup_key LIKE ?",
                (f"%{ip}%",)
            )
            conn.commit()
            log.info("[DATABASE] Unblocked IP (deleted %d row(s)) and cleared dedup: %s",
                     deleted, ip)
        finally:
            conn.close()


def acknowledge_alert(alert_id: int) -> None:
    with _write_lock:
        conn = get_conn()
        try:
            conn.execute(
                "UPDATE malicious_logs SET acknowledged=1 WHERE id=?",
                (alert_id,)
            )
            conn.commit()
        finally:
            conn.close()


# ── Read Operations ────────────────────────────────────────────────────────────

def get_stats() -> dict:
    conn = get_conn()
    try:
        return {
            'total_logs':   conn.execute(
                "SELECT COUNT(*) FROM normal_logs").fetchone()[0],
            'total_alerts': conn.execute(
                "SELECT COUNT(*) FROM malicious_logs").fetchone()[0],
            'blocked_ips':  conn.execute(
                "SELECT COUNT(*) FROM blocked_ips").fetchone()[0],
            'critical':     conn.execute(
                "SELECT COUNT(*) FROM malicious_logs "
                "WHERE severity='critical'").fetchone()[0],
            'high':         conn.execute(
                "SELECT COUNT(*) FROM malicious_logs "
                "WHERE severity='high'").fetchone()[0],
            'unacknowledged': conn.execute(
                "SELECT COUNT(*) FROM malicious_logs "
                "WHERE acknowledged=0").fetchone()[0],
        }
    finally:
        conn.close()


def get_recent_alerts(limit: int = 50) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT * FROM malicious_logs
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_blocked_ips() -> list[dict]:
    """Return all currently blocked IPs (active rows in the table)."""
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT * FROM blocked_ips
            ORDER BY id DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_recent_logs(limit: int = 100) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT * FROM normal_logs
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_analytics() -> dict:
    conn = get_conn()
    try:
        breakdown = conn.execute("""
            SELECT rule, COUNT(*) AS count
            FROM malicious_logs
            GROUP BY rule
            ORDER BY count DESC
        """).fetchall()

        daily = conn.execute("""
            SELECT DATE(created_at) AS date, COUNT(*) AS count
            FROM malicious_logs
            GROUP BY DATE(created_at)
            ORDER BY date DESC
            LIMIT 14
        """).fetchall()

        hourly = conn.execute("""
            SELECT CAST(strftime('%H', created_at) AS INTEGER) AS hour,
                   COUNT(*) AS count
            FROM malicious_logs
            GROUP BY hour
            ORDER BY hour
        """).fetchall()

        severity_dist = conn.execute("""
            SELECT severity, COUNT(*) AS count
            FROM malicious_logs
            GROUP BY severity
        """).fetchall()

        return {
            'breakdown':      [dict(r) for r in breakdown],
            'daily':          [dict(r) for r in daily],
            'hourly':         [dict(r) for r in hourly],
            'severity_dist':  [dict(r) for r in severity_dist],
        }
    finally:
        conn.close()


def get_logs_by_ip(ip: str, limit: int = 50) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT * FROM normal_logs
            WHERE ip=?
            ORDER BY id DESC LIMIT ?
        """, (ip, limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def search_logs(query: str, limit: int = 200) -> list[dict]:
    conn = get_conn()
    try:
        pattern = f"%{query}%"
        rows = conn.execute("""
            SELECT * FROM normal_logs
            WHERE raw LIKE ? OR user LIKE ? OR ip LIKE ?
            ORDER BY id DESC LIMIT ?
        """, (pattern, pattern, pattern, limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_all_known_ips() -> set:
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT DISTINCT ip FROM normal_logs
            WHERE raw LIKE '%Accepted password%'
               OR raw LIKE '%Accepted publickey%'
        """).fetchall()
        return {r['ip'] for r in rows}
    finally:
        conn.close()


def get_failed_attempts_in_window(ip: str, window_seconds: int) -> int:
    conn = get_conn()
    try:
        row = conn.execute("""
            SELECT COUNT(*) FROM normal_logs
            WHERE ip=?
              AND (raw LIKE '%Failed password%' OR raw LIKE '%authentication failure%')
              AND created_at >= datetime('now', ? || ' seconds')
        """, (ip, f'-{window_seconds}')).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def get_sudo_failures_in_window(user: str, window_seconds: int) -> int:
    conn = get_conn()
    try:
        row = conn.execute("""
            SELECT COUNT(*) FROM normal_logs
            WHERE user=?
              AND raw LIKE '%sudo%'
              AND (raw LIKE '%incorrect password%' OR raw LIKE '%authentication failure%')
              AND created_at >= datetime('now', ? || ' seconds')
        """, (user, f'-{window_seconds}')).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def get_ips_with_enough_failures(threshold: int, window_seconds: int) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT ip, COUNT(*) AS attempts,
                   MIN(created_at) AS first_seen
            FROM normal_logs
            WHERE (raw LIKE '%Failed password%' OR raw LIKE '%authentication failure%')
              AND created_at >= datetime('now', ? || ' seconds')
            GROUP BY ip
            HAVING attempts >= ?
        """, (f'-{window_seconds}', threshold)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_users_with_sudo_failures(threshold: int, window_seconds: int) -> list[dict]:
    """
    FIX: original query used AND between keyword conditions making it
    impossible to match (a log line can't contain both 'incorrect password'
    AND 'wrong password' AND 'pam_unix' simultaneously).
    Now uses OR so any sudo failure format is detected.

    FIX v2.2: added MIN(created_at) AS first_seen so the detector can build
    a dedup key anchored to when the actual log events were written — not to
    the current clock minute.  This makes the dedup key stable across every
    10-second detector cycle until those specific log rows age out of the
    window, preventing repeated alerts from a single attack session.
    """
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT user, COUNT(*) AS attempts,
                   MAX(ip) AS ip, MAX(hostname) AS hostname,
                   MIN(created_at) AS first_seen
            FROM normal_logs
            WHERE raw LIKE '%sudo%'
              AND (
                  raw LIKE '%incorrect password%'
                  OR raw LIKE '%wrong password%'
                  OR raw LIKE '%authentication failure%'
                  OR raw LIKE '%3 incorrect password attempts%'
                  OR raw LIKE '%sudo: %: command not allowed%'
              )
              AND created_at >= datetime('now', ? || ' seconds')
            GROUP BY user
            HAVING attempts >= ?
        """, (f'-{window_seconds}', threshold)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_successful_logins_in_window(window_seconds: int) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT * FROM normal_logs
            WHERE (raw LIKE '%Accepted password%' OR raw LIKE '%Accepted publickey%')
              AND created_at >= datetime('now', ? || ' seconds')
        """, (f'-{window_seconds}',)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_user_creations_in_window(window_seconds: int) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT * FROM normal_logs
            WHERE (raw LIKE '%useradd%' OR raw LIKE '%new user%' OR raw LIKE '%net user%')
              AND created_at >= datetime('now', ? || ' seconds')
        """, (f'-{window_seconds}',)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def is_ip_blocked(ip: str) -> bool:
    """Fast check — used by blocked_page and alerts_page."""
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT id FROM blocked_ips WHERE ip=?", (ip,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()
