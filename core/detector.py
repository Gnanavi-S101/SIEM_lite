"""
SIEM Lite — Rule-Based Detection Engine
Evaluates 5 detection rules against normalised log data on a fixed interval.

Rules:
  1. Brute Force Detection      — N failed SSH attempts from same IP in window
  2. Off-Hours Login            — Successful login between 22:00 and 06:00
  3. Sudo Failure Escalation    — N sudo failures from same user in window
  4. New User Creation          — useradd / net user detected
  5. First-Time IP Login        — Successful login from previously unseen IP

"""

import subprocess
import threading
import time
import logging
from datetime import datetime

from core import database
from config import (
    BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW,
    SUDO_FAILURE_THRESHOLD, SUDO_FAILURE_WINDOW,
    OFF_HOURS_START, OFF_HOURS_END,
)

log = logging.getLogger(__name__)

_SHORT_WINDOW = 120


class DetectionEngine:

    def __init__(self):
        self.running   = False
        self._callbacks: list = []
        self._lock     = threading.Lock()

    def add_callback(self, func) -> None:
        with self._lock:
            self._callbacks.append(func)

    def start(self) -> None:
        t = threading.Thread(
            target=self._run, name="detector", daemon=True
        )
        t.start()
        log.info("[DETECTOR] Started")

    def stop(self) -> None:
        self.running = False
        log.info("[DETECTOR] Stopped")

    def _run(self) -> None:
        self.running = True
        while self.running:
            try:
                self._rule_brute_force()
                self._rule_off_hours_login()
                self._rule_sudo_failure()
                self._rule_new_user_creation()
                self._rule_first_time_ip()
            except Exception as exc:
                log.error("[DETECTOR] Unexpected error in detection loop: %s", exc)
            time.sleep(10)

    def _raise_alert(self, alert: dict) -> None:
        database.insert_malicious_log(
            timestamp  = alert['timestamp'],
            hostname   = alert['hostname'],
            event_type = alert['event_type'],
            user       = alert['user'],
            ip         = alert['ip'],
            raw        = alert['raw'],
            reason     = alert['reason'],
            severity   = alert['severity'],
            rule       = alert['rule'],
        )
        with self._lock:
            callbacks = list(self._callbacks)
        for cb in callbacks:
            try:
                cb(alert)
            except Exception as exc:
                log.warning("[DETECTOR] Callback error: %s", exc)

    def _now(self) -> str:
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _block_ip(self, ip: str, reason: str = 'Auto-Block') -> None:
        """
        Block an IP via iptables and record in DB.
        Guards against double-insert — if the IP is already in blocked_ips
        (e.g. from a parallel detection cycle) we skip the insert.
        Loopback IPs get a DB record for demo visibility but skip iptables.
        """
        if not ip or ip == 'unknown':
            log.info("[DETECTOR] Skipping block — IP unknown")
            return

        # Guard: don't insert duplicate blocked_ips rows
        if database.is_ip_blocked(ip):
            log.debug("[DETECTOR] IP already blocked, skipping insert: %s", ip)
            return

        database.insert_blocked_ip(ip, reason, 'AUTO')

        if ip in ('127.0.0.1', 'localhost'):
            log.info("[DETECTOR] Local attack — DB recorded, skipping iptables for %s", ip)
            return

        try:
            result = subprocess.run(
                ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                log.info("[DETECTOR] Auto-blocked %s — reason: %s", ip, reason)
            else:
                log.warning("[DETECTOR] iptables returned non-zero for %s: %s",
                            ip, result.stderr.decode())
        except FileNotFoundError:
            log.warning("[DETECTOR] iptables not found — skipping block for %s", ip)
        except subprocess.TimeoutExpired:
            log.warning("[DETECTOR] iptables timed out blocking %s", ip)
        except Exception as exc:
            log.error("[DETECTOR] Could not block %s: %s", ip, exc)

    # ── Rule 1 — Brute Force Detection ────────────────────────────────────────

    def _rule_brute_force(self) -> None:
        candidates = database.get_ips_with_enough_failures(
            BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW
        )
        for row in candidates:
            ip       = row['ip']
            attempts = row['attempts']

            # FIX v2.2: dedup key anchored to first_seen (the earliest log
            # entry timestamp for this IP in the window), truncated to the
            # minute.  This key is STABLE across every 10-second detector
            # cycle — the same attack session always produces the same key,
            # so we only alert once per attack session.
            # When the user unblocks, unblock_ip() clears this key from
            # alert_dedup.  The old log rows are still in normal_logs, so
            # the detector re-queries them and fires exactly ONE new alert
            # (and re-block) — then stays silent until a new attack creates
            # new log rows with a new first_seen value.
            first_seen = row.get('first_seen', self._now())[:16]
            dedup = f"brute_force:{ip}:{first_seen}"

            if database.is_duplicate_alert(dedup):
                continue

            database.register_alert(dedup)
            alert = {
                'timestamp':  self._now(),
                'hostname':   'unknown',
                'event_type': 'brute_force',
                'user':       'unknown',
                'ip':         ip,
                'raw':        f'Brute force: {attempts} failed attempts in {BRUTE_FORCE_WINDOW}s',
                'reason':     f'{attempts} failed SSH attempts within {BRUTE_FORCE_WINDOW}s window',
                'severity':   'critical',
                'rule':       'Brute Force Detection',
            }
            self._raise_alert(alert)
            self._block_ip(ip, f'Brute Force Auto-Block — {attempts} failed attempts')
            log.warning("[ALERT][CRITICAL] Brute Force — IP: %s, attempts: %d", ip, attempts)

    # ── Rule 2 — Off-Hours Login ───────────────────────────────────────────────

    def _rule_off_hours_login(self) -> None:
        hour = datetime.now().hour
        is_off_hours = (hour >= OFF_HOURS_START) or (hour < OFF_HOURS_END)
        if not is_off_hours:
            return

        logins = database.get_successful_logins_in_window(_SHORT_WINDOW)
        for row in logins:
            ip   = row.get('ip',   'unknown')
            user = row.get('user', 'unknown')
            dedup = f"off_hours:{ip}:{user}:{hour}"

            if database.is_duplicate_alert(dedup):
                continue

            database.register_alert(dedup)
            alert = {
                'timestamp':  self._now(),
                'hostname':   row.get('hostname', 'unknown'),
                'event_type': 'off_hours_login',
                'user':       user,
                'ip':         ip,
                'raw':        row.get('raw', ''),
                'reason':     f'Successful login at off-hours ({hour:02d}:00)',
                'severity':   'high',
                'rule':       'Off-Hours Login',
            }
            self._raise_alert(alert)
            self._block_ip(ip, f'Off-Hours Login Auto-Block — user: {user} at {hour:02d}:00')
            log.warning("[ALERT][HIGH] Off-Hours Login — user: %s, ip: %s, hour: %d",
                        user, ip, hour)

    # ── Rule 3 — Sudo Failure Escalation ──────────────────────────────────────

    def _rule_sudo_failure(self) -> None:
        candidates = database.get_users_with_sudo_failures(
            SUDO_FAILURE_THRESHOLD, SUDO_FAILURE_WINDOW
        )
        for row in candidates:
            user     = row['user']
            attempts = row['attempts']
            ip       = row.get('ip', 'unknown')

            # FIX v2.2: same first_seen anchor as brute force rule above.
            # The dedup key is tied to the earliest sudo failure log entry
            # for this user, not the current clock minute.  This means:
            #
            #   1. One attack session (e.g. 5 wrong passwords) → exactly
            #      ONE alert + block, no matter how many 10-second cycles
            #      run while those log rows remain in the window.
            #
            #   2. Unblock clears this dedup key via unblock_ip().  The old
            #      log rows are still there, so the next detector cycle fires
            #      ONE re-alert + re-block (expected — evidence still exists).
            #      Then silence, until the user simulates a NEW attack whose
            #      new log rows have a different first_seen timestamp.
            #
            #   3. A genuinely new attack (new log rows, new first_seen) gets
            #      a new dedup key → new alert + block, even for the same IP.
            first_seen = row.get('first_seen', self._now())[:16]
            dedup = f"sudo_failure:{user}:{ip}:{first_seen}"

            if database.is_duplicate_alert(dedup):
                continue

            database.register_alert(dedup)
            alert = {
                'timestamp':  self._now(),
                'hostname':   row.get('hostname', 'unknown'),
                'event_type': 'sudo_failure',
                'user':       user,
                'ip':         ip,
                'raw':        f'Sudo failure escalation: {attempts} failures in {SUDO_FAILURE_WINDOW}s',
                'reason':     f'{attempts} sudo failures within {SUDO_FAILURE_WINDOW}s window',
                'severity':   'high',
                'rule':       'Sudo Failure Escalation',
            }
            self._raise_alert(alert)
            self._block_ip(ip, f'Sudo Failure Auto-Block — {attempts} failures by {user}')
            log.warning("[ALERT][HIGH] Sudo Failure — user: %s, attempts: %d, ip: %s",
                        user, attempts, ip)

    # ── Rule 4 — New User Creation ─────────────────────────────────────────────

    def _rule_new_user_creation(self) -> None:
        events = database.get_user_creations_in_window(_SHORT_WINDOW)
        for row in events:
            user      = row.get('user', 'unknown')
            ip        = row.get('ip', 'unknown')
            ts_minute = self._now()[:16]
            dedup     = f"new_user:{user}:{ip}:{ts_minute}"

            if database.is_duplicate_alert(dedup):
                continue

            database.register_alert(dedup)
            alert = {
                'timestamp':  self._now(),
                'hostname':   row.get('hostname', 'unknown'),
                'event_type': 'new_user_creation',
                'user':       user,
                'ip':         ip,
                'raw':        row.get('raw', ''),
                'reason':     'New user account created via useradd / net user',
                'severity':   'critical',
                'rule':       'New User Creation',
            }
            self._raise_alert(alert)
            self._block_ip(ip, f'Suspicious User Creation Auto-Block — new user: {user}')
            log.warning("[ALERT][CRITICAL] New User Created — user: %s, ip: %s", user, ip)

    # ── Rule 5 — First-Time IP Login ───────────────────────────────────────────

    def _rule_first_time_ip(self) -> None:
        known_ips = database.get_all_known_ips()
        recent    = database.get_successful_logins_in_window(_SHORT_WINDOW)

        for row in recent:
            ip   = row.get('ip', 'unknown')
            user = row.get('user', 'unknown')

            if ip in ('unknown', '127.0.0.1'):
                continue

            conn   = database.get_conn()
            count  = conn.execute(
                "SELECT COUNT(*) FROM normal_logs "
                "WHERE ip=? AND (raw LIKE '%Accepted password%' "
                "OR raw LIKE '%Accepted publickey%')",
                (ip,)
            ).fetchone()[0]
            conn.close()

            if count != 1:
                continue

            bucket = datetime.now().strftime('%Y%m%d%H')
            dedup = f"first_time_ip:{ip}:{bucket}"
            if database.is_duplicate_alert(dedup):
                continue

            database.register_alert(dedup)
            alert = {
                'timestamp':  self._now(),
                'hostname':   row.get('hostname', 'unknown'),
                'event_type': 'first_time_ip',
                'user':       user,
                'ip':         ip,
                'raw':        row.get('raw', ''),
                'reason':     f'Successful login from previously unseen IP: {ip}',
                'severity':   'medium',
                'rule':       'First-Time IP Login',
            }
            self._raise_alert(alert)
            self._block_ip(ip, f'First-Time IP Auto-Block — user: {user}, IP: {ip}')
            log.warning("[ALERT][MEDIUM] First-Time IP — ip: %s, user: %s", ip, user)
