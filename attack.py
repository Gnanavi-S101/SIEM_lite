#!/usr/bin/env python3
"""
SIEM Lite — Attack Simulator
Injects fake log entries directly into the database to simulate attacks
without needing actual network traffic or real system commands.

Run from your SIEM Lite project root:
    python simulate_attack.py

Choose attack type at the prompt.
After running, wait ~10-15 seconds for the DetectionEngine to pick it up.

Attacks available:
  1. Brute Force SSH     — 8 failed SSH attempts from a fake IP
  2. Sudo Escalation     — 5 sudo failure logs for a fake user
  3. Off-Hours Login     — 1 successful login (triggers if current hour is off-hours)
  4. New User Creation   — useradd log entry
  5. Combined Attack     — brute force + sudo from same IP
  6. Clean up fake logs  — remove all simulated entries from DB
"""

import sys
import os
import sqlite3
from datetime import datetime, timedelta
import random

# Add project root to path so we can import database
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from core import database
    from config import DB_PATH
except ImportError:
    print("ERROR: Run this script from your SIEM Lite project root directory.")
    print("  cd /path/to/siem_lite")
    print("  python simulate_attack.py")
    sys.exit(1)

# ── Fake attacker details ──────────────────────────────────────────────────────
FAKE_IP       = "10.66.66.66"       # obviously fake
FAKE_USER     = "hacker_test"
FAKE_HOSTNAME = "attacker-vm"
SIM_TAG       = "[SIMULATED]"       # tag so you can find


def _now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _past(seconds_ago: int = 0):
    return (datetime.now() - timedelta(seconds=seconds_ago)).strftime('%Y-%m-%d %H:%M:%S')


def _insert(timestamp, hostname, event_type, user, ip, raw):
    """Insert a single simulated log line into normal_logs."""
    database.insert_normal_log(
        timestamp  = timestamp,
        hostname   = hostname,
        event_type = event_type,
        user       = user,
        ip         = ip,
        raw        = f"{SIM_TAG} {raw}",
        source_os  = 'linux',
    )


# ── Attack 1: Brute Force SSH ──────────────────────────────────────────────────
def simulate_brute_force(ip=FAKE_IP, count=8):
    print(f"\n[SIM] Injecting {count} failed SSH attempts from {ip} ...")
    users = ['root', 'admin', 'ubuntu', 'user', 'test', 'pi', 'guest', 'oracle']
    for i in range(count):
        u = users[i % len(users)]
        ts = _past(seconds_ago=(count - i) * 3)   # spread over last ~24 seconds
        raw = (f"sshd[{1000+i}]: Failed password for invalid user {u} "
               f"from {ip} port {40000+i} ssh2")
        _insert(ts, FAKE_HOSTNAME, 'failed_login', u, ip, raw)
        print(f"  [{i+1}/{count}] {raw[:80]}")
    print(f"[SIM] Done. Wait ~10-15s for the detector to pick this up.")
    print(f"      IP {ip} should appear in Blocked IPs automatically.")


# ── Attack 2: Sudo Escalation ──────────────────────────────────────────────────
def simulate_sudo_failure(user=FAKE_USER, ip=FAKE_IP, count=5):
    print(f"\n[SIM] Injecting {count} sudo failure logs for user '{user}' from {ip} ...")
    for i in range(count):
        ts = _past(seconds_ago=(count - i) * 5)
        raw = (f"sudo[{2000+i}]: {user} : {i+1} incorrect password attempts ; "
               f"TTY=pts/{i} ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash")
        _insert(ts, FAKE_HOSTNAME, 'sudo', user, ip, raw)
        print(f"  [{i+1}/{count}] {raw[:80]}")
    print(f"[SIM] Done. Wait ~10-15s for the Sudo Failure Escalation rule to fire.")
    print(f"      Alert severity: HIGH  |  IP {ip} will be auto-blocked.")


# ── Attack 3: Off-Hours Login ──────────────────────────────────────────────────
def simulate_off_hours_login(ip=FAKE_IP, user=FAKE_USER):
    hour = datetime.now().hour
    from config import OFF_HOURS_START, OFF_HOURS_END
    is_off = (hour >= OFF_HOURS_START) or (hour < OFF_HOURS_END)
    if not is_off:
        print(f"\n[SIM] WARNING: Current hour is {hour:02d}:xx which is NOT off-hours")
        print(f"      Off-hours is {OFF_HOURS_START}:00 – {OFF_HOURS_END}:00.")
        print(f"      The alert won't fire but the log will still be injected.")
    print(f"\n[SIM] Injecting off-hours successful login from {ip} at {_now()} ...")
    raw = (f"sshd[3001]: Accepted password for {user} from {ip} port 52222 ssh2")
    _insert(_now(), FAKE_HOSTNAME, 'successful_login', user, ip, raw)
    print(f"  {raw}")
    if is_off:
        print(f"[SIM] Done. Off-Hours Login alert should fire within ~10-15s.")
    else:
        print(f"[SIM] Log injected. Off-hours rule won't fire at this hour.")


# ── Attack 4: New User Creation ────────────────────────────────────────────────
def simulate_user_creation(ip=FAKE_IP, user="backdoor_user"):
    print(f"\n[SIM] Injecting useradd event for user '{user}' from {ip} ...")
    raw = f"useradd[4001]: new user: name={user}, UID=1337, GID=1337, home=/home/{user}"
    _insert(_now(), FAKE_HOSTNAME, 'user_creation', user, ip, raw)
    print(f"  {raw}")
    print(f"[SIM] Done. New User Creation alert (CRITICAL) should fire within ~10-15s.")


# ── Attack 5: Combined ─────────────────────────────────────────────────────────
def simulate_combined(ip=FAKE_IP):
    print(f"\n[SIM] Combined attack from {ip}: brute force + sudo escalation")
    simulate_brute_force(ip=ip, count=8)
    simulate_sudo_failure(ip=ip, count=5)
    print(f"\n[SIM] Combined attack injected. Two separate alerts will fire.")


# ── Cleanup ────────────────────────────────────────────────────────────────────
def cleanup_simulated():
    print(f"\n[SIM] Removing all simulated log entries ...")
    conn = database.get_conn()
    try:
        with database._write_lock:
            n_logs = conn.execute(
                "DELETE FROM normal_logs WHERE raw LIKE ?", (f"%{SIM_TAG}%",)
            ).rowcount
            n_alerts = conn.execute(
                "DELETE FROM malicious_logs WHERE ip=? OR user=?",
                (FAKE_IP, FAKE_USER)
            ).rowcount
            n_blocked = conn.execute(
                "DELETE FROM blocked_ips WHERE ip=?", (FAKE_IP,)
            ).rowcount
            # Also clear dedup keys
            n_dedup = conn.execute(
                "DELETE FROM alert_dedup WHERE dedup_key LIKE ?",
                (f"%{FAKE_IP}%",)
            ).rowcount
            conn.commit()
    finally:
        conn.close()
    print(f"  Removed {n_logs} normal_logs, {n_alerts} malicious_logs, "
          f"{n_blocked} blocked_ips, {n_dedup} dedup keys.")
    print(f"[SIM] Cleanup complete. DB is clean of simulation data.")


# ── Menu ───────────────────────────────────────────────────────────────────────
def main():
    database.setup()

    print("=" * 58)
    print("  SIEM Lite — Attack Simulator")
    print(f"  Fake IP: {FAKE_IP}  |  Fake User: {FAKE_USER}")
    print("=" * 58)
    print("  1. Brute Force SSH (8 failed attempts)")
    print("  2. Sudo Escalation Failure (5 failures)")
    print("  3. Off-Hours Successful Login")
    print("  4. New User Creation (useradd)")
    print("  5. Combined Attack (brute force + sudo)")
    print("  6. Clean up all simulated data from DB")
    print("  0. Exit")
    print("-" * 58)

    while True:
        try:
            choice = input("Select [0-6]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if   choice == '1': simulate_brute_force()
        elif choice == '2': simulate_sudo_failure()
        elif choice == '3': simulate_off_hours_login()
        elif choice == '4': simulate_user_creation()
        elif choice == '5': simulate_combined()
        elif choice == '6': cleanup_simulated()
        elif choice == '0': break
        else: print("Invalid choice. Enter 0-6.")

        print()


if __name__ == '__main__':
    main()
