"""
SIEM Lite — Central Configuration
All tuneable constants live here. Never hardcode values in modules.
"""

import os

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, 'siem_lite.db')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

# Create reports directory on import so modules never have to worry about it
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Network ────────────────────────────────────────────────────────────────────
SERVER_HOST    = '0.0.0.0'
SERVER_PORT    = 5000
BUFFER_SIZE    = 8192        # bytes — handles log lines up to 8 KB
SOCKET_TIMEOUT = 1           # seconds per client connection

# ── Detection Thresholds ───────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD  = 5   # failed SSH attempts before alert
BRUTE_FORCE_WINDOW     = 300 # seconds — rolling window for brute force count (5 min)
SUDO_FAILURE_THRESHOLD = 3   # sudo failures before alert
SUDO_FAILURE_WINDOW    = 300 # seconds — rolling window for sudo failures
OFF_HOURS_START        = 22  # 10 PM
OFF_HOURS_END          = 6   # 6 AM

# ── Collector ──────────────────────────────────────────────────────────────────
COLLECT_INTERVAL   = 5      # seconds between local journalctl polls
SEEN_LOG_MAX_SIZE  = 10_000  # max entries in the dedup set before it is pruned

# ── ML Engine ──────────────────────────────────────────────────────────────────
ML_CONTAMINATION     = 0.05  # expected anomaly fraction (conservative)
ML_MIN_SAMPLES       = 100   # minimum logs required before training
ML_RETRAIN_INTERVAL  = 100  # seconds between model retrains (1 hour)
ML_DETECT_INTERVAL   = 10    # seconds between anomaly scans
ML_LOOKBACK_MINUTES  = 2     # how far back the detect pass looks each cycle

# ── Dashboard Refresh ──────────────────────────────────────────────────────────
UI_REFRESH_INTERVAL  = 3_000  # milliseconds (10 s)

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_LEVEL = 'INFO'           # DEBUG | INFO | WARNING | ERROR

# ── Static Users (replace with DB-backed auth for production) ─────────────────
USERS = {
    'admin':   {'password': 'admin123',   'role': 'admin'},
    'analyst': {'password': 'analyst123', 'role': 'analyst'},
    'viewer':  {'password': 'viewer123',  'role': 'viewer'},
}
