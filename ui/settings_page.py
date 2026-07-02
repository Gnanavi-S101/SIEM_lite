"""SIEM Lite — Settings Page """

import os, sys, platform
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QScrollArea
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QColor, QFont
from core    import database
from config  import (BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW,
                     SUDO_FAILURE_THRESHOLD, SUDO_FAILURE_WINDOW,
                     OFF_HOURS_START, OFF_HOURS_END,
                     ML_CONTAMINATION, ML_MIN_SAMPLES, DB_PATH, REPORTS_DIR)
from ui.theme import *


def _info_row(label, value, color=None):
    w = QWidget(); hl = QHBoxLayout(w); hl.setContentsMargins(0,2,0,2)
    ll = QLabel(label); ll.setFixedWidth(220)
    ll.setStyleSheet(f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 11px; background: transparent; border: none; }}")
    hl.addWidget(ll)
    vl = QLabel(str(value))
    vl.setStyleSheet(f"QLabel {{ color: {color or TEXT_PRIMARY}; font-size: 11px; font-family: 'Consolas',monospace; background: transparent; border: none; }}")
    hl.addWidget(vl); hl.addStretch()
    return w

def _status_pill(text, ok=True):
    color = LOW if ok else CRITICAL
    lbl = QLabel(f"  ● {text}  "); lbl.setFixedHeight(22); lbl.setAlignment(Qt.AlignCenter)
    lbl.setStyleSheet(f"QLabel {{ background-color: {'#f0fdf4' if ok else CRITICAL_BG}; color: {color}; border: 1px solid {color}; border-radius: 11px; font-size: 10px; font-weight: bold; letter-spacing: 1px; padding: 0 6px; }}")
    return lbl


class SettingsPage(QWidget):
    def __init__(self, current_user=None):
        super().__init__()
        self.current_user = current_user or {}
        self.role = self.current_user.get('role','viewer')
        self._status_widgets = {}
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self); outer.setContentsMargins(0,0,0,0)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }"); outer.addWidget(scroll)
        container = QWidget(); scroll.setWidget(container)
        layout = QVBoxLayout(container); layout.setContentsMargins(24,24,24,24); layout.setSpacing(24)

        # Header
        hdr_row = QHBoxLayout()
        hdr = QLabel("Settings & System Status")
        hdr.setStyleSheet(f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 20px; font-weight: bold; background: transparent; border: none; }}")
        hdr_row.addWidget(hdr); hdr_row.addStretch()
        self._lr = QLabel("")
        self._lr.setStyleSheet(f"QLabel {{ color: {TEXT_MUTED}; font-size: 10px; background: transparent; border: none; }}")
        hdr_row.addWidget(self._lr)
        layout.addLayout(hdr_row)

        # Live system status cards
        layout.addWidget(section_header("LIVE SYSTEM STATUS"))
        status_row = QHBoxLayout(); status_row.setSpacing(10)
        for key, name in [
            ('collector',  'Log Collector'),
            ('detector',   'Detection Engine'),
            ('ml_engine',  'ML Anomaly Engine'),
            ('database',   'SQLite Database'),
            ('reports',    'Report Generator'),
        ]:
            card = QFrame(); card.setObjectName("sc"); card.setFixedSize(155,72)
            card.setStyleSheet(f"QFrame#sc {{ background-color: {BG_CARD}; border: 1px solid {BORDER}; border-radius: 6px; }}")
            cl = QVBoxLayout(card); cl.setContentsMargins(12,10,12,10); cl.setSpacing(4)
            nl = QLabel(name); nl.setWordWrap(True)
            nl.setStyleSheet(f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 10px; background: transparent; border: none; }}")
            cl.addWidget(nl)
            pill = _status_pill("RUNNING"); cl.addWidget(pill)
            self._status_widgets[key] = pill; status_row.addWidget(card)
        status_row.addStretch(); layout.addLayout(status_row)

        # Lower two columns
        lower = QHBoxLayout(); lower.setSpacing(20)

        # Left — Current Thresholds
        left = QVBoxLayout(); left.setSpacing(8)
        left.addWidget(section_header("CURRENT THRESHOLDS"))
        for label, value, color in [
            ("Brute Force — Failed Attempts",    str(BRUTE_FORCE_THRESHOLD),  CRITICAL),
            ("Brute Force — Window (sec)",       str(BRUTE_FORCE_WINDOW),     CRITICAL),
            ("Sudo Failure — Attempt Count",     str(SUDO_FAILURE_THRESHOLD), HIGH),
            ("Sudo Failure — Window (sec)",      str(SUDO_FAILURE_WINDOW),    HIGH),
            ("Off-Hours Start (24h)",            str(OFF_HOURS_START),        MEDIUM),
            ("Off-Hours End (24h)",              str(OFF_HOURS_END),          MEDIUM),
            ("ML Contamination Factor",          str(ML_CONTAMINATION),       ACCENT),
            ("ML Min Training Samples",          str(ML_MIN_SAMPLES),         ACCENT),
        ]:
            left.addWidget(_info_row(label, value, color))
        if self.role != 'admin':
            note = QLabel("  Thresholds are modified in config.py (admin only)")
            note.setStyleSheet(f"QLabel {{ color: {TEXT_MUTED}; font-size: 10px; background: transparent; border: none; font-style: italic; }}")
            left.addWidget(note)
        left.addStretch(); lower.addLayout(left, stretch=1)

        # Right — DB Stats + About
        right = QVBoxLayout(); right.setSpacing(8)
        right.addWidget(section_header("DATABASE STATISTICS"))
        self._db_container = QVBoxLayout(); self._db_container.setSpacing(4)
        right.addLayout(self._db_container)
        right.addSpacing(16)
        right.addWidget(section_header("ABOUT"))
        for label, value in [
            ("Application", "SIEM Lite"),
            ("Version",     "2.0 Enterprise"),
            ("Python",      sys.version.split()[0]),
            ("Platform",    platform.system() + " " + platform.release()),
            ("DB Path",     DB_PATH),
            ("Reports Dir", REPORTS_DIR),
        ]:
            right.addWidget(_info_row(label, value))
        right.addStretch(); lower.addLayout(right, stretch=1)

        layout.addLayout(lower)
        layout.addStretch()

    def refresh(self):
        self._refresh_db_stats()
        self._refresh_pills()
        self._lr.setText(f"Last refresh: {datetime.now().strftime('%H:%M:%S')}")

    def _refresh_pills(self):
        db_ok = True
        try:
            database.get_stats()
        except:
            db_ok = False
        rep_ok = os.path.isdir(REPORTS_DIR)
        statuses = {
            'collector':  (True,   "RUNNING"),
            'detector':   (True,   "RUNNING"),
            'ml_engine':  (True,   "RUNNING"),
            'database':   (db_ok,  "CONNECTED" if db_ok else "ERROR"),
            'reports':    (rep_ok, "READY"     if rep_ok else "MISSING"),
        }
        for key, (ok, label) in statuses.items():
            pill = self._status_widgets.get(key)
            if not pill:
                continue
            color = LOW if ok else CRITICAL
            bg    = '#f0fdf4' if ok else CRITICAL_BG
            pill.setText(f"  ● {label}  ")
            pill.setStyleSheet(
                f"QLabel {{ background-color: {bg}; color: {color}; "
                f"border: 1px solid {color}; border-radius: 11px; "
                f"font-size: 10px; font-weight: bold; letter-spacing: 1px; padding: 0 6px; }}"
            )

    def _refresh_db_stats(self):
        while self._db_container.count():
            item = self._db_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        try:
            stats   = database.get_stats()
            db_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
            conn    = database.get_conn()
            try:
                dedup = conn.execute(
                    "SELECT COUNT(*) FROM alert_dedup"
                ).fetchone()[0]
            except:
                dedup = 0
            conn.close()
            for label, value, color in [
                ("normal_logs rows",    f"{stats['total_logs']:,}",    INFO),
                ("malicious_logs rows", f"{stats['total_alerts']:,}",  CRITICAL),
                ("blocked_ips rows",    f"{stats['blocked_ips']:,}",   HIGH),
                ("alert_dedup rows",    f"{dedup:,}",                  ACCENT),
                ("Database size",       f"{db_size/(1024*1024):.2f} MB", LOW),
                ("Database path",       DB_PATH,                        TEXT_SECONDARY),
            ]:
                self._db_container.addWidget(_info_row(label, value, color))
        except Exception as exc:
            err = QLabel(f"Cannot read database: {exc}")
            err.setStyleSheet(
                f"QLabel {{ color: {CRITICAL}; font-size: 11px; background: transparent; border: none; }}"
            )
            self._db_container.addWidget(err)
