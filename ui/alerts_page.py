"""SIEM Lite — Alerts Page (beige+pink light theme)

"""

import csv, os, subprocess
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLineEdit, QPushButton, QComboBox, QMessageBox,
    QFileDialog, QAbstractItemView, QFrame,
    QDialog, QTextEdit
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QColor, QFont
from core    import database
from ui.theme import *

RULE_FILTERS = ["All Rules","Brute Force Detection","Off-Hours Login",
                "Sudo Failure Escalation","New User Creation",
                "First-Time IP Login","ML Anomaly Detection"]
SEVERITY_FILTERS = ["All Severities","Critical","High","Medium","Low"]

# Cap on rendered rows — keeps the table snappy regardless of DB size
MAX_VISIBLE_ROWS = 200


# ── helpers ───────────────────────────────────────────────────────────────────
def _is_blocked(ip):
    """Single-IP check — only used by the detail dialog."""
    if not ip or ip in ('—', '0.0.0.0'):
        return False
    try:
        return database.is_ip_blocked(ip)
    except Exception:
        return False

def _sev_item(severity):
    sev   = severity.lower()
    color = SEVERITY_COLOR.get(sev, TEXT_SECONDARY)
    item  = QTableWidgetItem(severity.upper())
    item.setForeground(QColor(color))
    item.setFont(QFont('Segoe UI', 10, QFont.Bold))
    item.setTextAlignment(Qt.AlignCenter)
    return item


# ── Alert Detail dialog ───────────────────────────────────────────────────────
class AlertDetailDialog(QDialog):
    def __init__(self, alert: dict, parent=None):
        super().__init__(parent)
        self.alert = alert
        self.setWindowTitle("Alert Detail")
        self.setMinimumWidth(580)
        self.setStyleSheet(
            f"QDialog {{ background-color: {BG_CARD}; }}"
            f"QLabel  {{ color: {TEXT_PRIMARY}; background: transparent; border: none; }}"
        )
        self._build()

    def _build(self):
        main = QVBoxLayout(self)
        main.setContentsMargins(24, 20, 24, 16)
        main.setSpacing(14)

        title_row = QHBoxLayout()
        title_lbl = QLabel("ALERT DETAIL")
        title_lbl.setStyleSheet(
            f"QLabel {{ color: {ACCENT}; font-size: 13px; font-weight: bold; "
            f"letter-spacing: 2px; background: transparent; border: none; }}"
        )
        title_row.addWidget(title_lbl)
        title_row.addStretch()

        sev       = (self.alert.get('severity') or 'low').lower()
        sev_color = SEVERITY_COLOR.get(sev, TEXT_SECONDARY)
        sev_badge = QLabel(sev.upper())
        sev_badge.setStyleSheet(
            f"QLabel {{ color: {sev_color}; border: 1px solid {sev_color}; "
            f"border-radius: 10px; padding: 2px 14px; font-size: 11px; font-weight: bold; }}"
        )
        title_row.addWidget(sev_badge)
        main.addLayout(title_row)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"QFrame {{ color: {BORDER}; }}")
        main.addWidget(sep)

        grid = QVBoxLayout(); grid.setSpacing(8)
        acked  = self.alert.get('acknowledged', 0)
        status = "✓ Acknowledged" if acked else "Pending"
        fields = [
            ("Timestamp",  (self.alert.get('timestamp') or '')[:19]),
            ("Rule",       self.alert.get('rule', '—')),
            ("IP Address", self.alert.get('ip', '—')),
            ("User",       self.alert.get('user', '—')),
            ("Hostname",   self.alert.get('hostname', '—')),
            ("Event Type", self.alert.get('event_type', '—')),
            ("Reason",     self.alert.get('reason', '—')),
            ("Status",     status),
        ]
        for label, value in fields:
            row = QHBoxLayout()
            lbl = QLabel(label + ":")
            lbl.setFixedWidth(110)
            lbl.setStyleSheet(
                f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 12px; "
                f"background: transparent; border: none; }}"
            )
            val = QLabel(str(value))
            val.setWordWrap(True)
            val.setStyleSheet(
                f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 12px; "
                f"background: transparent; border: none; }}"
            )
            row.addWidget(lbl); row.addWidget(val, 1)
            grid.addLayout(row)
        main.addLayout(grid)

        raw_lbl = QLabel("RAW LOG")
        raw_lbl.setStyleSheet(
            f"QLabel {{ color: {ACCENT}; font-size: 10px; font-weight: bold; "
            f"letter-spacing: 2px; background: transparent; border: none; }}"
        )
        main.addWidget(raw_lbl)
        raw_box = QTextEdit()
        raw_box.setReadOnly(True)
        raw_box.setFixedHeight(72)
        raw_box.setPlainText(self.alert.get('raw', '') or self.alert.get('reason', '—'))
        raw_box.setStyleSheet(
            f"QTextEdit {{ background-color: {BG_TERMINAL}; border: 1px solid {BORDER}; "
            f"border-radius: 5px; color: {ACCENT}; "
            f"font-family: 'Consolas','Courier New',monospace; font-size: 11px; padding: 8px; }}"
        )
        main.addWidget(raw_box)

        btn_row = QHBoxLayout(); btn_row.setSpacing(8)
        btn_row.addStretch()

        ip = self.alert.get('ip', '')
        currently_blocked = _is_blocked(ip)

        if ip and ip not in ('—',):
            self._block_btn = QPushButton(
                f"🚫  Unblock {ip}" if currently_blocked else f"🚫  Block {ip}"
            )
            self._block_btn.setFixedHeight(34)
            self._block_btn.setStyleSheet(self._block_style(currently_blocked))
            self._block_btn.clicked.connect(self._toggle_block)
            btn_row.addWidget(self._block_btn)

        self._ack_btn = QPushButton("✓  Acknowledge")
        self._ack_btn.setFixedHeight(34)
        self._ack_btn.setEnabled(not bool(acked))
        self._ack_btn.setStyleSheet(
            f"QPushButton {{ background-color: {LOW}; color: white; border: none; "
            f"border-radius: 4px; padding: 0 16px; font-size: 12px; font-weight: bold; }}"
            f"QPushButton:hover {{ background-color: #15803d; }}"
            f"QPushButton:disabled {{ background-color: #d1fae5; color: #6ee7b7; }}"
        )
        self._ack_btn.clicked.connect(self._acknowledge)
        btn_row.addWidget(self._ack_btn)

        close_btn = QPushButton("Close")
        close_btn.setFixedHeight(34)
        close_btn.setStyleSheet(
            f"QPushButton {{ background-color: transparent; color: {TEXT_SECONDARY}; "
            f"border: 1px solid {BORDER}; border-radius: 4px; padding: 0 16px; font-size: 12px; }}"
            f"QPushButton:hover {{ color: {TEXT_PRIMARY}; border-color: {TEXT_SECONDARY}; }}"
        )
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        main.addLayout(btn_row)

    def _block_style(self, is_blocked: bool) -> str:
        if is_blocked:
            return (
                f"QPushButton {{ background-color: {HIGH}; color: white; border: none; "
                f"border-radius: 4px; padding: 0 16px; font-size: 12px; font-weight: bold; }}"
                f"QPushButton:hover {{ background-color: #b45309; }}"
            )
        return (
            f"QPushButton {{ background-color: {CRITICAL}; color: white; border: none; "
            f"border-radius: 4px; padding: 0 16px; font-size: 12px; font-weight: bold; }}"
            f"QPushButton:hover {{ background-color: #b91c1c; }}"
        )

    def _toggle_block(self):
        ip = self.alert.get('ip', '')
        if not ip or ip == '—':
            return
        if _is_blocked(ip):
            database.unblock_ip(ip)
            if ip not in ('127.0.0.1', 'localhost'):
                try:
                    subprocess.run(
                        ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                        capture_output=True, timeout=5
                    )
                except Exception:
                    pass
            self._block_btn.setText(f"🚫  Block {ip}")
            self._block_btn.setStyleSheet(self._block_style(False))
            QMessageBox.information(self, "Unblocked", f"{ip} has been unblocked.")
        else:
            reason = (
                f"Manually blocked from Alerts page "
                f"({self.alert.get('rule','')}) — "
                f"{self.alert.get('reason','')}"
            )
            database.insert_blocked_ip(ip, reason, 'MANUAL')
            if ip not in ('127.0.0.1', 'localhost'):
                try:
                    subprocess.run(
                        ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                        capture_output=True, timeout=5
                    )
                except Exception:
                    pass
            self._block_btn.setText(f"🚫  Unblock {ip}")
            self._block_btn.setStyleSheet(self._block_style(True))
            QMessageBox.information(
                self, "Blocked",
                f"{ip} has been blocked and added to Blocked IPs page."
            )

    def _acknowledge(self):
        aid = self.alert.get('id')
        if aid:
            database.acknowledge_alert(aid)
        self._ack_btn.setEnabled(False)
        QMessageBox.information(self, "Acknowledged", "Alert has been acknowledged.")


# ── main page ─────────────────────────────────────────────────────────────────
class AlertsPage(QWidget):
    def __init__(self, current_user=None):
        super().__init__()
        self.current_user = current_user or {}
        self.role         = self.current_user.get('role', 'viewer')
        self._all_alerts  = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        hdr_row = QHBoxLayout()
        hdr = QLabel("Alert Management")
        hdr.setStyleSheet(
            f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 20px; font-weight: bold; "
            f"background: transparent; border: none; }}"
        )
        hdr_row.addWidget(hdr)
        hdr_row.addStretch()

        export_btn = outline_button("Export CSV")
        export_btn.clicked.connect(self._export_csv)
        hdr_row.addWidget(export_btn)

        if self.role in ('admin', 'analyst'):
            self._dismiss_ml_btn = QPushButton("🧹 Dismiss ML False Positives")
            self._dismiss_ml_btn.setFixedHeight(32)
            self._dismiss_ml_btn.setToolTip(
                "Acknowledge all unacknowledged ML Anomaly Detection alerts at once"
            )
            self._dismiss_ml_btn.setStyleSheet(
                f"QPushButton {{ background-color: {HIGH}; color: white; border: none; "
                f"border-radius: 4px; padding: 0 14px; font-size: 11px; font-weight: bold; }}"
                f"QPushButton:hover {{ background-color: #b45309; }}"
            )
            self._dismiss_ml_btn.clicked.connect(self._dismiss_ml_alerts)
            hdr_row.addWidget(self._dismiss_ml_btn)

            self._ack_btn = QPushButton("✓ Acknowledge Selected")
            self._ack_btn.setFixedHeight(32)
            self._ack_btn.setStyleSheet(
                f"QPushButton {{ background-color: {LOW}; color: white; border: none; "
                f"border-radius: 4px; padding: 0 14px; font-size: 11px; font-weight: bold; }}"
                f"QPushButton:hover {{ background-color: #15803d; }}"
            )
            self._ack_btn.clicked.connect(self._acknowledge_selected)
            hdr_row.addWidget(self._ack_btn)
        layout.addLayout(hdr_row)

        filter_row = QHBoxLayout(); filter_row.setSpacing(10)
        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍  Search alerts…")
        self._search.setFixedHeight(34)
        self._search.setMinimumWidth(260)
        self._search.textChanged.connect(self._apply_filters)
        filter_row.addWidget(self._search)

        for lbl_text, attr, items, w in [
            ("Severity:", '_sev_filter',  SEVERITY_FILTERS, 140),
            ("Rule:",     '_rule_filter', RULE_FILTERS,     200),
            ("Status:",   '_ack_filter',  ["All","Unacknowledged","Acknowledged"], 150),
        ]:
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet(
                f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 11px; "
                f"background: transparent; border: none; }}"
            )
            filter_row.addWidget(lbl)
            cb = QComboBox(); cb.addItems(items); cb.setFixedHeight(34); cb.setFixedWidth(w)
            cb.currentTextChanged.connect(self._apply_filters)
            setattr(self, attr, cb)
            filter_row.addWidget(cb)

        filter_row.addStretch()
        clear_btn = QPushButton("Clear")
        clear_btn.setFixedHeight(34)
        clear_btn.setStyleSheet(
            f"QPushButton {{ background-color: transparent; color: {TEXT_SECONDARY}; "
            f"border: 1px solid {BORDER}; border-radius: 4px; padding: 0 12px; "
            f"font-size: 11px; font-weight: normal; }}"
            f"QPushButton:hover {{ color: {TEXT_PRIMARY}; border-color: {TEXT_SECONDARY}; }}"
        )
        clear_btn.clicked.connect(self._clear_filters)
        filter_row.addWidget(clear_btn)
        layout.addLayout(filter_row)

        badge_row = QHBoxLayout(); badge_row.setSpacing(8)
        self._badges = {}
        for sev, color in SEVERITY_COLOR.items():
            badge = QLabel(f"  {sev.upper()}  0  ")
            badge.setFixedHeight(24)
            badge.setStyleSheet(
                f"QLabel {{ background-color: {SEVERITY_BG.get(sev, BG_CARD)}; "
                f"color: {color}; border: 1px solid {color}; border-radius: 12px; "
                f"font-size: 10px; font-weight: bold; letter-spacing: 1px; padding: 0 8px; }}"
            )
            badge.setAlignment(Qt.AlignCenter)
            badge_row.addWidget(badge)
            self._badges[sev] = badge
        badge_row.addStretch()
        layout.addLayout(badge_row)

        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels(
            ["TIMESTAMP", "RULE", "IP ADDRESS", "USER",
             "SEVERITY", "REASON", "STATUS", "ACTIONS"]
        )
        hh = self._table.horizontalHeader()
        # FIX: use fixed/interactive modes — ResizeToContents on every row is slow
        hh.setSectionResizeMode(0, QHeaderView.Interactive)   # timestamp
        hh.setSectionResizeMode(1, QHeaderView.Stretch)       # rule
        hh.setSectionResizeMode(2, QHeaderView.Interactive)   # IP
        hh.setSectionResizeMode(3, QHeaderView.Interactive)   # user
        hh.setSectionResizeMode(4, QHeaderView.Interactive)   # severity
        hh.setSectionResizeMode(5, QHeaderView.Stretch)       # reason
        hh.setSectionResizeMode(6, QHeaderView.Interactive)   # status
        hh.setSectionResizeMode(7, QHeaderView.Interactive)   # actions
        # Set sensible default widths so columns aren't collapsed on start
        self._table.setColumnWidth(0, 148)
        self._table.setColumnWidth(2, 115)
        self._table.setColumnWidth(3, 90)
        self._table.setColumnWidth(4, 80)
        self._table.setColumnWidth(6, 80)
        self._table.setColumnWidth(7, 130)

        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(
            f"QTableWidget {{ alternate-background-color: {BG_ALT_ROW}; }}"
        )
        self._table.clicked.connect(self._on_row_clicked)
        layout.addWidget(self._table)

        footer = QHBoxLayout()
        self._count_label = QLabel("0 alerts")
        self._count_label.setStyleSheet(
            f"QLabel {{ color: {TEXT_MUTED}; font-size: 11px; "
            f"background: transparent; border: none; }}"
        )
        footer.addWidget(self._count_label)
        footer.addStretch()

        tip = QLabel("Click any row for full details  •  Block/Unblock from the Actions column or detail dialog")
        tip.setStyleSheet(
            f"QLabel {{ color: {TEXT_MUTED}; font-size: 10px; "
            f"background: transparent; border: none; }}"
        )
        footer.addWidget(tip)
        layout.addLayout(footer)

    # ── data ──────────────────────────────────────────────────────────────────
    def refresh(self):
        self._all_alerts = database.get_recent_alerts(500)
        self._update_badges()
        self._apply_filters()

    def _update_badges(self):
        counts = {s: 0 for s in SEVERITY_COLOR}
        for a in self._all_alerts:
            sev = (a.get('severity') or 'low').lower()
            if sev in counts:
                counts[sev] += 1
        for sev, lbl in self._badges.items():
            lbl.setText(f"  {sev.upper()}  {counts[sev]}  ")

    def _apply_filters(self):
        search = self._search.text().lower().strip()
        sf = self._sev_filter.currentText()
        rf = self._rule_filter.currentText()
        af = self._ack_filter.currentText()
        filtered = []
        for a in self._all_alerts:
            sev   = (a.get('severity') or 'low').lower()
            rule  = a.get('rule', '')
            acked = a.get('acknowledged', 0)
            if sf != "All Severities" and sev != sf.lower():   continue
            if rf != "All Rules"      and rule != rf:           continue
            if af == "Unacknowledged" and acked:                continue
            if af == "Acknowledged"   and not acked:            continue
            if search and search not in " ".join(str(v) for v in a.values()).lower():
                continue
            filtered.append(a)
        self._populate_table(filtered)
        n = len(filtered)
        total = len(self._all_alerts)
        suffix = f" (showing {MAX_VISIBLE_ROWS})" if n > MAX_VISIBLE_ROWS else ""
        self._count_label.setText(
            f"{n} alert{'s' if n != 1 else ''} of {total} total{suffix}"
        )

    def _populate_table(self, alerts):
        # Cap rendered rows — the main perf fix for large alert counts
        render_alerts = alerts[:MAX_VISIBLE_ROWS]

        # Fetch blocked IPs once — O(1) set lookup per row
        blocked_set = {r['ip'] for r in database.get_blocked_ips()}

        # Freeze repaints — single flush at the end
        self._table.setUpdatesEnabled(False)
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)

        font_bold = QFont('Segoe UI', 10, QFont.Bold)

        for alert in render_alerts:
            row = self._table.rowCount()
            self._table.insertRow(row)

            sev   = (alert.get('severity') or 'low').lower()
            acked = alert.get('acknowledged', 0)
            bg    = QColor(SEVERITY_BG.get(sev, BG_CARD))
            status = "✓ Acked" if acked else "Pending"
            ip    = alert.get('ip', '—') or '—'

            vals = [
                (alert.get('timestamp') or '')[:19],
                alert.get('rule', ''),
                ip,
                alert.get('user', ''),
                sev,
                alert.get('reason', ''),
                status,
            ]
            for col, val in enumerate(vals):
                if col == 4:
                    item = _sev_item(val)
                elif col == 6:
                    item = QTableWidgetItem(status)
                    item.setForeground(QColor(LOW if acked else TEXT_MUTED))
                    item.setTextAlignment(Qt.AlignCenter)
                else:
                    item = QTableWidgetItem(str(val))
                if col == 0:
                    item.setData(Qt.UserRole, alert)
                item.setBackground(bg)
                self._table.setItem(row, col, item)

            actions_widget = self._make_actions_widget(ip, alert, blocked_set)
            self._table.setCellWidget(row, 7, actions_widget)

        self._table.setSortingEnabled(True)
        self._table.setUpdatesEnabled(True)

    def _make_actions_widget(self, ip: str, alert: dict, blocked_set: set) -> QWidget:
        w  = QWidget()
        hl = QHBoxLayout(w)
        hl.setContentsMargins(4, 2, 4, 2)
        hl.setSpacing(4)

        blocked   = ip in blocked_set
        block_btn = QPushButton("Unblock" if blocked else "Block")
        block_btn.setFixedHeight(24)
        block_btn.setStyleSheet(self._block_btn_style(blocked))
        block_btn.clicked.connect(
            lambda _, i=ip, a=alert, b=block_btn: self._toggle_block(i, a, b)
        )
        hl.addWidget(block_btn)

        acked   = alert.get('acknowledged', 0)
        ack_btn = QPushButton("✓ Ack")
        ack_btn.setFixedHeight(24)
        ack_btn.setEnabled(not bool(acked))
        ack_btn.setStyleSheet(
            f"QPushButton {{ background-color: transparent; color: {LOW}; "
            f"border: 1px solid {LOW}; border-radius: 3px; "
            f"font-size: 11px; font-weight: bold; padding: 0 8px; }}"
            f"QPushButton:hover {{ background-color: #d1fae5; }}"
            f"QPushButton:disabled {{ color: #a7f3d0; border-color: #a7f3d0; }}"
        )
        aid = alert.get('id')
        ack_btn.clicked.connect(lambda _, a=aid, b=ack_btn: self._acknowledge_by_id(a, b))
        hl.addWidget(ack_btn)

        return w

    def _block_btn_style(self, is_blocked: bool) -> str:
        if is_blocked:
            return (
                f"QPushButton {{ background-color: transparent; color: {HIGH}; "
                f"border: 1px solid {HIGH}; border-radius: 3px; "
                f"font-size: 11px; font-weight: bold; padding: 0 8px; }}"
                f"QPushButton:hover {{ background-color: #fef3c7; }}"
            )
        return (
            f"QPushButton {{ background-color: transparent; color: {CRITICAL}; "
            f"border: 1px solid {CRITICAL}; border-radius: 3px; "
            f"font-size: 11px; font-weight: bold; padding: 0 8px; }}"
            f"QPushButton:hover {{ background-color: {CRITICAL_BG}; }}"
        )

    def _toggle_block(self, ip: str, alert: dict, btn: QPushButton):
        if not ip or ip == '—':
            return
        if _is_blocked(ip):
            database.unblock_ip(ip)
            if ip not in ('127.0.0.1', 'localhost'):
                try:
                    subprocess.run(
                        ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                        capture_output=True, timeout=5
                    )
                except Exception:
                    pass
            btn.setText("Block")
            btn.setStyleSheet(self._block_btn_style(False))
            QMessageBox.information(self, "Unblocked", f"{ip} has been unblocked.")
        else:
            reason = (
                f"Manually blocked from Alerts page "
                f"({alert.get('rule','')}) — {alert.get('reason','')}"
            )
            database.insert_blocked_ip(ip, reason, 'MANUAL')
            if ip not in ('127.0.0.1', 'localhost'):
                try:
                    subprocess.run(
                        ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                        capture_output=True, timeout=5
                    )
                except Exception:
                    pass
            btn.setText("Unblock")
            btn.setStyleSheet(self._block_btn_style(True))
            QMessageBox.information(
                self, "Blocked",
                f"{ip} blocked and added to Blocked IPs page."
            )

    def _on_row_clicked(self, index):
        if index.column() == 7:
            return
        item = self._table.item(index.row(), 0)
        if not item:
            return
        alert = item.data(Qt.UserRole)
        if not alert:
            return
        dlg = AlertDetailDialog(alert, parent=self)
        dlg.exec_()
        self.refresh()

    def _acknowledge_selected(self):
        done = set()
        for item in self._table.selectedItems():
            r = item.row()
            if r in done:
                continue
            done.add(r)
            id_item = self._table.item(r, 0)
            if id_item:
                alert = id_item.data(Qt.UserRole)
                if alert and alert.get('id'):
                    database.acknowledge_alert(alert['id'])
        self.refresh()

    def _acknowledge_by_id(self, aid, btn: QPushButton = None):
        if aid:
            database.acknowledge_alert(aid)
        if btn:
            btn.setEnabled(False)
        self.refresh()

    def _dismiss_ml_alerts(self):
        ml_alerts = [
            a for a in self._all_alerts
            if a.get('rule') == 'ML Anomaly Detection'
            and not a.get('acknowledged', 0)
        ]
        if not ml_alerts:
            QMessageBox.information(
                self, "Nothing to dismiss",
                "No unacknowledged ML Anomaly alerts found."
            )
            return

        msg = QMessageBox(self)
        msg.setWindowTitle("Dismiss ML False Positives")
        msg.setText(f"Acknowledge all <b>{len(ml_alerts)}</b> ML Anomaly Detection alerts?")
        msg.setInformativeText(
            "This marks them all as acknowledged so they stop cluttering your view. "
            "They will remain in the database and history."
        )
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
        msg.setDefaultButton(QMessageBox.Cancel)
        if msg.exec_() != QMessageBox.Yes:
            return

        conn = database.get_conn()
        try:
            with database._write_lock:
                conn.execute(
                    "UPDATE malicious_logs SET acknowledged=1 "
                    "WHERE rule='ML Anomaly Detection' AND acknowledged=0"
                )
                conn.commit()
        finally:
            conn.close()

        self.refresh()
        QMessageBox.information(
            self, "Done",
            f"Dismissed {len(ml_alerts)} ML Anomaly alerts."
        )

    def _clear_filters(self):
        self._search.clear()
        self._sev_filter.setCurrentIndex(0)
        self._rule_filter.setCurrentIndex(0)
        self._ack_filter.setCurrentIndex(0)

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Alerts",
            os.path.expanduser(
                f"~/SIEM_Alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            ),
            "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["timestamp","rule","ip","user","severity","reason","acknowledged"],
                    extrasaction='ignore'
                )
                writer.writeheader()
                writer.writerows(self._all_alerts)
            QMessageBox.information(
                self, "Export Complete",
                f"Exported {len(self._all_alerts)} alerts to:\n{path}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))
