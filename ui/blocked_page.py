"""SIEM Lite — Blocked IPs Page 
"""

import csv, subprocess, os
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QLineEdit, QPushButton, QComboBox,
    QMessageBox, QInputDialog, QFileDialog,
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QColor, QFont
from core    import database
from ui.theme import *


def _time_since(ts_str):
    if not ts_str: return "—"
    try:
        ts = datetime.strptime(ts_str[:19], '%Y-%m-%d %H:%M:%S')
        delta = datetime.now() - ts
        s = int(delta.total_seconds())
        if s < 60:    return f"{s}s ago"
        elif s < 3600: return f"{s//60}m ago"
        elif s < 86400: return f"{s//3600}h ago"
        else:           return f"{s//86400}d ago"
    except:
        return ts_str[:19]


def _mini_stat(title, value, color):
    frame = QFrame(); frame.setObjectName("ms")
    frame.setFixedSize(160, 56)
    frame.setStyleSheet(
        f"QFrame#ms {{ background-color: {BG_CARD}; border: 1px solid {BORDER}; "
        f"border-left: 3px solid {color}; border-radius: 5px; }}"
    )
    fl = QHBoxLayout(frame); fl.setContentsMargins(12, 8, 12, 8)
    vl = QLabel(value)
    vl.setStyleSheet(
        f"QLabel {{ color: {color}; font-size: 22px; font-weight: bold; "
        f"background: transparent; border: none; }}"
    )
    tl = QLabel(title); tl.setWordWrap(True)
    tl.setStyleSheet(
        f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 10px; "
        f"background: transparent; border: none; }}"
    )
    fl.addWidget(vl); fl.addWidget(tl)
    frame._val = vl
    return frame


class BlockedPage(QWidget):
    def __init__(self, current_user=None):
        super().__init__()
        self.current_user = current_user or {}
        self.role = self.current_user.get('role', 'viewer')
        self._active_data = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        hdr_row = QHBoxLayout()
        hdr = QLabel("Blocked IP Management")
        hdr.setStyleSheet(
            f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 20px; font-weight: bold; "
            f"background: transparent; border: none; }}"
        )
        hdr_row.addWidget(hdr); hdr_row.addStretch()
        eb = outline_button("Export CSV"); eb.clicked.connect(self._export_csv)
        hdr_row.addWidget(eb)
        if self.role == 'admin':
            mb = QPushButton("+ Block IP Manually")
            mb.setFixedHeight(32)
            mb.clicked.connect(self._manual_block)
            hdr_row.addWidget(mb)
        layout.addLayout(hdr_row)

        strip = QHBoxLayout(); strip.setSpacing(12)
        self._s_active = _mini_stat("Active Blocks",  "0", CRITICAL)
        self._s_auto   = _mini_stat("Auto Blocked",   "0", HIGH)
        self._s_manual = _mini_stat("Manual Blocked", "0", INFO)
        for s in (self._s_active, self._s_auto, self._s_manual):
            strip.addWidget(s)
        strip.addStretch()
        layout.addLayout(strip)

        fr = QHBoxLayout(); fr.setSpacing(10)
        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍  Search by IP or reason…")
        self._search.setFixedHeight(34)
        self._search.textChanged.connect(self._apply_filters)
        fr.addWidget(self._search)

        tl = QLabel("Type:")
        tl.setStyleSheet(
            f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 11px; "
            f"background: transparent; border: none; }}"
        )
        fr.addWidget(tl)
        self._type_filter = QComboBox()
        self._type_filter.addItems(["All Types", "AUTO", "MANUAL"])
        self._type_filter.setFixedHeight(34); self._type_filter.setFixedWidth(130)
        self._type_filter.currentTextChanged.connect(self._apply_filters)
        fr.addWidget(self._type_filter)
        fr.addStretch()

        cb = QPushButton("Clear"); cb.setFixedHeight(34)
        cb.setStyleSheet(
            f"QPushButton {{ background-color: transparent; color: {TEXT_SECONDARY}; "
            f"border: 1px solid {BORDER}; border-radius: 4px; padding: 0 12px; "
            f"font-size: 11px; font-weight: normal; }}"
        )
        cb.clicked.connect(self._clear_filters)
        fr.addWidget(cb)
        layout.addLayout(fr)

        self._table = self._build_table()
        layout.addWidget(self._table)

        self._active_count = QLabel("0 active blocks")
        self._active_count.setStyleSheet(
            f"QLabel {{ color: {TEXT_MUTED}; font-size: 11px; "
            f"background: transparent; border: none; }}"
        )
        layout.addWidget(self._active_count)

    def _build_table(self):
        cols = ["IP ADDRESS", "REASON", "BLOCKED AT", "DURATION", "TYPE", "ACTION"]
        t = QTableWidget()
        t.setColumnCount(len(cols))
        t.setHorizontalHeaderLabels(cols)
        hh = t.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        for i in range(2, len(cols)):
            hh.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectRows)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        t.setStyleSheet(f"QTableWidget {{ alternate-background-color: {BG_ALT_ROW}; }}")
        return t

    def refresh(self):
        rows = database.get_blocked_ips()
        self._active_data = rows
        self._s_active._val.setText(str(len(rows)))
        self._s_auto._val.setText(str(sum(1 for r in rows if r.get('block_type') == 'AUTO')))
        self._s_manual._val.setText(str(sum(1 for r in rows if r.get('block_type') == 'MANUAL')))
        self._apply_filters()

    def _apply_filters(self):
        search = self._search.text().lower().strip()
        tf = self._type_filter.currentText()
        filtered = [
            r for r in self._active_data
            if (tf == "All Types" or (r.get('block_type') or '').upper() == tf)
            and (not search
                 or search in (r.get('ip', '') or '').lower()
                 or search in (r.get('reason', '') or '').lower())
        ]
        self._populate_table(filtered)
        self._active_count.setText(
            f"{len(filtered)} active block{'s' if len(filtered) != 1 else ''}"
        )

    def _populate_table(self, data):
        self._table.setUpdatesEnabled(False)
        self._table.setRowCount(0)
        for entry in data:
            row = self._table.rowCount()
            self._table.insertRow(row)
            ip       = entry.get('ip', '—')
            reason   = entry.get('reason', '—')
            blocked_at = entry.get('blocked_at', '—')
            btype    = entry.get('block_type', 'AUTO')

            ii = QTableWidgetItem(ip)
            ii.setForeground(QColor(CRITICAL))
            ii.setFont(QFont('Consolas', 11, QFont.Bold))
            self._table.setItem(row, 0, ii)
            self._table.setItem(row, 1, QTableWidgetItem(reason))
            self._table.setItem(row, 2, QTableWidgetItem((blocked_at or '')[:19]))
            self._table.setItem(row, 3, QTableWidgetItem(_time_since(blocked_at)))

            ti = QTableWidgetItem(btype)
            ti.setForeground(QColor(CRITICAL if btype == 'AUTO' else INFO))
            ti.setFont(QFont('Segoe UI', 10, QFont.Bold))
            ti.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 4, ti)

            if self.role == 'admin':
                btn = QPushButton("Unblock")
                btn.setFixedHeight(26)
                btn.setStyleSheet(
                    f"QPushButton {{ background-color: transparent; color: {CRITICAL}; "
                    f"border: 1px solid {CRITICAL}; border-radius: 3px; "
                    f"font-size: 11px; font-weight: bold; padding: 0 10px; }}"
                    f"QPushButton:hover {{ background-color: {CRITICAL_BG}; }}"
                )
                btn.clicked.connect(lambda _, i=ip: self._confirm_unblock(i))
                self._table.setCellWidget(row, 5, btn)
            else:
                lk = QLabel("Admin only")
                lk.setAlignment(Qt.AlignCenter)
                lk.setStyleSheet(
                    f"QLabel {{ color: {TEXT_MUTED}; font-size: 10px; "
                    f"background: transparent; border: none; }}"
                )
                self._table.setCellWidget(row, 5, lk)
        self._table.setUpdatesEnabled(True)

    def _confirm_unblock(self, ip):
        msg = QMessageBox(self)
        msg.setWindowTitle("Confirm Unblock")
        msg.setText(f"Unblock <b>{ip}</b>?")
        msg.setInformativeText(
            "This removes the IP from the blocked list. "
            "If the same attack continues, SIEM Lite will auto-block it again."
        )
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
        msg.setDefaultButton(QMessageBox.Cancel)
        msg.setStyleSheet(
            f"QMessageBox {{ background-color: {BG_CARD}; }} "
            f"QLabel {{ color: {TEXT_PRIMARY}; background: transparent; }} "
            f"QPushButton {{ background-color: {ACCENT}; color: white; border: none; "
            f"padding: 6px 18px; border-radius: 4px; font-weight: bold; min-width: 80px; }}"
        )
        if msg.exec_() == QMessageBox.Yes:
            self._do_unblock(ip)

    def _do_unblock(self, ip):
        # database.unblock_ip DELETEs the row AND clears dedup keys atomically
        database.unblock_ip(ip)
        if ip not in ('127.0.0.1', 'localhost'):
            try:
                subprocess.run(
                    ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                    capture_output=True, timeout=5
                )
            except Exception as exc:
                QMessageBox.warning(
                    self, "iptables Warning",
                    f"DB updated but iptables failed:\n{exc}"
                )
        self.refresh()

    def _manual_block(self):
        ip, ok = QInputDialog.getText(self, "Manual Block", "Enter IP address to block:")
        if not ok or not ip.strip():
            return
        ip = ip.strip()
        parts = ip.split('.')
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            QMessageBox.warning(self, "Invalid IP", f"'{ip}' is not a valid IPv4 address.")
            return
        reason, ok2 = QInputDialog.getText(self, "Block Reason", "Enter reason:")
        if not ok2 or not reason.strip():
            return
        database.insert_blocked_ip(ip, reason.strip(), 'MANUAL')
        if ip not in ('127.0.0.1', 'localhost'):
            try:
                subprocess.run(
                    ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                    capture_output=True, timeout=5
                )
            except Exception as exc:
                QMessageBox.warning(
                    self, "iptables Warning",
                    f"DB updated but iptables failed:\n{exc}"
                )
        self.refresh()

    def _clear_filters(self):
        self._search.clear()
        self._type_filter.setCurrentIndex(0)

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Blocked IPs",
            os.path.expanduser(
                f"~/SIEM_BlockedIPs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            ),
            "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["ip", "reason", "block_type", "blocked_at"],
                    extrasaction='ignore'
                )
                writer.writeheader()
                writer.writerows(self._active_data)
            QMessageBox.information(self, "Export Complete", f"Exported to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))
