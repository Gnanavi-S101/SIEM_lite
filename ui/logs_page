"""SIEM Lite — Log Viewer Page
   Fast & simple: single-click opens detail dialog. No block logic here.

   FIXES v2.1:
   - Replaced ResizeToContents on all columns with fixed/stretch widths.
     ResizeToContents iterates every cell to calculate width — with 500+ rows
     this causes a visible freeze on every refresh. Fixed widths are instant.
   - Added MAX_VISIBLE_ROWS cap (500) — DB can hold thousands but we only
     render the most recent 500 to keep the table responsive.
   - setUpdatesEnabled(False/True) wraps the table fill (was already partially
     there but now consistent).
"""

import csv, os
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QLineEdit, QPushButton, QComboBox,
    QTextEdit, QFileDialog, QMessageBox,
    QDialog, QFrame, QAbstractItemView
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QColor, QFont
from core    import database
from ui.theme import *

EVENT_TYPES = ["All Events","failed_login","successful_login","sudo",
               "user_creation","user_deletion","ssh","ssh_disconnect",
               "cron","system","kernel","firewall","general"]
OS_FILTERS  = ["All OS","linux","windows","unknown"]

# Cap rendered rows — DB can have thousands, we show the freshest 500
MAX_VISIBLE_ROWS = 500

EVENT_COLORS = {
    'failed_login':     CRITICAL,
    'successful_login': LOW,
    'sudo':             HIGH,
    'user_creation':    '#c2410c',
    'user_deletion':    CRITICAL,
    'ssh':              INFO,
    'ssh_disconnect':   TEXT_SECONDARY,
    'kernel':           '#6d28d9',
    'firewall':         CRITICAL,
    'cron':             '#0e7490',
    'system':           LOW,
    'general':          TEXT_MUTED,
}


class LogDetailDialog(QDialog):
    def __init__(self, log: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Log Detail")
        self.setMinimumWidth(520)
        self.setStyleSheet(
            f"QDialog{{background:{BG_CARD};}}"
            f"QLabel{{color:{TEXT_PRIMARY};background:transparent;border:none;}}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 18, 24, 16)
        layout.setSpacing(12)

        top = QHBoxLayout()
        t = QLabel("LOG DETAIL")
        t.setStyleSheet(f"QLabel{{color:{ACCENT};font-size:13px;font-weight:bold;"
                        f"letter-spacing:2px;background:transparent;border:none;}}")
        top.addWidget(t); top.addStretch()
        et       = log.get('event_type','general')
        et_color = EVENT_COLORS.get(et, TEXT_MUTED)
        badge    = QLabel(et.upper().replace('_',' '))
        badge.setStyleSheet(f"QLabel{{color:{et_color};border:1px solid {et_color};"
                            f"border-radius:10px;padding:2px 12px;"
                            f"font-size:11px;font-weight:bold;}}")
        top.addWidget(badge)
        layout.addLayout(top)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"QFrame{{color:{BORDER};}}")
        layout.addWidget(sep)

        lbl_style = (f"color:{TEXT_SECONDARY};font-size:12px;"
                     f"background:transparent;border:none;")
        val_style = (f"color:{TEXT_PRIMARY};font-size:12px;"
                     f"background:transparent;border:none;")
        for label, value in [
            ("Timestamp",  (log.get('timestamp') or '')[:19]),
            ("Hostname",   log.get('hostname','—')),
            ("Event Type", et.replace('_',' ')),
            ("User",       log.get('user','—')),
            ("IP Address", log.get('ip','—')),
            ("Source OS",  log.get('source_os','—')),
        ]:
            row = QHBoxLayout()
            l = QLabel(label + ":"); l.setFixedWidth(100)
            l.setStyleSheet(f"QLabel{{{lbl_style}}}")
            v = QLabel(str(value))
            v.setStyleSheet(f"QLabel{{{val_style}}}")
            row.addWidget(l); row.addWidget(v); row.addStretch()
            layout.addLayout(row)

        rl = QLabel("RAW LOG")
        rl.setStyleSheet(f"QLabel{{color:{ACCENT};font-size:10px;font-weight:bold;"
                         f"letter-spacing:2px;background:transparent;border:none;}}")
        layout.addWidget(rl)
        raw = QTextEdit(); raw.setReadOnly(True); raw.setFixedHeight(72)
        raw.setPlainText(log.get('raw','—') or '—')
        raw.setStyleSheet(
            f"QTextEdit{{background:{BG_TERMINAL};border:1px solid {BORDER};"
            f"border-radius:5px;color:{ACCENT};"
            f"font-family:'Consolas','Courier New',monospace;"
            f"font-size:11px;padding:8px;}}"
        )
        layout.addWidget(raw)

        btn_row = QHBoxLayout(); btn_row.addStretch()
        close = QPushButton("Close"); close.setFixedHeight(32)
        close.setStyleSheet(
            f"QPushButton{{background:transparent;color:{TEXT_SECONDARY};"
            f"border:1px solid {BORDER};border-radius:4px;"
            f"padding:0 18px;font-size:12px;}}"
            f"QPushButton:hover{{color:{TEXT_PRIMARY};border-color:{TEXT_SECONDARY};}}"
        )
        close.clicked.connect(self.accept)
        btn_row.addWidget(close)
        layout.addLayout(btn_row)


class LogsPage(QWidget):
    def __init__(self, current_user=None):
        super().__init__()
        self.current_user = current_user or {}
        self._all_logs    = []
        self._live_tail   = True
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        hdr_row = QHBoxLayout()
        hdr = QLabel("Log Viewer")
        hdr.setStyleSheet(f"QLabel{{color:{TEXT_PRIMARY};font-size:20px;"
                          f"font-weight:bold;background:transparent;border:none;}}")
        hdr_row.addWidget(hdr); hdr_row.addStretch()

        self._tail_btn = QPushButton("⏸  Pause Live Tail")
        self._tail_btn.setFixedHeight(32); self._tail_btn.setCheckable(True)
        self._tail_btn.setStyleSheet(
            f"QPushButton{{background:{LOW};color:white;border:none;"
            f"border-radius:4px;padding:0 14px;font-size:11px;font-weight:bold;}}"
            f"QPushButton:checked{{background:{HIGH};}}"
        )
        self._tail_btn.clicked.connect(self._toggle_tail)
        hdr_row.addWidget(self._tail_btn)

        eb = outline_button("Export CSV"); eb.clicked.connect(self._export_csv)
        hdr_row.addWidget(eb)
        layout.addLayout(hdr_row)

        fr = QHBoxLayout(); fr.setSpacing(10)
        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍  Search logs — IP, user, hostname, raw…")
        self._search.setFixedHeight(34); self._search.setMinimumWidth(260)
        self._search.textChanged.connect(self._apply_filters)
        fr.addWidget(self._search)

        for lbl_text, attr, items, w in [
            ("Event:", '_event_filter', EVENT_TYPES, 160),
            ("OS:",    '_os_filter',    OS_FILTERS,  110),
        ]:
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet(f"QLabel{{color:{TEXT_SECONDARY};font-size:11px;"
                              f"background:transparent;border:none;}}")
            fr.addWidget(lbl)
            cb = QComboBox(); cb.addItems(items)
            cb.setFixedHeight(34); cb.setFixedWidth(w)
            cb.currentTextChanged.connect(self._apply_filters)
            setattr(self, attr, cb); fr.addWidget(cb)

        fr.addStretch()
        clr = QPushButton("Clear"); clr.setFixedHeight(34)
        clr.setStyleSheet(
            f"QPushButton{{background:transparent;color:{TEXT_SECONDARY};"
            f"border:1px solid {BORDER};border-radius:4px;"
            f"padding:0 12px;font-size:11px;}}"
        )
        clr.clicked.connect(self._clear_filters); fr.addWidget(clr)
        layout.addLayout(fr)

        self._table = QTableWidget()
        self._table.setColumnCount(6)
        self._table.setHorizontalHeaderLabels(
            ["TIMESTAMP","HOSTNAME","EVENT TYPE","USER","IP","SOURCE OS"]
        )
        hh = self._table.horizontalHeader()

        # FIX: fixed widths instead of ResizeToContents — massive speed improvement
        # ResizeToContents scans every cell on every repaint — O(n) per column = O(6n) freeze
        hh.setSectionResizeMode(0, QHeaderView.Interactive)   # timestamp
        hh.setSectionResizeMode(1, QHeaderView.Interactive)   # hostname
        hh.setSectionResizeMode(2, QHeaderView.Interactive)   # event type
        hh.setSectionResizeMode(3, QHeaderView.Interactive)   # user
        hh.setSectionResizeMode(4, QHeaderView.Interactive)   # IP
        hh.setSectionResizeMode(5, QHeaderView.Stretch)       # source OS (fills remainder)
        self._table.setColumnWidth(0, 148)
        self._table.setColumnWidth(1, 130)
        self._table.setColumnWidth(2, 140)
        self._table.setColumnWidth(3, 90)
        self._table.setColumnWidth(4, 115)

        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(
            f"QTableWidget{{alternate-background-color:{BG_ALT_ROW};}}"
        )
        self._table.clicked.connect(self._on_row_clicked)
        layout.addWidget(self._table)

        footer = QHBoxLayout()
        self._count_label = QLabel("0 logs")
        self._count_label.setStyleSheet(
            f"QLabel{{color:{TEXT_MUTED};font-size:11px;"
            f"background:transparent;border:none;}}"
        )
        footer.addWidget(self._count_label); footer.addStretch()
        tip = QLabel("Click any row for full details")
        tip.setStyleSheet(f"QLabel{{color:{TEXT_MUTED};font-size:10px;"
                          f"background:transparent;border:none;}}")
        footer.addWidget(tip)
        layout.addLayout(footer)

    def refresh(self):
        if not self._live_tail:
            return
        self._all_logs = database.get_recent_logs(MAX_VISIBLE_ROWS)
        self._apply_filters()

    def _apply_filters(self):
        search = self._search.text().lower().strip()
        ef  = self._event_filter.currentText()
        osf = self._os_filter.currentText()
        filtered = []
        for log in self._all_logs:
            et  = log.get('event_type','general')
            os_ = log.get('source_os','unknown')
            if ef  != "All Events" and et  != ef:  continue
            if osf != "All OS"     and os_ != osf: continue
            if search and search not in " ".join(str(v) for v in log.values()).lower():
                continue
            filtered.append(log)
        self._populate_table(filtered)
        n = len(filtered)
        self._count_label.setText(
            f"{n} log{'s' if n!=1 else ''} of {len(self._all_logs)} loaded"
        )

    def _populate_table(self, logs):
        self._table.setUpdatesEnabled(False)
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)

        color_cache = {}
        font_bold   = QFont('Segoe UI', 10, QFont.Bold)

        for log in logs:
            row = self._table.rowCount()
            self._table.insertRow(row)
            et = log.get('event_type','general')
            if et not in color_cache:
                color_cache[et] = QColor(EVENT_COLORS.get(et, TEXT_MUTED))

            vals = [
                (log.get('timestamp') or '')[:19],
                log.get('hostname','—'),
                et.replace('_',' '),
                log.get('user','—'),
                log.get('ip','—'),
                log.get('source_os','—'),
            ]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                if col == 2:
                    item.setForeground(color_cache[et])
                    item.setFont(font_bold)
                if col == 0:
                    item.setData(Qt.UserRole, log)
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)
        self._table.setUpdatesEnabled(True)

        if self._live_tail and self._table.rowCount() > 0:
            self._table.scrollToTop()

    def _on_row_clicked(self, index):
        item = self._table.item(index.row(), 0)
        if not item:
            return
        log = item.data(Qt.UserRole)
        if not log:
            return
        dlg = LogDetailDialog(log, parent=self)
        dlg.exec_()

    def _toggle_tail(self):
        self._live_tail = not self._tail_btn.isChecked()
        self._tail_btn.setText(
            "⏸  Pause Live Tail" if self._live_tail else "▶  Resume Live Tail"
        )

    def _clear_filters(self):
        self._search.clear()
        self._event_filter.setCurrentIndex(0)
        self._os_filter.setCurrentIndex(0)

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Logs",
            os.path.expanduser(
                f"~/SIEM_Logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            ),
            "CSV Files (*.csv)"
        )
        if not path: return
        try:
            with open(path,'w',newline='',encoding='utf-8') as f:
                writer = csv.DictWriter(
                    f, fieldnames=["timestamp","hostname","event_type",
                                   "user","ip","source_os","raw"],
                    extrasaction='ignore'
                )
                writer.writeheader(); writer.writerows(self._all_logs)
            QMessageBox.information(self,"Export Complete",
                                    f"Exported {len(self._all_logs)} logs to:\n{path}")
        except Exception as exc:
            QMessageBox.critical(self,"Export Failed",str(exc))
