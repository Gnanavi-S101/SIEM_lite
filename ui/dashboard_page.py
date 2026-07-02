"""SIEM Lite — Dashboard Page (beige+pink light theme)"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QScrollArea, QSizePolicy
)
from PyQt5.QtCore  import Qt
from PyQt5.QtGui   import QColor, QFont

from core    import database
from ui.theme import *


class StatCard(QFrame):
    def __init__(self, title, value="0", accent=ACCENT, icon=""):
        super().__init__()
        self.setObjectName("statcard")
        self.setStyleSheet(f"""
            QFrame#statcard {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER};
                border-top: 3px solid {accent};
                border-radius: 8px;
            }}
        """)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(100)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20,14,20,14)
        layout.setSpacing(4)
        top = QHBoxLayout()
        if icon:
            il = QLabel(icon)
            il.setStyleSheet(f"QLabel {{ color: {accent}; font-size: 16px; background: transparent; border: none; }}")
            top.addWidget(il)
        tl = QLabel(title.upper())
        tl.setStyleSheet(f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 10px; letter-spacing: 2px; font-weight: bold; background: transparent; border: none; }}")
        top.addWidget(tl)
        top.addStretch()
        layout.addLayout(top)
        self._val = QLabel(str(value))
        self._val.setStyleSheet(f"QLabel {{ color: {accent}; font-size: 32px; font-weight: 900; background: transparent; border: none; }}")
        layout.addWidget(self._val)

    def set_value(self, v):
        self._val.setText(str(v))


def _sev_item(severity):
    sev   = severity.lower()
    color = SEVERITY_COLOR.get(sev, TEXT_SECONDARY)
    item  = QTableWidgetItem(severity.upper())
    item.setForeground(QColor(color))
    item.setFont(QFont('Segoe UI', 10, QFont.Bold))
    item.setTextAlignment(Qt.AlignCenter)
    return item


class DashboardPage(QWidget):
    def __init__(self, current_user=None):
        super().__init__()
        self.current_user = current_user or {}
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0,0,0,0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        outer.addWidget(scroll)
        container = QWidget()
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24,24,24,24)
        layout.setSpacing(20)

        # Header
        hdr_row = QHBoxLayout()
        hdr = QLabel("Security Overview")
        hdr.setStyleSheet(f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 20px; font-weight: bold; background: transparent; border: none; }}")
        hdr_row.addWidget(hdr)
        hdr_row.addStretch()
        self._last_refresh = QLabel("Refreshing…")
        self._last_refresh.setStyleSheet(f"QLabel {{ color: {TEXT_MUTED}; font-size: 10px; background: transparent; border: none; }}")
        hdr_row.addWidget(self._last_refresh)
        layout.addLayout(hdr_row)

        # Cards row 1
        r1 = QHBoxLayout(); r1.setSpacing(12)
        self._c_logs    = StatCard("Total Logs",   "0", INFO,     "📋")
        self._c_alerts  = StatCard("Total Alerts", "0", CRITICAL, "🔴")
        self._c_blocked = StatCard("Blocked IPs",  "0", HIGH,     "🚫")
        self._c_crit    = StatCard("Critical",     "0", CRITICAL, "⚠")
        for c in (self._c_logs, self._c_alerts, self._c_blocked, self._c_crit):
            r1.addWidget(c)
        layout.addLayout(r1)

        # Cards row 2
        r2 = QHBoxLayout(); r2.setSpacing(12)
        self._c_high  = StatCard("High Severity",  "0", HIGH,   "🔶")
        self._c_unack = StatCard("Unacknowledged", "0", CRITICAL,"🔔")
        self._c_ml    = StatCard("ML Anomalies",   "0", ACCENT,  "🤖")
        self._c_brute = StatCard("Brute Force",    "0", CRITICAL,"🔨")
        for c in (self._c_high, self._c_unack, self._c_ml, self._c_brute):
            r2.addWidget(c)
        layout.addLayout(r2)

        # Content row
        content = QHBoxLayout(); content.setSpacing(16)

        left = QVBoxLayout(); left.setSpacing(8)
        left.addWidget(section_header("RECENT ALERTS"))
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(["TIME","RULE","IP","USER","SEVERITY"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setMinimumHeight(300)
        self._table.setStyleSheet(f"QTableWidget {{ alternate-background-color: {BG_ALT_ROW}; }}")
        left.addWidget(self._table)
        content.addLayout(left, stretch=3)

        right = QVBoxLayout(); right.setSpacing(8)
        right.addWidget(section_header("LIVE EVENT FEED"))
        feed = QFrame()
        feed.setObjectName("ff")
        feed.setStyleSheet(f"QFrame#ff {{ background-color: {BG_TERMINAL}; border: 1px solid {BORDER}; border-radius: 6px; }}")
        feed.setMinimumHeight(300)
        fl = QVBoxLayout(feed)
        fl.setContentsMargins(12,12,12,12)
        fl.setSpacing(4)
        self._feed: list[QLabel] = []
        for _ in range(12):
            lbl = QLabel("—")
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"QLabel {{ color: {ACCENT}; font-family: 'Consolas','Courier New',monospace; font-size: 10px; background: transparent; border: none; }}")
            fl.addWidget(lbl)
            self._feed.append(lbl)
        fl.addStretch()
        right.addWidget(feed)
        content.addLayout(right, stretch=2)
        layout.addLayout(content)

        layout.addWidget(section_header("THREAT BREAKDOWN"))
        self._breakdown = QHBoxLayout(); self._breakdown.setSpacing(8)
        layout.addLayout(self._breakdown)
        layout.addStretch()

    def refresh(self):
        from datetime import datetime
        self._refresh_stats()
        self._refresh_table()
        self._refresh_feed()
        self._refresh_breakdown()
        self._last_refresh.setText(f"Last refresh: {datetime.now().strftime('%H:%M:%S')}")

    def _refresh_stats(self):
        s = database.get_stats()
        self._c_logs.set_value(f"{s['total_logs']:,}")
        self._c_alerts.set_value(f"{s['total_alerts']:,}")
        self._c_blocked.set_value(f"{s['blocked_ips']:,}")
        self._c_crit.set_value(f"{s['critical']:,}")
        self._c_high.set_value(f"{s['high']:,}")
        self._c_unack.set_value(f"{s['unacknowledged']:,}")
        conn = database.get_conn()
        ml    = conn.execute("SELECT COUNT(*) FROM malicious_logs WHERE rule='ML Anomaly Detection'").fetchone()[0]
        brute = conn.execute("SELECT COUNT(*) FROM malicious_logs WHERE rule='Brute Force Detection'").fetchone()[0]
        conn.close()
        self._c_ml.set_value(f"{ml:,}")
        self._c_brute.set_value(f"{brute:,}")

    def _refresh_table(self):
        alerts = database.get_recent_alerts(15)
        self._table.setRowCount(0)
        for a in alerts:
            row = self._table.rowCount()
            self._table.insertRow(row)
            sev = a.get('severity','low')
            self._table.setItem(row,0,QTableWidgetItem((a.get('timestamp') or '')[:19]))
            self._table.setItem(row,1,QTableWidgetItem(a.get('rule','')))
            self._table.setItem(row,2,QTableWidgetItem(a.get('ip','')))
            self._table.setItem(row,3,QTableWidgetItem(a.get('user','')))
            self._table.setItem(row,4,_sev_item(sev))
            if sev == 'critical':
                for col in range(5):
                    item = self._table.item(row,col)
                    if item:
                        item.setBackground(QColor(CRITICAL_BG))

    def _refresh_feed(self):
        logs = database.get_recent_logs(12)
        feed_colors = {
            'fail': '#e88080', 'success': '#7ab87a',
            'sudo': '#d4a060', 'default': ACCENT
        }
        for i, lbl in enumerate(self._feed):
            if i < len(logs):
                e   = logs[i]
                ts  = (e.get('timestamp') or '')[-8:]
                et  = (e.get('event_type') or 'general').replace('_',' ')
                ip  = e.get('ip','—')
                raw = (e.get('raw') or '')[:55]
                raw_lc = raw.lower()
                if 'fail' in et or 'brute' in et: c = feed_colors['fail']
                elif 'success' in et or 'accept' in raw_lc: c = feed_colors['success']
                elif 'sudo' in et: c = feed_colors['sudo']
                else: c = feed_colors['default']
                lbl.setStyleSheet(f"QLabel {{ color: {c}; font-family: 'Consolas','Courier New',monospace; font-size: 10px; background: transparent; border: none; }}")
                lbl.setText(f"[{ts}]  {et.upper():<16}  {ip:<15}  {raw}")
            else:
                lbl.setText("—")

    def _refresh_breakdown(self):
        while self._breakdown.count():
            item = self._breakdown.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        data = database.get_analytics()
        breakdown = data.get('breakdown',[])
        if not breakdown:
            ph = QLabel("No threat data yet — system is monitoring.")
            ph.setStyleSheet(f"QLabel {{ color: {TEXT_MUTED}; font-size: 11px; background: transparent; border: none; }}")
            self._breakdown.addWidget(ph)
            return
        total = sum(r.get('count',0) for r in breakdown)
        for idx, row in enumerate(breakdown[:7]):
            rule  = row.get('rule','Unknown')
            count = row.get('count',0)
            pct   = (count/total*100) if total else 0
            color = CHART_COLORS[idx % len(CHART_COLORS)]
            card  = QFrame()
            card.setObjectName("bcard")
            card.setStyleSheet(f"QFrame#bcard {{ background-color: {BG_CARD}; border: 1px solid {BORDER}; border-left: 4px solid {color}; border-radius: 5px; }}")
            card.setFixedHeight(64)
            cl = QVBoxLayout(card)
            cl.setContentsMargins(12,8,12,8)
            cl.setSpacing(2)
            nl = QLabel(rule)
            nl.setWordWrap(True)
            nl.setStyleSheet(f"QLabel {{ color: {color}; font-size: 10px; font-weight: bold; background: transparent; border: none; }}")
            vl = QLabel(f"{count}  ({pct:.0f}%)")
            vl.setStyleSheet(f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 13px; font-weight: bold; background: transparent; border: none; }}")
            cl.addWidget(nl); cl.addWidget(vl)
            self._breakdown.addWidget(card)
        self._breakdown.addStretch()
