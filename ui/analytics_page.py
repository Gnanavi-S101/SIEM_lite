"""SIEM Lite — Analytics Page """

from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QScrollArea, QSizePolicy, QProgressBar
)
from PyQt5.QtCore  import Qt
from PyQt5.QtGui   import QColor, QFont, QPainter, QPen
from core    import database
from ui.theme import *


class BarChartWidget(QWidget):
    def __init__(self, color=ACCENT):
        super().__init__()
        self._color = color; self._data = []
        self.setMinimumHeight(200)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_data(self, data):
        self._data = data; self.update()

    def paintEvent(self, event):
        if not self._data: return
        painter = QPainter(self); painter.setRenderHint(QPainter.Antialiasing)
        w = self.width(); h = self.height()
        pad_l=44; pad_r=16; pad_t=24; pad_b=36
        cw = w-pad_l-pad_r; ch = h-pad_t-pad_b
        max_val = max((v for _,v in self._data), default=1) or 1
        n = len(self._data); gap=4; bw = max(4,(cw-gap*(n-1))//n)

        painter.fillRect(self.rect(), QColor(BG_CARD))

        grid_pen = QPen(QColor(BORDER)); grid_pen.setWidth(1); painter.setPen(grid_pen)
        for i in range(5):
            y = pad_t + ch - int(ch*i/4)
            painter.drawLine(pad_l, y, pad_l+cw, y)
            painter.setPen(QColor(TEXT_MUTED)); painter.setFont(QFont('Consolas',7))
            painter.drawText(0, y+4, pad_l-4, 12, Qt.AlignRight, str(int(max_val*i/4)))
            painter.setPen(grid_pen)

        for i, (label, value) in enumerate(self._data):
            x = pad_l + i*(bw+gap); bh = int(ch*value/max_val) if max_val else 0; y = pad_t+ch-bh
            painter.fillRect(x, y, bw, bh, QColor(self._color))
            if bh > 14:
                painter.setPen(QColor(TEXT_ON_ACCENT)); painter.setFont(QFont('Consolas',7,QFont.Bold))
                painter.drawText(x, y-2, bw, 12, Qt.AlignHCenter, str(value))
            painter.setPen(QColor(TEXT_SECONDARY)); painter.setFont(QFont('Consolas',7))
            short = label[-5:] if len(label)>6 else label
            painter.drawText(x, pad_t+ch+4, bw, 20, Qt.AlignHCenter, short)
        painter.end()


def _bar_row(label, value, max_val, color=ACCENT):
    w = QWidget(); hl = QHBoxLayout(w); hl.setContentsMargins(0,2,0,2); hl.setSpacing(10)
    nl = QLabel(label); nl.setFixedWidth(200); nl.setStyleSheet(f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 11px; background: transparent; border: none; }}"); hl.addWidget(nl)
    bar = QProgressBar(); bar.setRange(0,max(max_val,1)); bar.setValue(value); bar.setFixedHeight(16); bar.setTextVisible(False)
    bar.setStyleSheet(f"QProgressBar {{ background-color: {BORDER}; border: none; border-radius: 3px; }} QProgressBar::chunk {{ background-color: {color}; border-radius: 3px; }}")
    hl.addWidget(bar)
    cl = QLabel(str(value)); cl.setFixedWidth(40); cl.setAlignment(Qt.AlignRight|Qt.AlignVCenter)
    cl.setStyleSheet(f"QLabel {{ color: {color}; font-size: 11px; font-weight: bold; background: transparent; border: none; }}"); hl.addWidget(cl)
    return w


def _mini_stat(title, value, color):
    f = QFrame(); f.setObjectName("ms"); f.setFixedHeight(70)
    f.setStyleSheet(f"QFrame#ms {{ background-color: {BG_CARD}; border: 1px solid {BORDER}; border-top: 3px solid {color}; border-radius: 6px; }}")
    fl = QVBoxLayout(f); fl.setContentsMargins(16,10,16,10); fl.setSpacing(2)
    vl = QLabel(value); vl.setStyleSheet(f"QLabel {{ color: {color}; font-size: 24px; font-weight: 900; background: transparent; border: none; }}")
    tl = QLabel(title.upper()); tl.setStyleSheet(f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 9px; letter-spacing: 2px; background: transparent; border: none; }}")
    fl.addWidget(vl); fl.addWidget(tl); f._val = vl
    return f


class AnalyticsPage(QWidget):
    def __init__(self, current_user=None):
        super().__init__()
        self.current_user = current_user or {}
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self); outer.setContentsMargins(0,0,0,0)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }"); outer.addWidget(scroll)
        container = QWidget(); scroll.setWidget(container)
        layout = QVBoxLayout(container); layout.setContentsMargins(24,24,24,24); layout.setSpacing(24)

        hdr_row = QHBoxLayout()
        hdr = QLabel("Analytics"); hdr.setStyleSheet(f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 20px; font-weight: bold; background: transparent; border: none; }}")
        hdr_row.addWidget(hdr); hdr_row.addStretch()
        self._lr = QLabel(""); self._lr.setStyleSheet(f"QLabel {{ color: {TEXT_MUTED}; font-size: 10px; background: transparent; border: none; }}"); hdr_row.addWidget(self._lr)
        layout.addLayout(hdr_row)

        strip = QHBoxLayout(); strip.setSpacing(12)
        self._s = {}
        for key, title, color in [('total','Total Alerts',ACCENT),('critical','Critical',CRITICAL),
                                    ('high','High',HIGH),('blocked','IPs Blocked',INFO),
                                    ('ml','ML Anomalies',ACCENT_HOVER),('rules','Rules Triggered',LOW)]:
            s = _mini_stat(title,"0",color); self._s[key] = s; strip.addWidget(s)
        layout.addLayout(strip)

        charts = QHBoxLayout(); charts.setSpacing(16)
        dc = QVBoxLayout(); dc.setSpacing(8); dc.addWidget(section_header("DAILY ALERT TREND  (last 14 days)"))
        self._daily_chart = BarChartWidget(ACCENT); self._daily_chart.setMinimumHeight(200); dc.addWidget(self._daily_chart); charts.addLayout(dc, stretch=3)
        hc = QVBoxLayout(); hc.setSpacing(8); hc.addWidget(section_header("ALERTS BY HOUR OF DAY"))
        self._hourly_chart = BarChartWidget(CRITICAL); self._hourly_chart.setMinimumHeight(200); hc.addWidget(self._hourly_chart); charts.addLayout(hc, stretch=2)
        layout.addLayout(charts)

        lower = QHBoxLayout(); lower.setSpacing(16)
        sc = QVBoxLayout(); sc.setSpacing(8); sc.addWidget(section_header("SEVERITY DISTRIBUTION"))
        self._sev_container = QVBoxLayout(); self._sev_container.setSpacing(6); sc.addLayout(self._sev_container); sc.addStretch(); lower.addLayout(sc, stretch=1)

        rc = QVBoxLayout(); rc.setSpacing(8); rc.addWidget(section_header("ALERTS BY DETECTION RULE"))
        self._rule_container = QVBoxLayout(); self._rule_container.setSpacing(6); rc.addLayout(self._rule_container); rc.addStretch(); lower.addLayout(rc, stretch=2)

        ic = QVBoxLayout(); ic.setSpacing(8); ic.addWidget(section_header("TOP ATTACKING IPs"))
        self._ip_table = QTableWidget(); self._ip_table.setColumnCount(3)
        self._ip_table.setHorizontalHeaderLabels(["IP ADDRESS","ALERTS","LAST SEEN"])
        hh = self._ip_table.horizontalHeader()
        hh.setSectionResizeMode(0,QHeaderView.Stretch); hh.setSectionResizeMode(1,QHeaderView.ResizeToContents); hh.setSectionResizeMode(2,QHeaderView.ResizeToContents)
        self._ip_table.setEditTriggers(QTableWidget.NoEditTriggers); self._ip_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._ip_table.verticalHeader().setVisible(False); self._ip_table.setAlternatingRowColors(True)
        self._ip_table.setMinimumHeight(220)
        self._ip_table.setStyleSheet(f"QTableWidget {{ alternate-background-color: {BG_ALT_ROW}; }}")
        ic.addWidget(self._ip_table); lower.addLayout(ic, stretch=2)
        layout.addLayout(lower); layout.addStretch()

    def refresh(self):
        data = database.get_analytics(); stats = database.get_stats()
        self._s['total']._val.setText(str(stats.get('total_alerts',0)))
        self._s['critical']._val.setText(str(stats.get('critical',0)))
        self._s['high']._val.setText(str(stats.get('high',0)))
        self._s['blocked']._val.setText(str(stats.get('blocked_ips',0)))
        conn = database.get_conn()
        ml = conn.execute("SELECT COUNT(*) FROM malicious_logs WHERE rule='ML Anomaly Detection'").fetchone()[0]
        rules = conn.execute("SELECT COUNT(DISTINCT rule) FROM malicious_logs").fetchone()[0]
        conn.close()
        self._s['ml']._val.setText(str(ml)); self._s['rules']._val.setText(str(rules))

        daily = list(reversed(data.get('daily',[])))
        self._daily_chart.set_data([(r.get('date','')[-5:], r.get('count',0)) for r in daily])
        hourly = {r.get('hour',0): r.get('count',0) for r in data.get('hourly',[])}
        self._hourly_chart.set_data([(f"{h:02d}h", hourly.get(h,0)) for h in range(24)])

        for container, items, key, colors_map in [
            (self._sev_container, [(s, SEVERITY_COLOR.get(s,TEXT_MUTED)) for s in ('critical','high','medium','low')],
             'severity_dist', None),
        ]:
            while container.count():
                item = container.takeAt(0)
                if item.widget(): item.widget().deleteLater()
            sev_data = {r.get('severity','low'): r.get('count',0) for r in data.get('severity_dist',[])}
            max_val = max(sev_data.values()) if sev_data else 1
            for sev, color in items:
                container.addWidget(_bar_row(sev.upper(), sev_data.get(sev,0), max_val, color))

        while self._rule_container.count():
            item = self._rule_container.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        breakdown = data.get('breakdown',[]); max_val = max((r.get('count',0) for r in breakdown), default=1)
        for idx, row in enumerate(breakdown):
            self._rule_container.addWidget(_bar_row(row.get('rule','Unknown'), row.get('count',0), max_val, CHART_COLORS[idx%len(CHART_COLORS)]))

        self._ip_table.setRowCount(0)
        conn = database.get_conn()
        rows = conn.execute("SELECT ip, COUNT(*) AS c, MAX(created_at) AS ls FROM malicious_logs WHERE ip NOT IN ('unknown','127.0.0.1') GROUP BY ip ORDER BY c DESC LIMIT 15").fetchall()
        conn.close()
        for entry in rows:
            row = self._ip_table.rowCount(); self._ip_table.insertRow(row)
            ii = QTableWidgetItem(entry['ip']); ii.setForeground(QColor(CRITICAL)); ii.setFont(QFont('Consolas',11,QFont.Bold))
            ci = QTableWidgetItem(str(entry['c'])); ci.setForeground(QColor(HIGH)); ci.setFont(QFont('Segoe UI',10,QFont.Bold)); ci.setTextAlignment(Qt.AlignCenter)
            self._ip_table.setItem(row,0,ii); self._ip_table.setItem(row,1,ci)
            self._ip_table.setItem(row,2,QTableWidgetItem((entry['ls'] or '')[:19]))
        self._lr.setText(f"Last refresh: {datetime.now().strftime('%H:%M:%S')}")
                                                                                    
