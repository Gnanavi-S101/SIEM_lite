"""SIEM Lite — Main Window"""

import logging
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QStackedWidget, QFrame,
    QApplication
)
from PyQt5.QtCore  import Qt, QTimer, pyqtSignal
from PyQt5.QtGui   import QFont, QColor

from core    import database
from config  import UI_REFRESH_INTERVAL
from ui.theme import *

log = logging.getLogger(__name__)

ROLE_PAGES = {
    'admin':   ['dashboard','alerts','blocked','logs','analytics','reports','settings'],
    'analyst': ['dashboard','alerts','blocked','logs','analytics','reports'],
    'viewer':  ['dashboard','logs','analytics'],
}

PAGE_META = [
    ('dashboard', '⬛  Dashboard',  'Overview & live stats'),
    ('alerts',    '🔴  Alerts',      'Security alerts & events'),
    ('blocked',   '🚫  Blocked IPs', 'Firewall block management'),
    ('logs',      '📋  Log Viewer',  'Raw log stream'),
    ('analytics', '📊  Analytics',   'Charts & trend analysis'),
    ('reports',   '📄  Reports',     'PDF report generation'),
    ('settings',  '⚙️   Settings',   'Rules & system status'),
]


class MainWindow(QMainWindow):
    alert_signal = pyqtSignal(dict)

    def __init__(self, collector, detector, ml_engine, current_user):
        super().__init__()
        self.collector    = collector
        self.detector     = detector
        self.ml_engine    = ml_engine
        self.current_user = current_user
        self.role         = current_user['role']
        self.allowed      = ROLE_PAGES.get(self.role, ['dashboard'])
        self._pages       = {}
        self._nav_buttons = {}
        self._setup_window()
        self.setStyleSheet(GLOBAL_STYLE)
        self._build_ui()
        self._connect_signals()
        self._start_timers()
        self._switch_page('dashboard')

    def _setup_window(self):
        self.setWindowTitle("SIEM Lite — Enterprise Security Monitor")
        self.setMinimumSize(1280, 780)
        self.resize(1440, 860)
        screen = QApplication.primaryScreen().geometry()
        self.move((screen.width()-self.width())//2, (screen.height()-self.height())//2)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setSpacing(0)
        root.setContentsMargins(0,0,0,0)
        root.addWidget(self._build_sidebar())
        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setSpacing(0)
        cl.setContentsMargins(0,0,0,0)
        cl.addWidget(self._build_topbar())
        self._stack = QStackedWidget()
        self._stack.setStyleSheet(f"QStackedWidget {{ background-color: {BG_ROOT}; }}")
        cl.addWidget(self._stack)
        root.addWidget(content)
        self._build_pages()

    def _build_sidebar(self):
        sidebar = QWidget()
        sidebar.setFixedWidth(220)
        sidebar.setObjectName("sidebar")
        sidebar.setStyleSheet(f"""
            QWidget#sidebar {{
                background-color: {BG_SIDEBAR};
                border-right: 1px solid {BORDER};
            }}
        """)
        layout = QVBoxLayout(sidebar)
        layout.setSpacing(0)
        layout.setContentsMargins(0,0,0,0)

        # Brand
        brand = QWidget()
        brand.setFixedHeight(70)
        brand.setStyleSheet(f"background-color: {BG_CARD}; border-bottom: 1px solid {BORDER};")
        bl = QVBoxLayout(brand)
        bl.setContentsMargins(20,12,20,12)
        bl.setSpacing(2)
        logo = QLabel("SIEM LITE")
        logo.setStyleSheet(f"QLabel {{ color: {ACCENT}; font-size: 16px; font-weight: 900; letter-spacing: 4px; background: transparent; border: none; }}")
        bl.addWidget(logo)
        ver = QLabel("Enterprise v2.0")
        ver.setStyleSheet(f"QLabel {{ color: {TEXT_MUTED}; font-size: 9px; letter-spacing: 1px; background: transparent; border: none; }}")
        bl.addWidget(ver)
        layout.addWidget(brand)

        # User badge
        ub = QWidget()
        ub.setFixedHeight(56)
        ub.setStyleSheet(f"background-color: {BG_SIDEBAR}; border-bottom: 1px solid {BORDER};")
        ul = QHBoxLayout(ub)
        ul.setContentsMargins(16,8,16,8)
        avatar = QLabel(self.current_user['username'][0].upper())
        avatar.setFixedSize(32,32)
        avatar.setAlignment(Qt.AlignCenter)
        avatar.setStyleSheet(f"QLabel {{ background-color: {ACCENT}; color: {TEXT_ON_ACCENT}; border-radius: 16px; font-weight: bold; font-size: 14px; border: none; }}")
        ul.addWidget(avatar)
        ul.addSpacing(8)
        ui2 = QVBoxLayout()
        ui2.setSpacing(0)
        uname = QLabel(self.current_user['username'])
        uname.setStyleSheet(f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 12px; font-weight: bold; border: none; background: transparent; }}")
        urole = QLabel(self.role.upper())
        urole.setStyleSheet(f"QLabel {{ color: {ACCENT}; font-size: 9px; letter-spacing: 1px; border: none; background: transparent; }}")
        ui2.addWidget(uname)
        ui2.addWidget(urole)
        ul.addLayout(ui2)
        layout.addWidget(ub)

        # Nav label
        nav_lbl = QLabel("NAVIGATION")
        nav_lbl.setStyleSheet(f"QLabel {{ color: {TEXT_MUTED}; font-size: 9px; letter-spacing: 2px; padding: 16px 20px 6px 20px; background: transparent; border: none; }}")
        layout.addWidget(nav_lbl)

        for page_id, label, tooltip in PAGE_META:
            if page_id not in self.allowed:
                continue
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setToolTip(tooltip)
            btn.setFixedHeight(42)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setProperty("page_id", page_id)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: {TEXT_SECONDARY};
                    border: none;
                    border-left: 3px solid transparent;
                    padding: 0 16px;
                    text-align: left;
                    font-size: 13px;
                    border-radius: 0;
                }}
                QPushButton:hover {{
                    background-color: {BG_HOVER};
                    color: {TEXT_PRIMARY};
                    border-left: 3px solid {BORDER};
                }}
                QPushButton:checked {{
                    background-color: {ACCENT_LIGHT};
                    color: {ACCENT};
                    border-left: 3px solid {ACCENT};
                    font-weight: bold;
                }}
            """)
            btn.clicked.connect(lambda _, p=page_id: self._switch_page(p))
            layout.addWidget(btn)
            self._nav_buttons[page_id] = btn

        layout.addStretch()

        self._alert_badge = QLabel("● All clear")
        self._alert_badge.setStyleSheet(f"QLabel {{ color: {LOW}; font-size: 10px; padding: 8px 20px; background: transparent; border-top: 1px solid {BORDER}; }}")
        layout.addWidget(self._alert_badge)

        self._status_label = QLabel("● SYSTEM ACTIVE")
        self._status_label.setAlignment(Qt.AlignCenter)
        self._status_label.setStyleSheet(f"QLabel {{ color: {LOW}; font-size: 10px; font-weight: bold; padding: 12px 20px; letter-spacing: 2px; background: transparent; border-top: 1px solid {BORDER}; }}")
        layout.addWidget(self._status_label)
        return sidebar

    def _build_topbar(self):
        bar = QWidget()
        bar.setFixedHeight(52)
        bar.setObjectName("topbar")
        bar.setStyleSheet(f"QWidget#topbar {{ background-color: {BG_CARD}; border-bottom: 1px solid {BORDER}; }}")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24,0,24,0)

        self._page_title = QLabel("Dashboard")
        self._page_title.setStyleSheet(f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 15px; font-weight: bold; background: transparent; border: none; }}")
        layout.addWidget(self._page_title)
        layout.addStretch()

        self._clock = QLabel()
        self._clock.setStyleSheet(f"QLabel {{ color: {TEXT_MUTED}; font-size: 11px; font-family: 'Consolas', monospace; background: transparent; border: none; }}")
        layout.addWidget(self._clock)
        self._update_clock()
        layout.addSpacing(16)

        logout_btn = QPushButton("Logout")
        logout_btn.setFixedHeight(30)
        logout_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {TEXT_SECONDARY};
                border: 1px solid {BORDER};
                border-radius: 4px;
                padding: 0 12px;
                font-size: 11px;
                font-weight: normal;
            }}
            QPushButton:hover {{ color: {CRITICAL}; border-color: {CRITICAL}; }}
        """)
        logout_btn.clicked.connect(self._logout)
        layout.addWidget(logout_btn)
        return bar

    def _build_pages(self):
        from ui.dashboard_page import DashboardPage
        from ui.alerts_page    import AlertsPage
        from ui.blocked_page   import BlockedPage
        from ui.logs_page      import LogsPage
        from ui.analytics_page import AnalyticsPage
        from ui.reports_page   import ReportsPage
        from ui.settings_page  import SettingsPage

        classes = {
            'dashboard': DashboardPage, 'alerts': AlertsPage,
            'blocked': BlockedPage,     'logs': LogsPage,
            'analytics': AnalyticsPage, 'reports': ReportsPage,
            'settings': SettingsPage,
        }
        for pid, cls in classes.items():
            if pid not in self.allowed:
                continue
            page = cls(current_user=self.current_user)
            self._pages[pid] = page
            self._stack.addWidget(page)

    def _switch_page(self, page_id):
        if page_id not in self._pages:
            return
        self._stack.setCurrentWidget(self._pages[page_id])
        self._pages[page_id].refresh()
        for pid, btn in self._nav_buttons.items():
            btn.setChecked(pid == page_id)
        for pid, label, _ in PAGE_META:
            if pid == page_id:
                clean = label.split('  ', 1)[-1] if '  ' in label else label
                self._page_title.setText(clean)
                break

    def _connect_signals(self):
        self.alert_signal.connect(self._on_new_alert)
        self.detector.add_callback(lambda a: self.alert_signal.emit(a))
        self.ml_engine.add_callback(lambda a: self.alert_signal.emit(a))

    def _on_new_alert(self, alert):
        for pid in ('alerts', 'dashboard'):
            if pid in self._pages:
                self._pages[pid].refresh()
        self._update_alert_badge()

    def _update_alert_badge(self):
        stats = database.get_stats()
        count = stats.get('unacknowledged', 0)
        if count > 0:
            self._alert_badge.setStyleSheet(f"QLabel {{ color: {CRITICAL}; font-size: 10px; padding: 8px 20px; background: transparent; border-top: 1px solid {BORDER}; }}")
            self._alert_badge.setText(f"● {count} unacknowledged")
        else:
            self._alert_badge.setStyleSheet(f"QLabel {{ color: {LOW}; font-size: 10px; padding: 8px 20px; background: transparent; border-top: 1px solid {BORDER}; }}")
            self._alert_badge.setText("● All clear")

    def _start_timers(self):
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._auto_refresh)
        self._refresh_timer.start(UI_REFRESH_INTERVAL)
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._update_clock)
        self._clock_timer.start(1000)

    def _auto_refresh(self):
        current = self._stack.currentWidget()
        for page in self._pages.values():
            if page is current:
                page.refresh()
                break
        self._update_alert_badge()

    def _update_clock(self):
        from datetime import datetime
        self._clock.setText(datetime.now().strftime('%Y-%m-%d  %H:%M:%S'))

    def _logout(self):
        self._cleanup()
        from ui.login_window import LoginWindow
        self._login = LoginWindow()
        self._login.login_successful.connect(self._on_relogin)
        self._login.show()
        self.close()

    def _on_relogin(self, user):
        self._login.close()
        import main as m
        m._start_main(QApplication.instance(), user)

    def _cleanup(self):
        self._refresh_timer.stop()
        self._clock_timer.stop()
        self.collector.stop()
        self.detector.stop()
        self.ml_engine.stop()

    def closeEvent(self, event):
        self._cleanup()
        event.accept()
