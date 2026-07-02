"""
SIEM Lite — Login Window (Pink/Beige Theme + Fullscreen Layout)
Combines the light aesthetic with the advanced fullscreen structure.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QGraphicsDropShadowEffect,
    QSizePolicy, QDesktopWidget
)
from PyQt5.QtCore  import Qt, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui   import QFont, QColor, QPainter, QLinearGradient, QBrush

from config import USERS
from ui.theme import *

class LoginWindow(QWidget):
    login_successful = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._failed_attempts = 0
        self._locked          = False
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("SIEM Lite — Login")
        self.setWindowFlags(Qt.Window)

        # Fullscreen logic from script #2
        screen = QDesktopWidget().screenGeometry()
        self.setGeometry(screen)
        self.showMaximized()

        # Root background using light theme variables
        self.setStyleSheet(f"QWidget {{ background-color: {BG_ROOT}; }}")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setAlignment(Qt.AlignCenter)

        # Main Card
        card = self._build_card()
        hbox = QHBoxLayout()
        hbox.setAlignment(Qt.AlignCenter)
        hbox.addWidget(card)
        root.addLayout(hbox)

        # Bottom status bar (integrated from script #2 with light theme colors)
        status = QLabel("● SECURE CONNECTION  |  AES-256  |  SIEM LITE v2.0")
        status.setAlignment(Qt.AlignCenter)
        status.setStyleSheet(f"""
            QLabel {{
                color: {TEXT_MUTED};
                font-size: 9px;
                letter-spacing: 3px;
                background: transparent;
                border: none;
                padding: 12px;
            }}
        """)
        root.addWidget(status)

    def paintEvent(self, event):
        """Paints the subtle grid from script #2 using theme colors."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Background Fill
        painter.fillRect(self.rect(), QColor(BG_ROOT))

        # Subtle grid lines (using a faint version of the BORDER color)
        painter.setPen(QColor(180, 120, 120, 30))
        step = 40
        for x in range(0, self.width(), step):
            painter.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), step):
            painter.drawLine(0, y, self.width(), y)
        painter.end()

    def _build_card(self):
        card = QFrame()
        card.setObjectName("card")
        card.setFixedSize(440, 540)
        card.setStyleSheet(f"""
            QFrame#card {{
                background-color: {BG_CARD};
                border: 1px solid {BORDER};
                border-radius: 16px;
            }}
        """)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(40)
        shadow.setOffset(0, 8)
        shadow.setColor(QColor(180, 120, 120, 60))
        card.setGraphicsEffect(shadow)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(44, 44, 44, 36)
        layout.setSpacing(0)

        # Logo
        logo = QLabel("SIEM")
        logo.setAlignment(Qt.AlignCenter)
        logo.setStyleSheet(f"QLabel {{ color: {ACCENT}; font-size: 56px; font-weight: 900; letter-spacing: 8px; background: transparent; }}")
        layout.addWidget(logo)

        lite = QLabel("LITE")
        lite.setAlignment(Qt.AlignCenter)
        lite.setStyleSheet(f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 14px; font-weight: 300; letter-spacing: 12px; background: transparent; margin-bottom: 4px; }}")
        layout.addWidget(lite)

        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet(f"background-color: {ACCENT}; max-height: 2px; border: none;")
        layout.addWidget(divider)
        layout.addSpacing(8)

        subtitle = QLabel("Security Information & Event Management")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(f"QLabel {{ color: {TEXT_MUTED}; font-size: 11px; letter-spacing: 1px; background: transparent; }}")
        layout.addWidget(subtitle)
        layout.addSpacing(40)

        # Fields
        for attr, label_text, placeholder, echo in [
            ('username_input', 'USERNAME', 'Enter your username', QLineEdit.Normal),
            ('password_input', 'PASSWORD', 'Enter your password', QLineEdit.Password),
        ]:
            lbl = QLabel(label_text)
            lbl.setStyleSheet(f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 10px; font-weight: bold; letter-spacing: 2px; background: transparent; }}")
            layout.addWidget(lbl)
            layout.addSpacing(6)

            field = QLineEdit()
            field.setPlaceholderText(placeholder)
            field.setEchoMode(echo)
            field.setFixedHeight(48)
            field.setStyleSheet(f"""
                QLineEdit {{
                    background-color: {BG_INPUT};
                    border: 1px solid {BORDER};
                    border-radius: 8px;
                    padding: 0 14px;
                    color: {TEXT_PRIMARY};
                    font-size: 14px;
                }}
                QLineEdit:focus {{ border: 1px solid {ACCENT}; background-color: {BG_CARD}; }}
            """)
            field.returnPressed.connect(self._attempt_login)
            setattr(self, attr, field)
            layout.addWidget(field)
            layout.addSpacing(20)

        # Message label
        self.msg_label = QLabel("")
        self.msg_label.setAlignment(Qt.AlignCenter)
        self.msg_label.setFixedHeight(20)
        self.msg_label.setStyleSheet(f"QLabel {{ color: {CRITICAL}; font-size: 12px; background: transparent; }}")
        layout.addWidget(self.msg_label)
        layout.addSpacing(20)

        # Login button
        self.login_btn = QPushButton("SIGN IN")
        self.login_btn.setFixedHeight(50)
        self.login_btn.setCursor(Qt.PointingHandCursor)
        self.login_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ACCENT};
                color: {TEXT_ON_ACCENT};
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: bold;
                letter-spacing: 3px;
            }}
            QPushButton:hover {{ background-color: {ACCENT_HOVER}; }}
            QPushButton:pressed {{ background-color: {ACCENT_PRESSED}; }}
            QPushButton:disabled {{ background-color: {BORDER}; color: {TEXT_MUTED}; }}
        """)
        self.login_btn.clicked.connect(self._attempt_login)
        layout.addWidget(self.login_btn)
        layout.addSpacing(24)

        hint = QLabel("admin  ·  analyst  ·  viewer")
        hint.setAlignment(Qt.AlignCenter)
        hint.setStyleSheet(f"QLabel {{ color: {TEXT_MUTED}; font-size: 10px; letter-spacing: 2px; background: transparent; }}")
        layout.addWidget(hint)
        layout.addStretch()

        return card

    # Authentication methods remain the same as the original logic
    def _attempt_login(self):
        if self._locked: return
        u, p = self.username_input.text().strip(), self.password_input.text().strip()
        if not u or not p:
            self._show_error("Please enter both credentials.")
            return
        record = USERS.get(u)
        if record and record['password'] == p:
            self._on_success(u, record)
        else:
            self._on_failure()

    def _on_success(self, username, record):
        self.msg_label.setStyleSheet(f"QLabel {{ color: {LOW}; font-size: 11px; }}")
        self.msg_label.setText(f"Welcome, {username}. Loading...")
        for w in (self.login_btn, self.username_input, self.password_input): w.setEnabled(False)
        QTimer.singleShot(800, lambda: self.login_successful.emit({'username': username, 'role': record['role']}))

    def _on_failure(self):
        self._failed_attempts += 1
        if self._failed_attempts >= 5:
            self._lock_out()
        else:
            self._show_error(f"Invalid credentials. {5-self._failed_attempts} remaining.")
            self._shake(self.password_input)
            self.password_input.clear()
            self.password_input.setFocus()

    def _lock_out(self):
        self._locked = True
        for w in (self.login_btn, self.username_input, self.password_input): w.setEnabled(False)
        self.countdown = 30
        def tick():
            if self.countdown <= 0:
                self._locked = False
                self._failed_attempts = 0
                for w in (self.login_btn, self.username_input, self.password_input): w.setEnabled(True)
                self.msg_label.setText("")
                return
            self._show_error(f"Locked. Try again in {self.countdown}s.")
            self.countdown -= 1
            QTimer.singleShot(1000, tick)
        tick()

    def _show_error(self, message):
        self.msg_label.setStyleSheet(f"QLabel {{ color: {CRITICAL}; font-size: 11px; }}")
        self.msg_label.setText(message)

    def _shake(self, widget):
        op = widget.pos()
        anim = QPropertyAnimation(widget, b"pos")
        anim.setDuration(300)
        anim.setEasingCurve(QEasingCurve.OutElastic)
        anim.setKeyValueAt(0.0, op)
        anim.setKeyValueAt(0.2, op + type(op)(8, 0))
        anim.setKeyValueAt(0.4, op + type(op)(-8, 0))
        anim.setKeyValueAt(1.0, op)
        anim.start()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape: self.showNormal()
