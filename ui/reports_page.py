"""SIEM Lite — Reports Page """

import os
from datetime import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QPushButton, QFrame, QFileDialog,
    QMessageBox, QListWidget, QListWidgetItem, QSplitter
)
from PyQt5.QtCore  import Qt, QThread, pyqtSignal
from PyQt5.QtGui   import QColor
from core    import database
from config  import REPORTS_DIR
from ui.theme import *


class ReportWorker(QThread):
    finished = pyqtSignal(str)
    failed   = pyqtSignal(str)
    def __init__(self, filepath):
        super().__init__()
        self.filepath = filepath
    def run(self):
        try:
            _generate_pdf(self.filepath)
            self.finished.emit(self.filepath)
        except Exception as exc:
            self.failed.emit(str(exc))


def _generate_pdf(filepath):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable)

    stats = database.get_stats(); alerts = database.get_recent_alerts(50)
    blocked = database.get_blocked_ips(); data = database.get_analytics()

    doc = SimpleDocTemplate(filepath, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    title_style   = ParagraphStyle('T', parent=styles['Normal'], fontSize=22, textColor=colors.HexColor('#c4788a'), fontName='Helvetica-Bold', spaceAfter=4)
    sub_style     = ParagraphStyle('S', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#8a7070'), fontName='Helvetica', spaceAfter=2)
    section_style = ParagraphStyle('H', parent=styles['Normal'], fontSize=13, textColor=colors.HexColor('#c4788a'), fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=6)
    body_style    = ParagraphStyle('B', parent=styles['Normal'], fontSize=9,  textColor=colors.HexColor('#2d1f1f'), fontName='Helvetica', spaceAfter=4)

    def _ts():
        return TableStyle([
            ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#f5f0ec')),
            ('TEXTCOLOR',(0,0),(-1,0),colors.HexColor('#c4788a')),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,0),9),
            ('FONTNAME',(0,1),(-1,-1),'Helvetica'),('FONTSIZE',(0,1),(-1,-1),8),
            ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#faf7f4')]),
            ('GRID',(0,0),(-1,-1),0.4,colors.HexColor('#e8ddd5')),
            ('PADDING',(0,0),(-1,-1),6),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ])

    story = []
    story.append(Spacer(1,1*cm))
    story.append(Paragraph("SIEM LITE", title_style))
    story.append(Paragraph("Security Information &amp; Event Management", sub_style))
    story.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", sub_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#c4788a'), spaceAfter=16))

    story.append(Paragraph("1. Executive Summary", section_style))
    t = Table([["Metric","Value"],["Total Logs",f"{stats['total_logs']:,}"],
               ["Total Alerts",f"{stats['total_alerts']:,}"],["Critical",f"{stats['critical']:,}"],
               ["High",f"{stats['high']:,}"],["Blocked IPs",f"{stats['blocked_ips']:,}"],
               ["Unacknowledged",f"{stats['unacknowledged']:,}"]], colWidths=[10*cm,6*cm])
    t.setStyle(_ts()); story.append(t)

    story.append(Paragraph("2. Alert Breakdown by Detection Rule", section_style))
    breakdown = data.get('breakdown',[])
    if breakdown:
        total = sum(r.get('count',0) for r in breakdown)
        bd = [["Rule","Count","%"]]+[[r.get('rule','—'),str(r.get('count',0)),f"{(r['count']/total*100 if total else 0):.1f}%"] for r in breakdown]
        t2 = Table(bd, colWidths=[10*cm,3*cm,3*cm]); t2.setStyle(_ts()); story.append(t2)

    story.append(Paragraph("3. Recent Alerts (last 50)", section_style))
    if alerts:
        sev_colors = {'CRITICAL':'#9b1c1c','HIGH':'#c2410c','MEDIUM':'#92400e','LOW':'#166534'}
        al = [["Timestamp","Rule","IP","User","Severity"]]+[
            [(a.get('timestamp') or '')[:19],a.get('rule','—'),a.get('ip','—'),a.get('user','—'),(a.get('severity') or '—').upper()]
            for a in alerts]
        t3 = Table(al, colWidths=[4*cm,5*cm,3*cm,2.5*cm,2.5*cm])
        ts3 = _ts()
        for i, a in enumerate(alerts,1):
            sev = (a.get('severity') or '').upper()
            c = sev_colors.get(sev)
            if c: ts3.add('TEXTCOLOR',(4,i),(4,i),colors.HexColor(c)); ts3.add('FONTNAME',(4,i),(4,i),'Helvetica-Bold')
        t3.setStyle(ts3); story.append(t3)

    story.append(Paragraph("4. Blocked IPs", section_style))
    if blocked:
        bl = [["IP","Reason","Type","Blocked At"]]+[[b.get('ip','—'),b.get('reason','—'),b.get('block_type','—'),(b.get('blocked_at') or '')[:19]] for b in blocked]
        t4 = Table(bl, colWidths=[4*cm,6*cm,3*cm,4*cm]); t4.setStyle(_ts()); story.append(t4)
    else:
        story.append(Paragraph("No IPs currently blocked.", body_style))

    story.append(Spacer(1,1*cm))
    story.append(HRFlowable(width="100%",thickness=1,color=colors.HexColor('#e8ddd5'),spaceAfter=6))
    story.append(Paragraph("Generated automatically by SIEM Lite v2.0 Enterprise.", sub_style))
    doc.build(story)


class ReportsPage(QWidget):
    def __init__(self, current_user=None):
        super().__init__()
        self.current_user = current_user or {}
        self._worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self); layout.setContentsMargins(24,24,24,24); layout.setSpacing(16)

        hdr = QLabel("Reports"); hdr.setStyleSheet(f"QLabel {{ color: {TEXT_PRIMARY}; font-size: 20px; font-weight: bold; background: transparent; border: none; }}"); layout.addWidget(hdr)
        sub = QLabel("Generate comprehensive PDF security reports for review, compliance and incident documentation.")
        sub.setStyleSheet(f"QLabel {{ color: {TEXT_SECONDARY}; font-size: 12px; background: transparent; border: none; }}"); layout.addWidget(sub)

        btn_row = QHBoxLayout(); btn_row.setSpacing(10)
        self._gen_btn = QPushButton("Generate Security Report  (PDF)"); self._gen_btn.setFixedHeight(42); self._gen_btn.setMinimumWidth(260); self._gen_btn.clicked.connect(self._generate); btn_row.addWidget(self._gen_btn)
        self._status_lbl = QLabel(""); self._status_lbl.setStyleSheet(f"QLabel {{ color: {LOW}; font-size: 11px; background: transparent; border: none; }}"); btn_row.addWidget(self._status_lbl); btn_row.addStretch()
        layout.addLayout(btn_row)

        splitter = QSplitter(Qt.Horizontal); splitter.setStyleSheet(f"QSplitter::handle {{ background-color: {BORDER}; width: 2px; }}")

        pw = QWidget(); pl = QVBoxLayout(pw); pl.setContentsMargins(0,0,8,0); pl.setSpacing(8)
        ph = QLabel("REPORT PREVIEW"); ph.setStyleSheet(f"QLabel {{ color: {ACCENT}; font-size: 11px; font-weight: bold; letter-spacing: 2px; background: transparent; border: none; }}"); pl.addWidget(ph)
        self._preview = QTextEdit(); self._preview.setReadOnly(True)
        self._preview.setStyleSheet(f"QTextEdit {{ background-color: {BG_SIDEBAR}; border: 1px solid {BORDER}; border-radius: 5px; color: {TEXT_PRIMARY}; font-family: 'Consolas','Courier New',monospace; font-size: 11px; padding: 12px; }}")
        pl.addWidget(self._preview); splitter.addWidget(pw)

        hw = QWidget(); hl = QVBoxLayout(hw); hl.setContentsMargins(8,0,0,0); hl.setSpacing(8)
        hh = QLabel("GENERATED REPORTS"); hh.setStyleSheet(f"QLabel {{ color: {ACCENT}; font-size: 11px; font-weight: bold; letter-spacing: 2px; background: transparent; border: none; }}"); hl.addWidget(hh)
        self._history_list = QListWidget(); self._history_list.doubleClicked.connect(self._open_report); hl.addWidget(self._history_list)
        ob = outline_button("Open Selected Report"); ob.clicked.connect(self._open_report); hl.addWidget(ob)
        splitter.addWidget(hw); splitter.setSizes([520,280]); layout.addWidget(splitter)

    def refresh(self):
        self._update_preview(); self._update_history()

    def _update_preview(self):
        stats = database.get_stats(); data = database.get_analytics(); breakdown = data.get('breakdown',[])
        lines = [
            "╔══════════════════════════════════════════════╗",
            "║          SIEM LITE — REPORT PREVIEW          ║",
            "╚══════════════════════════════════════════════╝","",
            f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}","",
            "  ── EXECUTIVE SUMMARY ──────────────────────────",
            f"  Total Logs Collected   : {stats['total_logs']:>8,}",
            f"  Total Security Alerts  : {stats['total_alerts']:>8,}",
            f"  Critical Alerts        : {stats['critical']:>8,}",
            f"  High Severity Alerts   : {stats['high']:>8,}",
            f"  Active Blocked IPs     : {stats['blocked_ips']:>8,}",
            f"  Unacknowledged Alerts  : {stats['unacknowledged']:>8,}","",
            "  ── ALERT BREAKDOWN ─────────────────────────────",
        ]
        total = sum(r.get('count',0) for r in breakdown)
        for row in breakdown:
            rule = row.get('rule','Unknown')[:32]; count = row.get('count',0); pct = (count/total*100) if total else 0
            lines.append(f"  {rule:<34}  {count:>4}  ({pct:5.1f}%)")
        lines += ["","  Click 'Generate Security Report' to export PDF."]
        self._preview.setPlainText("\n".join(lines))

    def _update_history(self):
        self._history_list.clear()
        if not os.path.isdir(REPORTS_DIR): return
        files = sorted([f for f in os.listdir(REPORTS_DIR) if f.endswith('.pdf')], reverse=True)
        for fname in files:
            item = QListWidgetItem(fname); item.setData(Qt.UserRole, os.path.join(REPORTS_DIR,fname))
            item.setForeground(QColor(TEXT_PRIMARY)); self._history_list.addItem(item)
        if not files:
            ph = QListWidgetItem("No reports generated yet."); ph.setForeground(QColor(TEXT_MUTED)); ph.setFlags(Qt.NoItemFlags); self._history_list.addItem(ph)

    def _generate(self):
        filename = f"SIEM_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        path, _ = QFileDialog.getSaveFileName(self,"Save Security Report", os.path.join(REPORTS_DIR,filename),"PDF Files (*.pdf)")
        if not path: return
        self._gen_btn.setEnabled(False); self._gen_btn.setText("Generating…"); self._status_lbl.setText("")
        self._worker = ReportWorker(path)
        self._worker.finished.connect(self._on_done); self._worker.failed.connect(self._on_error); self._worker.start()

    def _on_done(self, filepath):
        self._gen_btn.setEnabled(True); self._gen_btn.setText("Generate Security Report  (PDF)")
        self._status_lbl.setStyleSheet(f"QLabel {{ color: {LOW}; font-size: 11px; background: transparent; border: none; }}")
        self._status_lbl.setText(f"✓  Saved: {os.path.basename(filepath)}"); self._update_history()

    def _on_error(self, error):
        self._gen_btn.setEnabled(True); self._gen_btn.setText("Generate Security Report  (PDF)")
        self._status_lbl.setStyleSheet(f"QLabel {{ color: {CRITICAL}; font-size: 11px; background: transparent; border: none; }}")
        self._status_lbl.setText(f"✗  Failed: {error}")
        QMessageBox.critical(self,"Report Failed",f"Could not generate PDF:\n\n{error}\n\npip install reportlab")

    def _open_report(self):
        item = self._history_list.currentItem()
        if not item: return
        filepath = item.data(Qt.UserRole)
        if not filepath or not os.path.exists(filepath): return
        import subprocess, sys
        try:
            if sys.platform.startswith('linux'): subprocess.Popen(['xdg-open',filepath])
            elif sys.platform == 'darwin': subprocess.Popen(['open',filepath])
            else: os.startfile(filepath)
        except Exception as exc:
            QMessageBox.warning(self,"Cannot Open",f"Could not open:\n{exc}")
