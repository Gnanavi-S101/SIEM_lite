# SIEM Lite

A lightweight, Python-based Security Information and Event Management (SIEM) 
system for real-time log monitoring, hybrid threat detection, and automated 
IP blocking — built as a low-cost alternative to enterprise SIEM tools.

## Features
- Real-time log collection (local + remote agents, Linux & Windows)
- Rule-based detection (5 rules: brute force, sudo failure, off-hours login, 
  new user creation, first-time IP login)
- ML-based anomaly detection using Isolation Forest
- Automatic IP blocking via iptables
- Role-based GUI (admin / analyst / viewer) built with PyQt5
- PDF security report generation
- SQLite-backed storage with deduplication logic

## Tech Stack
Python · PyQt5 · SQLite · scikit-learn · ReportLab

## Project Structure
SIEM-Lite/
│
├── main_window.py
├── config.py
├── attack.py
│
├── core/
│   ├── __init__.py
│   ├── database.py
│   ├── parser.py
│   ├── detector.py
│   ├── ml_engine.py
│   └── collector.py
│
├── ui/
│   ├── __init__.py
│   ├── login_window.py
│   ├── dashboard_page.py
│   ├── alerts_page.py
│   ├── blocked_page.py
│   ├── logs_page.py
│   ├── analytics_page.py
│   ├── reports_page.py
│   └── settings_page_.py
│
├── agent.py
├── requirements.txt
└── README.md

## Setup
\`\`\`bash
pip install -r requirements.txt
python main_window.py
\`\`\`

