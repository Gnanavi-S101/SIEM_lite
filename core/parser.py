"""
SIEM Lite — Log Parser & Normalizer
Converts raw unstructured log strings from Linux (syslog / journalctl),
Windows Event Log, and generic sources into a clean, consistent dict that
the rest of the pipeline can rely on.

Output schema (always present, never None):
    timestamp  : str  — ISO-8601 or original string
    hostname   : str
    event_type : str  — normalised category
    user       : str
    ip         : str
    raw        : str  — original untouched line
    source_os  : str  — 'linux' | 'windows' | 'unknown'
"""

import re
import logging
from datetime import datetime

log = logging.getLogger(__name__)

# ── Compiled Patterns (compiled once at import, never re-compiled) ─────────────

# Standard syslog:  "May  7 14:23:01 hostname process[pid]: message"
_SYSLOG = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'   # timestamp
    r'(\S+)\s+'                                        # hostname
    r'(\S+?)(?:\[\d+\])?:\s+'                         # process (optional PID)
    r'(.*)'                                            # message
)

# journalctl --no-pager long format:
# "2024-05-07 14:23:01 hostname process[pid]: message"
_JOURNALCTL = re.compile(
    r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp
    r'(\S+)\s+'                                        # hostname
    r'(\S+?)(?:\[\d+\])?:\s+'                         # process
    r'(.*)'                                            # message
)

# Windows Event Log export (tab / space separated):
# "2024-05-07 14:23:01  Security  4625  ..."
_WINDOWS = re.compile(
    r'^(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})'   # timestamp
    r'.*?(\d{4,5})'                                    # event id
)

# IPv4 — excludes loopback
_IPV4 = re.compile(r'\b((?!127\.)\d{1,3}(?:\.\d{1,3}){3})\b')

# User extraction — ordered most-specific → least-specific
_USER_PATTERNS = [
    re.compile(r'for\s+invalid\s+user\s+(\S+)',   re.IGNORECASE),
    re.compile(r'for\s+user\s+(\S+)',             re.IGNORECASE),
    re.compile(r'for\s+(\w+)\s+from',             re.IGNORECASE),
    # sudo summary: "alice : 3 incorrect password attempts ; TTY=..."
    re.compile(r'sudo\[\d+\]:\s+(\w+)\s+:',      re.IGNORECASE),
    re.compile(r'user[=:\s]+(\w+)',               re.IGNORECASE),
    re.compile(r'USER=(\S+)',                     re.IGNORECASE),
    re.compile(r'account\s+(\S+)\s+was',         re.IGNORECASE),
    re.compile(r'useradd.*?(\w+)$',              re.IGNORECASE),
]

# Words that should never be returned as a username
_INVALID_USERS = {
    'invalid', 'unknown', 'failed', 'accepted', 'password',
    'publickey', 'from', 'port', 'ssh', 'pam', 'sudo', 'root',
    'session', 'opened', 'closed', 'error', 'warning', 'notice',
}

# ── Event Type Detection ───────────────────────────────────────────────────────

# Each entry: (keyword_list, event_type_string)
# Evaluated in order — first match wins
_EVENT_RULES = [
    (['failed password', 'authentication failure', 'invalid user',
      'failed publickey'],                              'failed_login'),
    (['accepted password', 'accepted publickey',
      'session opened for user'],                       'successful_login'),
    (['sudo:', 'sudo '],                               'sudo'),
    (['useradd', 'new user:', 'net user'],             'user_creation'),
    (['userdel', 'removed user', 'delete user'],      'user_deletion'),
    (['connection closed', 'disconnected from',
      'connection reset'],                             'ssh_disconnect'),
    (['sshd', 'ssh2'],                                'ssh'),
    (['cron', 'crond', 'crontab'],                    'cron'),
    (['systemd', 'systemd-logind'],                   'system'),
    (['kernel:', 'kernel '],                          'kernel'),
    (['ufw', 'iptables', 'firewall'],                 'firewall'),
    (['su:', 'su '],                                  'su'),
    (['passwd', 'password changed'],                  'password_change'),
]


def _detect_event_type(raw: str) -> str:
    lower = raw.lower()
    for keywords, event_type in _EVENT_RULES:
        if any(kw in lower for kw in keywords):
            return event_type
    return 'general'


def _extract_user(raw: str) -> str:
    for pattern in _USER_PATTERNS:
        m = pattern.search(raw)
        if m:
            candidate = m.group(1).strip().lower()
            if candidate not in _INVALID_USERS and len(candidate) >= 2:
                return m.group(1).strip()
    return 'unknown'


def _extract_ip(raw: str) -> str | None:
    """Return the first non-loopback IPv4 address found in the string."""
    m = _IPV4.search(raw)
    return m.group(1) if m else None


def _now_str() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _detect_os(raw: str) -> str:
    lower = raw.lower()
    if any(k in lower for k in ['eventid', 'windows', 'winlogon',
                                  'security', '4624', '4625', '4720']):
        return 'windows'
    if any(k in lower for k in ['sshd', 'sudo', 'useradd', 'systemd',
                                  'cron', 'kernel', 'journalctl']):
        return 'linux'
    return 'unknown'


# ── Public API ─────────────────────────────────────────────────────────────────

def parse_log(raw: str, source_ip: str = 'unknown') -> dict:
    """
    Parse a single raw log line into a normalised record.
    Never raises — always returns a complete dict.
    """
    raw = raw.strip()
    if not raw:
        return _fallback(raw, source_ip)

    # ── Try journalctl ISO timestamp format first ──────────────────────────
    m = _JOURNALCTL.match(raw)
    if m:
        return _build(
            timestamp  = m.group(1),
            hostname   = m.group(2),
            raw        = raw,
            source_ip  = source_ip,
            source_os  = 'linux',
        )

    # ── Try classic syslog format ──────────────────────────────────────────
    m = _SYSLOG.match(raw)
    if m:
        # Normalise syslog timestamp to include current year
        ts_raw = m.group(1)
        try:
            dt = datetime.strptime(
                f"{datetime.now().year} {ts_raw}", "%Y %b %d %H:%M:%S"
            )
            timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            timestamp = ts_raw

        return _build(
            timestamp  = timestamp,
            hostname   = m.group(2),
            raw        = raw,
            source_ip  = source_ip,
            source_os  = 'linux',
        )

    # ── Try Windows Event Log format ───────────────────────────────────────
    m = _WINDOWS.match(raw)
    if m:
        return _build(
            timestamp  = m.group(1).replace('T', ' '),
            hostname   = source_ip,   # Windows logs often lack hostname
            raw        = raw,
            source_ip  = source_ip,
            source_os  = 'windows',
        )

    # ── Fallback ───────────────────────────────────────────────────────────
    return _fallback(raw, source_ip)


def _build(
    timestamp: str,
    hostname:  str,
    raw:       str,
    source_ip: str,
    source_os: str,
) -> dict:
    """Assemble a normalised record from already-extracted header fields."""
    return {
        'timestamp':  timestamp,
        'hostname':   hostname  or source_ip,
        'event_type': _detect_event_type(raw),
        'user':       _extract_user(raw),
        'ip':         _extract_ip(raw) or source_ip,
        'raw':        raw,
        'source_os':  source_os,
    }


def _fallback(raw: str, source_ip: str) -> dict:
    """Last-resort record when no pattern matches."""
    return {
        'timestamp':  _now_str(),
        'hostname':   source_ip,
        'event_type': _detect_event_type(raw),
        'user':       _extract_user(raw),
        'ip':         _extract_ip(raw) or source_ip,
        'raw':        raw,
        'source_os':  _detect_os(raw),
    }
         
