"""
SIEM Lite — Universal Agent (Linux + Windows)
=============================================
Drop this single file on ANY machine (Linux or Windows).
It auto-detects the OS and collects the right logs.

USAGE
-----
  # Install dependency (only one needed):
  pip install psutil

  # Run (edit SIEM_HOST before first run):
  python agent.py

WHAT IT COLLECTS
----------------
  Linux  : /var/log/auth.log, /var/log/syslog, journalctl
  Windows: Security Event Log (4624/4625/4634/4720/4722/4725/4726/4740/4776)
           System Event Log, Application Event Log

PROTOCOL
--------
  Connects to SIEM server on TCP 5000, sends newline-separated log lines,
  then closes the connection.  Matches collector.py's _handle_client() exactly.
"""

import os
import sys
import socket
import time
import logging
import platform
import subprocess
import threading
import hashlib
from collections import deque
from datetime import datetime, timedelta

# ──────────────────────────────────────────────────────────────────────────────
# CONFIG  ← Edit these before deploying
# ──────────────────────────────────────────────────────────────────────────────
SIEM_HOST        = "X.X.X.X"   
SIEM_PORT        = 5000
SEND_INTERVAL    = 5          # seconds between each batch send
BATCH_SIZE       = 100         # max lines per TCP connection
LOG_LEVEL        = logging.INFO
AGENT_TAG        = platform.node()  # hostname of this machine
DEDUP_SIZE       = 5000        # how many recent log hashes to remember

# Linux-specific
LINUX_LOG_FILES  = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/secure",          # RHEL/CentOS/Fedora equivalent of auth.log
]
USE_JOURNALCTL   = True         # set False if journalctl not available

# Windows-specific
WIN_EVENT_CHANNELS = ["Security", "System", "Application"]
WIN_SECURITY_IDS   = {
    4624: "successful_login",
    4625: "failed_login",
    4634: "logoff",
    4647: "logoff",
    4720: "user_creation",
    4722: "user_enabled",
    4725: "user_disabled",
    4726: "user_deletion",
    4740: "account_lockout",
    4776: "credential_validation",
    4648: "explicit_credential_login",
    4672: "special_privileges",
    7045: "service_installed",
}
# ──────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [AGENT] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("siem_agent")

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"


# ══════════════════════════════════════════════════════════════════════════════
#  REAL IP DETECTION
#  Finds the machine's actual network IP (not the VirtualBox adapter IP).
#  This is embedded in every log line so the SIEM shows the correct source.
# ══════════════════════════════════════════════════════════════════════════════

def get_real_ip() -> str:
    """
    Return the machine's real outbound IP address.
    Works on Windows, Linux, and macOS regardless of VirtualBox adapters.
    Falls back gracefully if no network is available.
    """
    # Method 1: UDP trick — finds the IP used to reach the outside world
    # (no actual data is sent — connect() on UDP just sets the route)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass

    # Method 2: Try connecting to SIEM host itself to find the right interface
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((SIEM_HOST, SIEM_PORT))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass

    # Method 3: Hostname resolution fallback
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass

    return "unknown"


REAL_IP = get_real_ip()


def tag_line(line: str) -> str:
    """
    Append agent metadata to a log line so the SIEM can always identify
    which machine sent it, regardless of VirtualBox network topology.
    Format appended:  agent_ip=<real_ip> agent_host=<hostname>
    """
    return f"{line} agent_ip={REAL_IP} agent_host={AGENT_TAG}"


# ══════════════════════════════════════════════════════════════════════════════
#  DEDUPLICATION
#  Keeps a rolling set of hashes of recently sent lines.
#  If the same log line appears again within the dedup window, it's dropped.
#  Uses a deque so the memory footprint stays fixed at DEDUP_SIZE entries.
# ══════════════════════════════════════════════════════════════════════════════

class DedupFilter:
    def __init__(self, maxsize: int = DEDUP_SIZE):
        self._seen  = set()
        self._queue = deque()   # tracks insertion order for eviction
        self._max   = maxsize

    def is_duplicate(self, line: str) -> bool:
        # Hash only the core content — strip the timestamp so slightly
        # different timestamps on the same event don't bypass dedup
        core = line.split("agent_ip=")[0].strip()
        h    = hashlib.md5(core.encode("utf-8", errors="replace")).hexdigest()

        if h in self._seen:
            return True

        # Not seen before — record it
        self._seen.add(h)
        self._queue.append(h)

        # Evict oldest entry if over capacity
        if len(self._queue) > self._max:
            old = self._queue.popleft()
            self._seen.discard(old)

        return False

    def filter(self, lines: list[str]) -> list[str]:
        unique = []
        dupes  = 0
        for line in lines:
            if self.is_duplicate(line):
                dupes += 1
            else:
                unique.append(line)
        if dupes:
            log.debug("Dedup dropped %d duplicate line(s)", dupes)
        return unique


_dedup = DedupFilter()


# ══════════════════════════════════════════════════════════════════════════════
#  SENDER
# ══════════════════════════════════════════════════════════════════════════════

def send_lines(lines: list[str]) -> bool:
    """Send a batch of log lines to the SIEM server. Returns True on success."""
    if not lines:
        return True
    payload = "\n".join(lines) + "\n"
    try:
        with socket.create_connection((SIEM_HOST, SIEM_PORT), timeout=10) as s:
            s.sendall(payload.encode("utf-8", errors="replace"))
        log.info("Sent %d lines to %s:%s", len(lines), SIEM_HOST, SIEM_PORT)
        return True
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        log.warning("Send failed: %s", exc)
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  LINUX COLLECTORS
# ══════════════════════════════════════════════════════════════════════════════

class LinuxFileCollector:
    """Tail log files on Linux by remembering the last read position."""

    def __init__(self, paths: list[str]):
        self._paths      = paths
        self._positions  = {}    # path -> last byte offset

    def collect(self) -> list[str]:
        lines = []
        for path in self._paths:
            if not os.path.exists(path):
                continue
            try:
                pos = self._positions.get(path, 0)
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    new_lines = f.readlines()
                    self._positions[path] = f.tell()
                for line in new_lines:
                    line = line.strip()
                    if line:
                        lines.append(tag_line(line))
            except PermissionError:
                log.warning("Permission denied: %s  (try running as root)", path)
            except OSError as exc:
                log.error("Error reading %s: %s", path, exc)
        return lines


class LinuxJournalCollector:
    """Collect logs from journalctl since last run."""

    def __init__(self):
        self._last_run = datetime.now() - timedelta(seconds=SEND_INTERVAL)

    def collect(self) -> list[str]:
        since_str = self._last_run.strftime("%Y-%m-%d %H:%M:%S")
        self._last_run = datetime.now()
        try:
            result = subprocess.run(
                ["journalctl", "--no-pager", "--output=short-iso",
                 f"--since={since_str}"],
                capture_output=True, text=True, timeout=10,
            )
            lines = [tag_line(l.strip()) for l in result.stdout.splitlines() if l.strip()]
            return lines
        except FileNotFoundError:
            log.debug("journalctl not found — skipping")
            return []
        except subprocess.TimeoutExpired:
            log.warning("journalctl timed out")
            return []
        except Exception as exc:
            log.error("journalctl error: %s", exc)
            return []


# ══════════════════════════════════════════════════════════════════════════════
#  WINDOWS COLLECTORS
# ══════════════════════════════════════════════════════════════════════════════

def _format_win_event(event) -> str:
    """Convert a Windows Event Log record to a SIEM-compatible log string."""
    try:
        import win32evtlog  # type: ignore
        ts        = event.TimeGenerated.Format()          # e.g. "Wed May 15 14:23:01 2024"
        event_id  = event.EventID & 0xFFFF               # strip facility/severity bits
        category  = WIN_SECURITY_IDS.get(event_id, "general")
        src       = event.SourceName
        strings   = event.StringInserts or []
        msg_parts = [s for s in strings if s and s.strip()]
        msg       = " | ".join(msg_parts[:6])             # cap at 6 fields

        # Build a syslog-ish line the parser.py can handle
        line = (
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
            f"{AGENT_TAG} {src}[{event_id}]: "
            f"EventID={event_id} Category={category} agent_ip={REAL_IP} agent_host={AGENT_TAG} {msg}"
        )
        return line
    except Exception as exc:
        log.debug("Event format error: %s", exc)
        return ""


class WindowsEventCollector:
    """Read Windows Event Log channels using win32evtlog."""

    def __init__(self, channels: list[str]):
        self._channels  = channels
        self._handles   = {}
        self._available = False
        self._init()

    def _init(self):
        try:
            import win32evtlog  # type: ignore
            self._win32evtlog  = win32evtlog
            self._available    = True
            log.info("Windows Event Log collector initialised")
        except ImportError:
            log.warning(
                "pywin32 not installed. Run:  pip install pywin32\n"
                "Windows Event Log collection disabled until installed."
            )

    def collect(self) -> list[str]:
        if not self._available:
            return []
        try:
            import win32evtlog  # type: ignore
        except ImportError:
            return []

        lines = []
        for channel in self._channels:
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                          win32evtlog.EVENTLOG_SEQUENTIAL_READ)
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                count  = 0
                for event in (events or []):
                    line = _format_win_event(event)
                    if line:
                        lines.append(line)
                    count += 1
                    if count >= BATCH_SIZE:
                        break
                win32evtlog.CloseEventLog(handle)
            except Exception as exc:
                log.error("Windows event log error (%s): %s", channel, exc)
        return lines


class WindowsWMICollector:
    """
    Fallback: collect Security events via WMI if win32evtlog is unavailable.
    Requires: pip install wmi
    """

    def __init__(self):
        self._available = False
        try:
            import wmi  # type: ignore
            self._wmi = wmi.WMI()
            self._available = True
            log.info("WMI fallback collector initialised")
        except ImportError:
            pass
        except Exception as exc:
            log.warning("WMI init failed: %s", exc)

    def collect(self) -> list[str]:
        if not self._available:
            return []
        lines = []
        try:
            query = (
                "SELECT * FROM Win32_NTLogEvent WHERE Logfile='Security' "
                "AND EventCode IN (4624, 4625, 4634, 4720, 4726, 4740)"
            )
            for event in self._wmi.query(query)[:BATCH_SIZE]:
                eid      = event.EventCode
                category = WIN_SECURITY_IDS.get(int(eid), "general")
                msg      = (event.Message or "").replace("\n", " ")[:200]
                line = (
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
                    f"{AGENT_TAG} Security[{eid}]: "
                    f"EventID={eid} Category={category} agent_ip={REAL_IP} agent_host={AGENT_TAG} {msg}"
                )
                lines.append(line)
        except Exception as exc:
            log.error("WMI query error: %s", exc)
        return lines


# ══════════════════════════════════════════════════════════════════════════════
#  AGENT ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

class SIEMAgent:

    def __init__(self):
        self._collectors = []
        self._pending    = []   # unsent lines buffer (retry on next cycle)
        self._lock       = threading.Lock()

        if IS_LINUX:
            log.info("Platform: Linux — initialising Linux collectors")
            self._collectors.append(LinuxFileCollector(LINUX_LOG_FILES))
            if USE_JOURNALCTL:
                self._collectors.append(LinuxJournalCollector())

        elif IS_WINDOWS:
            log.info("Platform: Windows — initialising Windows collectors")
            win_col = WindowsEventCollector(WIN_EVENT_CHANNELS)
            self._collectors.append(win_col)
            if not win_col._available:
                log.info("Trying WMI fallback collector")
                self._collectors.append(WindowsWMICollector())

        else:
            log.warning("Unsupported platform: %s — no collectors loaded", platform.system())

    def run_once(self):
        """Collect and send one batch."""
        fresh_lines = []
        for collector in self._collectors:
            try:
                fresh_lines.extend(collector.collect())
            except Exception as exc:
                log.error("Collector error: %s", exc)

        # Drop duplicates before queuing
        fresh_lines = _dedup.filter(fresh_lines)

        with self._lock:
            self._pending.extend(fresh_lines)
            to_send = self._pending[:BATCH_SIZE]

        if not to_send:
            return

        success = send_lines(to_send)
        if success:
            with self._lock:
                self._pending = self._pending[len(to_send):]
            log.debug("Buffer remaining: %d lines", len(self._pending))
        else:
            log.warning("Send failed — %d lines queued for retry", len(self._pending))

    def run_forever(self):
        log.info(
            "SIEM Universal Agent started | host=%s port=%d interval=%ds | this machine: %s (%s)",
            SIEM_HOST, SIEM_PORT, SEND_INTERVAL, AGENT_TAG, REAL_IP,
        )
        while True:
            try:
                self.run_once()
            except KeyboardInterrupt:
                log.info("Agent stopped by user")
                sys.exit(0)
            except Exception as exc:
                log.error("Unexpected error: %s", exc)
            time.sleep(SEND_INTERVAL)


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if SIEM_HOST == "YOUR_SIEM_SERVER_IP":
        print(
            "\n[!] Please edit SIEM_HOST at the top of this file before running.\n"
            "    Set it to the IP address of your SIEM Lite server.\n"
        )
        sys.exit(1)
    SIEMAgent().run_forever()
