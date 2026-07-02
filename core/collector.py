"""
SIEM Lite — Log Collection Module
Runs two collection paths simultaneously:

  1. Network server  — listens on TCP port 5000 for remote agents.
                       Handles multi-line / large payloads correctly.
  2. Local collector — polls journalctl every COLLECT_INTERVAL seconds
                       for logs produced on the SIEM server itself.

Design decisions:
  - Each remote client gets its own thread (lightweight for expected load).
  - The local seen-set is capped at SEEN_LOG_MAX_SIZE to prevent unbounded
    memory growth over long uptimes.
  - All DB writes go through database.py — no raw SQL here.
  - Parser errors are caught and logged; they never kill a collection thread.
"""

import socket
import threading
import subprocess
import time
import logging
from core import database
from core.parser import parse_log
from config import (
    SERVER_HOST, SERVER_PORT,
    BUFFER_SIZE, SOCKET_TIMEOUT,
    COLLECT_INTERVAL, SEEN_LOG_MAX_SIZE,
)

log = logging.getLogger(__name__)


class LogCollector:

    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        self.host    = host
        self.port    = port
        self.running = False
        self._server_sock: socket.socket | None = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start both collection threads. Non-blocking — returns immediately."""
        database.setup()
        self.running = True

        net_thread = threading.Thread(
            target=self._run_server, name="collector-net", daemon=True
        )
        net_thread.start()

        local_thread = threading.Thread(
            target=self._run_local, name="collector-local", daemon=True
        )
        local_thread.start()

        log.info("[COLLECTOR] Started — network on port %s, local polling every %ss",
                 self.port, COLLECT_INTERVAL)

    def stop(self) -> None:
        self.running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        log.info("[COLLECTOR] Stopped")

    # ── Network Server ─────────────────────────────────────────────────────────

    def _run_server(self) -> None:
        """Accept incoming TCP connections from remote log agents."""
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.host, self.port))
            self._server_sock.listen(20)
            self._server_sock.settimeout(1.0)   # allows clean shutdown check
            log.info("[COLLECTOR] Listening on %s:%s", self.host, self.port)
        except OSError as exc:
            log.error("[COLLECTOR] Cannot bind port %s: %s", self.port, exc)
            return

        while self.running:
            try:
                client, addr = self._server_sock.accept()
            except socket.timeout:
                continue          # loop back and check self.running
            except OSError:
                break             # socket was closed by stop()

            t = threading.Thread(
                target=self._handle_client,
                args=(client, addr),
                name=f"client-{addr[0]}",
                daemon=True,
            )
            t.start()

    def _handle_client(self, client: socket.socket, addr: tuple) -> None:
        """
        Read ALL data from a connected agent.

        Protocol: agent sends one or more newline-terminated log lines,
        then closes the connection.  We read until EOF so no log line
        is ever truncated regardless of size.
        """
        source_ip = addr[0]
        client.settimeout(SOCKET_TIMEOUT)
        chunks: list[bytes] = []

        try:
            while True:
                chunk = client.recv(BUFFER_SIZE)
                if not chunk:
                    break           # EOF — agent closed its side
                chunks.append(chunk)
        except socket.timeout:
            pass                    # agent slow but we have what we got
        except OSError as exc:
            log.warning("[COLLECTOR] Socket error from %s: %s", source_ip, exc)
        finally:
            client.close()

        if not chunks:
            return

        raw_data = b"".join(chunks).decode("utf-8", errors="replace")

        # Each agent message may contain multiple newline-separated log lines
        for line in raw_data.splitlines():
            line = line.strip()
            if not line:
                continue
            self._process_line(line, source_ip)

    # ── Local Collection ───────────────────────────────────────────────────────

    def _run_local(self) -> None:
        """
        Poll journalctl for new log lines every COLLECT_INTERVAL seconds.
        Keeps a capped seen-set to deduplicate without leaking memory.
        """
        seen: set[str] = set()

        while self.running:
            try:
                output = subprocess.getoutput(
                    "journalctl -n 200 --no-pager --output=short-iso "
                    "--since '2 minutes ago'"
                )
                lines = output.splitlines()

                for line in lines:
                    line = line.strip()
                    if not line or line in seen:
                        continue

                    seen.add(line)
                    self._process_line(line, '127.0.0.1')

                # ── Prune seen-set to prevent unbounded growth ─────────────
                if len(seen) > SEEN_LOG_MAX_SIZE:
                    # Discard the oldest half — convert to list, keep newest
                    seen_list = list(seen)
                    seen = set(seen_list[len(seen_list) // 2:])
                    log.debug("[COLLECTOR] Pruned seen-set to %d entries", len(seen))

            except Exception as exc:
                log.error("[COLLECTOR] Local collection error: %s", exc)

            time.sleep(COLLECT_INTERVAL)

    # ── Shared Processing ──────────────────────────────────────────────────────

    def _process_line(self, line: str, source_ip: str) -> None:
        """Parse a single log line and persist it to the database."""
        try:
            parsed = parse_log(line, source_ip)
            database.insert_normal_log(
                timestamp  = parsed['timestamp'],
                hostname   = parsed['hostname'],
                event_type = parsed['event_type'],
                user       = parsed['user'],
                ip         = parsed['ip'],
                raw        = parsed['raw'],
                source_os  = parsed['source_os'],
            )
        except Exception as exc:
            log.error("[COLLECTOR] Failed to process line from %s: %s | line: %.120s",
                      source_ip, exc, line)
