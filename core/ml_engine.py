"""
SIEM Lite — ML Anomaly Detection Engine
Uses Isolation Forest to detect unusual log behaviour that rule-based
detection would miss (zero-day patterns, slow reconnaissance, etc.).

Pipeline:
  1. Every ML_RETRAIN_INTERVAL seconds: fetch last N normal logs,
     extract features, fit IsolationForest + StandardScaler.
  2. Every ML_DETECT_INTERVAL seconds: score logs from the last
     ML_LOOKBACK_MINUTES window against the fitted model.
  3. Any log scored as an outlier (prediction == -1) AND whose
     anomaly score clears ML_SCORE_THRESHOLD raises an alert.

Feature vector (7 dimensions):
  [0] hour_of_day        — 0-23, captures time-of-day patterns
  [1] is_failed_login    — binary
  [2] is_successful_login— binary
  [3] is_sudo            — binary
  [4] is_root_involved   — binary
  [5] is_ssh             — binary
  [6] raw_length         — normalised log length (proxy for verbosity)

"""

import threading
import time
import logging
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from core import database
from config import (
    ML_CONTAMINATION,
    ML_MIN_SAMPLES,
    ML_RETRAIN_INTERVAL,
    ML_DETECT_INTERVAL,
    ML_LOOKBACK_MINUTES,
    # ✅ NEW — add these two to your config.py if not already there:
    # ML_SCORE_THRESHOLD = -0.12   (only alert if score < this; more negative = more anomalous)
    # ML_DEDUP_BUCKET_MINUTES = 30 (how long before the same log can re-alert)
)

log = logging.getLogger(__name__)

# ── Tuneable defaults (override via config.py) ─────────────────────────────────
try:
    from config import ML_SCORE_THRESHOLD
except ImportError:
    # Only alert on genuinely anomalous scores — shallow outliers skip
    # score_samples returns negative values; -0.12 filters ~top 30% of outliers
    ML_SCORE_THRESHOLD = -0.12

try:
    from config import ML_DEDUP_BUCKET_MINUTES
except ImportError:
    # 30-minute bucket — same log can't re-alert within the same half-hour
    ML_DEDUP_BUCKET_MINUTES = 30


class MLEngine:

    def __init__(self):
        self.running  = False
        self._model   : IsolationForest | None = None
        self._scaler  : StandardScaler  | None = None
        self._trained = False
        self._model_lock  = threading.Lock()
        self._cb_lock     = threading.Lock()
        self._callbacks: list = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def add_callback(self, func) -> None:
        with self._cb_lock:
            self._callbacks.append(func)

    def start(self) -> None:
        self.running = True
        t = threading.Thread(
            target=self._run, name="ml-engine", daemon=True
        )
        t.start()
        log.info("[ML ENGINE] Started")

    def stop(self) -> None:
        self.running = False
        log.info("[ML ENGINE] Stopped")

    @property
    def is_trained(self) -> bool:
        return self._trained

    # ── Main Loop ──────────────────────────────────────────────────────────────

    def _run(self) -> None:
        last_train = 0.0
        while self.running:
            try:
                now = time.time()
                if now - last_train >= ML_RETRAIN_INTERVAL:
                    self._train()
                    last_train = now
                if self._trained:
                    self._detect()
            except Exception as exc:
                log.error("[ML ENGINE] Unexpected error: %s", exc, exc_info=True)
            time.sleep(ML_DETECT_INTERVAL)

    # ── Feature Extraction ─────────────────────────────────────────────────────

    @staticmethod
    def _extract_features(logs: list[dict]) -> np.ndarray:
        """
        Convert a list of log dicts into a 2-D numpy feature matrix.
        Each row is one log event; columns are the 7 features above.
        """
        rows = []
        for log_row in logs:
            raw   = (log_row.get('raw') or '').lower()
            ts    = (log_row.get('timestamp') or '')

            # ── hour of day ───────────────────────────────────────────────
            hour = 0
            try:
                time_part = ts.split(' ')[-1] if ' ' in ts else ts
                hour = int(time_part.split(':')[0])
                hour = max(0, min(23, hour))
            except (ValueError, IndexError):
                pass

            rows.append([
                hour,
                1 if ('failed password'        in raw or
                      'authentication failure' in raw) else 0,
                1 if ('accepted password'       in raw or
                      'accepted publickey'      in raw) else 0,
                1 if 'sudo'                     in raw else 0,
                1 if 'root'                     in raw else 0,
                1 if ('sshd' in raw or 'ssh2'  in raw) else 0,
                min(len(raw), 2000),
            ])

        return np.array(rows, dtype=np.float64)

    # ── Training ───────────────────────────────────────────────────────────────

    def _train(self) -> None:
        """
        Fetch recent normal logs, extract features, fit scaler + model.
        The new model/scaler pair replaces the old one atomically.
        """
        logs = database.get_recent_logs(limit=2000)

        if len(logs) < ML_MIN_SAMPLES:
            log.info(
                "[ML ENGINE] Training skipped — only %d logs (need %d)",
                len(logs), ML_MIN_SAMPLES
            )
            return

        features = self._extract_features(logs)

        new_scaler = StandardScaler()
        scaled     = new_scaler.fit_transform(features)

        new_model  = IsolationForest(
            contamination = ML_CONTAMINATION,
            n_estimators  = 200,
            max_samples   = 'auto',
            random_state  = 42,
            n_jobs        = -1,
        )
        new_model.fit(scaled)

        with self._model_lock:
            self._model   = new_model
            self._scaler  = new_scaler
            self._trained = True

        log.info("[ML ENGINE] Trained on %d logs", len(logs))

    # ── Detection ──────────────────────────────────────────────────────────────

    def _detect(self) -> None:
        """
        Score recent logs against the fitted model.

        Two-gate filtering to cut false positives:
          Gate 1 — Isolation Forest prediction must be -1 (outlier).
          Gate 2 — score_samples must be < ML_SCORE_THRESHOLD.
                   Shallow outliers (score close to 0) are skipped.

        Dedup bucket is ML_DEDUP_BUCKET_MINUTES wide so the same log
        cannot re-alert every detection cycle.
        """
        with self._model_lock:
            if not self._trained:
                return
            model  = self._model
            scaler = self._scaler

        conn = database.get_conn()
        try:
            rows = conn.execute("""
                SELECT * FROM normal_logs
                WHERE created_at >= datetime('now', ? || ' minutes')
            """, (f'-{ML_LOOKBACK_MINUTES}',)).fetchall()
        finally:
            conn.close()

        logs = [dict(r) for r in rows]
        if not logs:
            return

        features     = self._extract_features(logs)
        scaled       = scaler.transform(features)
        predictions  = model.predict(scaled)
        scores       = model.score_samples(scaled)

        for log_row, pred, score in zip(logs, predictions, scores):
            # ✅ Gate 1: must be flagged as outlier
            if pred != -1:
                continue

            # ✅ Gate 2: score must clear the confidence threshold
            # score_samples returns negative values — more negative = more anomalous
            # ML_SCORE_THRESHOLD default -0.12 skips shallow/noisy outliers
            if score >= ML_SCORE_THRESHOLD:
                log.debug(
                    "[ML ENGINE] Skipping shallow outlier — score: %.4f (threshold: %.4f)",
                    score, ML_SCORE_THRESHOLD
                )
                continue

            ip     = log_row.get('ip',   'unknown')
            user   = log_row.get('user', 'unknown')
            log_id = log_row.get('id', 0)

            # ✅ 30-minute dedup bucket — same log won't re-alert every cycle
            now    = datetime.now()
            bucket = now.strftime('%Y%m%d%H') + str(
                (now.minute // ML_DEDUP_BUCKET_MINUTES) * ML_DEDUP_BUCKET_MINUTES
            )
            dedup  = f"ml_anomaly:{log_id}:{bucket}"

            if database.is_duplicate_alert(dedup):
                continue

            database.register_alert(dedup)

            # Classify severity — only reached for genuinely anomalous scores
            if score < -0.20:
                severity = 'critical'
            elif score < -0.15:
                severity = 'high'
            else:
                severity = 'medium'

            alert = {
                'timestamp':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'hostname':   log_row.get('hostname', 'unknown'),
                'event_type': 'ml_anomaly',
                'user':       user,
                'ip':         ip,
                'raw':        log_row.get('raw', ''),
                'reason':     (
                    f'ML anomaly score: {score:.4f} '
                    f'(threshold: {ML_SCORE_THRESHOLD})'
                ),
                'severity':   severity,
                'rule':       'ML Anomaly Detection',
            }

            database.insert_malicious_log(**alert)
            self._notify(alert)
            log.warning(
                "[ML][%s] Anomaly — ip: %s, user: %s, score: %.4f",
                severity.upper(), ip, user, score
            )

    # ── Callbacks ──────────────────────────────────────────────────────────────

    def _notify(self, alert: dict) -> None:
        with self._cb_lock:
            callbacks = list(self._callbacks)
        for cb in callbacks:
            try:
                cb(alert)
            except Exception as exc:
                log.warning("[ML ENGINE] Callback error: %s", exc)
