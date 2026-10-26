"""
Flossx83 Fraud Engine — Rule-Based Scoring Core (stdlib only, zero deps)
=======================================================================
Input  : parsed ISO 8583 transaction as dict (post-tokenization, PCI-safe):
         {"mti": "0200", "fields": {"2_PAN_tokenized": "...", "3": "000000", ...}}
Output : {"decision": "clean|suspicious|fraud", "score": 0-100,
          "recommended_action": "approve|review|decline",
          "triggered_rules": [...], "meta": {...}}
Rules are configurable via rules.json next to this file.
"""
import json
import os
import threading
import time
from collections import defaultdict, deque

RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")

DEFAULT_RULES = {
    "implied_decimals": 2,
    "amount_high": 5000.00,
    "amount_extreme": 50000.00,
    "odd_hours": [0, 1, 2, 3, 4, 5],
    "odd_hour_min_amount": 1000.00,
    "high_risk_mcc": ["7995", "7993", "6051", "4829", "5944"],
    "high_risk_mcc_min_amount": 2000.00,
    "allowed_mti": ["0100", "0101", "0200", "0201", "0210", "0220", "0221",
                    "0230", "0320", "0330", "0400", "0420", "0430",
                    "0800", "0810", "0820", "0830"],
    "mandatory_fields": ["3", "4", "7", "11"],
    "velocity_window_s": 60,
    "velocity_suspicious": 5,
    "velocity_fraud": 8,
    "replay_ttl_s": 120,
    "threshold_suspicious": 40,
    "threshold_fraud": 80,
}


def mask_pan(value: str) -> str:
    """PCI-style mask for PAN or PAN-token strings."""
    v = str(value)
    if len(v) <= 8:
        return "*" * len(v)
    return v[:4] + "*" * (len(v) - 8) + v[-4:]


class FraudEngine:
    """Stateful rule engine: velocity + replay tracking are in-memory per process."""

    def __init__(self, rules: dict | None = None):
        self.rules = dict(DEFAULT_RULES)
        if rules:
            self.rules.update(rules)
        self._load_rules_file()
        self._lock = threading.Lock()
        self._velocity = defaultdict(deque)   # pan_token -> deque[timestamps]
        self._stans = defaultdict(deque)     # (pan_token, stan) -> deque[timestamps]

    def _load_rules_file(self):
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                self.rules.update(json.load(f))
        except (OSError, json.JSONDecodeError):
            pass  # fall back to defaults

    def reset(self):
        with self._lock:
            self._velocity.clear()
            self._stans.clear()

    # ---------- field helpers ----------

    @staticmethod
    def _get(fields: dict, *names):
        for n in names:
            v = fields.get(n)
            if v is not None:
                return str(v)
        return None

    def _pan_token(self, fields: dict):
        return self._get(fields, "2_PAN_tokenized", "2", "pan_token")

    def _amount(self, fields: dict):
        raw = self._get(fields, "4", "amount")
        if raw is None:
            return None, "missing"
        digits = raw.replace(".", "").lstrip("0") or "0"
        if not digits.isdigit():
            return None, "non_numeric"
        try:
            return int(digits) / (10 ** self.rules["implied_decimals"]), "ok"
        except (ValueError, ZeroDivisionError):
            return None, "invalid"

    def _txn_hour(self, fields: dict):
        """Prefer transaction-local time (F12 HHMMSS), then F7 (MMDDhhmmss)."""
        f12 = self._get(fields, "12", "local_time")
        if f12 and len(f12) >= 2 and f12[:2].isdigit():
            return int(f12[:2])
        f7 = self._get(fields, "7", "transmission")
        if f7 and len(f7) >= 4 and f7[2:4].isdigit():
            return int(f7[2:4])
        return time.localtime().tm_hour

    # ---------- rules ----------

    def _r001_high_amount(self, amount, out):
        if amount is None:
            return
        if amount >= self.rules["amount_extreme"]:
            out.append({"id": "R001", "name": "extreme_amount", "points": 80,
                        "detail": f"amount {amount:.2f} >= extreme limit"})
        elif amount >= self.rules["amount_high"]:
            out.append({"id": "R001", "name": "high_amount", "points": 40,
                        "detail": f"amount {amount:.2f} >= high limit"})

    def _r002_velocity(self, pan, out):
        if pan is None:
            return
        now = time.time()
        win = self.rules["velocity_window_s"]
        with self._lock:
            dq = self._velocity[pan]
            dq.append(now)
            while dq and now - dq[0] > win:
                dq.popleft()
            count = len(dq)
        if count >= self.rules["velocity_fraud"]:
            out.append({"id": "R002", "name": "velocity_fraud", "points": 80,
                        "detail": f"{count} tx on same PAN-token within {win}s"})
        elif count >= self.rules["velocity_suspicious"]:
            out.append({"id": "R002", "name": "velocity_suspicious", "points": 25,
                        "detail": f"{count} tx on same PAN-token within {win}s"})

    def _r003_odd_hours(self, hour, amount, out):
        if hour in self.rules["odd_hours"] and amount and amount >= self.rules["odd_hour_min_amount"]:
            out.append({"id": "R003", "name": "odd_hours", "points": 15,
                        "detail": f"txn at hour {hour}:00 with amount {amount:.2f}"})

    def _r004_high_risk_mcc(self, fields, amount, out):
        mcc = self._get(fields, "18", "mcc")
        if mcc in self.rules["high_risk_mcc"] and amount and amount >= self.rules["high_risk_mcc_min_amount"]:
            out.append({"id": "R004", "name": "high_risk_mcc", "points": 40,
                        "detail": f"MCC {mcc} flagged high-risk with amount {amount:.2f}"})

    def _r005_invalid_mti(self, mti, out):
        if mti not in self.rules["allowed_mti"]:
            out.append({"id": "R005", "name": "invalid_mti", "points": 60,
                        "detail": f"MTI {mti!r} not in allowed set"})

    def _r006_missing_mandatory(self, fields, out):
        missing = [f for f in self.rules["mandatory_fields"] if fields.get(f) in (None, "")]
        if missing:
            out.append({"id": "R006", "name": "missing_mandatory",
                        "points": min(60, 20 * len(missing)),
                        "detail": "missing mandatory fields: " + ", ".join(missing)})

    def _r007_amount_anomaly(self, amount, status, out):
        if status != "ok":
            out.append({"id": "R007", "name": "amount_anomaly", "points": 30,
                        "detail": f"field 4 problem: {status}"})
        elif amount == 0:
            out.append({"id": "R007", "name": "zero_amount", "points": 10,
                        "detail": "transaction amount is zero"})

    def _r008_replay(self, pan, stan, out):
        if pan is None or stan is None:
            return
        now = time.time()
        ttl = self.rules["replay_ttl_s"]
        with self._lock:
            dq = self._stans[(pan, stan)]
            dq.append(now)
            while dq and now - dq[0] > ttl:
                dq.popleft()
            count = len(dq)
        if count > 1:
            out.append({"id": "R008", "name": "duplicate_stan_replay", "points": 40,
                        "detail": f"same PAN-token + STAN seen {count} times within {ttl}s"})

    # ---------- main entry ----------

    def score(self, msg: dict) -> dict:
        if not isinstance(msg, dict):
            return {"decision": "suspicious", "score": 0,
                    "recommended_action": "review",
                    "triggered_rules": [{"id": "R000", "name": "bad_payload",
                                         "points": 40,
                                         "detail": "request body is not a JSON object"}],
                    "meta": {}}

        mti = str(msg.get("mti") or "")
        fields = msg.get("fields") if isinstance(msg.get("fields"), dict) else {}

        pan = self._pan_token(fields)
        amount, amount_status = self._amount(fields)
        hour = self._txn_hour(fields)
        stan = self._get(fields, "11", "stan")

        triggered: list[dict] = []
        self._r001_high_amount(amount, triggered)
        self._r002_velocity(pan, triggered)
        self._r003_odd_hours(hour, amount, triggered)
        self._r004_high_risk_mcc(fields, amount, triggered)
        self._r005_invalid_mti(mti, triggered)
        self._r006_missing_mandatory(fields, triggered)
        self._r007_amount_anomaly(amount, amount_status, triggered)
        self._r008_replay(pan, stan, triggered)

        total = min(100, sum(r["points"] for r in triggered))
        if total >= self.rules["threshold_fraud"]:
            decision, action = "fraud", "decline"
        elif total >= self.rules["threshold_suspicious"]:
            decision, action = "suspicious", "review"
        else:
            decision, action = "clean", "approve"

        return {
            "decision": decision,
            "score": total,
            "recommended_action": action,
            "triggered_rules": triggered,
            "meta": {
                "mti": mti or None,
                "pan_masked": mask_pan(pan) if pan else None,
                "amount": amount if amount_status == "ok" else None,
                "stan": stan,
                "txn_hour": hour,
                "ts": int(time.time()),
            },
        }
