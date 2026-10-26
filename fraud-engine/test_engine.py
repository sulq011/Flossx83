#!/usr/bin/env python3
"""Flossx83 Fraud Engine unit tests (stdlib only): python3 test_engine.py"""
import unittest
from engine import FraudEngine, mask_pan


def msg(mti="0200", pan="tok_abc123def456", amount="000000010000", stan="123456",
        mcc=None, f12=None):
    fields = {
        "2_PAN_tokenized": pan,
        "3": "000000",
        "4": amount,
        "7": "0710143030",
        "11": stan,
    }
    if mcc:
        fields["18"] = mcc
    if f12:
        fields["12"] = f12
    return {"mti": mti, "fields": fields}


class TestFraudEngine(unittest.TestCase):

    def setUp(self):
        self.e = FraudEngine()

    def test_clean_transaction(self):
        r = self.e.score(msg(amount="000000005000"))  # 50.00
        self.assertEqual(r["decision"], "clean")
        self.assertEqual(r["recommended_action"], "approve")

    def test_high_amount_suspicious(self):
        r = self.e.score(msg(amount="000000600000"))  # 6000.00 -> 40 pts
        self.assertEqual(r["decision"], "suspicious")
        self.assertEqual(r["recommended_action"], "review")

    def test_extreme_amount_fraud(self):
        r = self.e.score(msg(amount="000009000000"))  # 90000.00 -> 80 pts
        self.assertEqual(r["decision"], "fraud")
        self.assertEqual(r["recommended_action"], "decline")

    def test_velocity_fraud_burst(self):
        for i in range(8):
            r = self.e.score(msg(stan=str(100000 + i)))
        self.assertEqual(r["decision"], "fraud")
        self.assertTrue(any(t["id"] == "R002" for t in r["triggered_rules"]))

    def test_invalid_mti(self):
        r = self.e.score(msg(mti="9999"))
        self.assertEqual(r["decision"], "suspicious")
        self.assertTrue(any(t["id"] == "R005" for t in r["triggered_rules"]))

    def test_missing_mandatory(self):
        m = msg()
        m["fields"].pop("3")
        m["fields"].pop("7")
        r = self.e.score(m)
        self.assertTrue(any(t["id"] == "R006" for t in r["triggered_rules"]))
        self.assertEqual(r["decision"], "suspicious")

    def test_replay_same_stan(self):
        first = self.e.score(msg(stan="555555"))
        second = self.e.score(msg(stan="555555"))
        self.assertEqual(first["decision"], "clean")
        self.assertTrue(any(t["id"] == "R008" for t in second["triggered_rules"]))

    def test_odd_hours_rule(self):
        r = self.e.score(msg(amount="000000200000", f12="033000"))  # 03:30, 2000.00
        self.assertTrue(any(t["id"] == "R003" for t in r["triggered_rules"]))

    def test_high_risk_mcc(self):
        r = self.e.score(msg(amount="000000300000", mcc="7995", f12="120000"))  # 3000, gambling
        self.assertTrue(any(t["id"] == "R004" for t in r["triggered_rules"]))
        self.assertEqual(r["decision"], "suspicious")

    def test_amount_from_field4_minor_units(self):
        r = self.e.score(msg(amount="000000010000"))
        self.assertEqual(r["meta"]["amount"], 100.00)

    def test_mask(self):
        self.assertEqual(mask_pan("1234567890123456"), "1234********3456")

    def test_no_pan_ok(self):
        m = msg()
        m["fields"].pop("2_PAN_tokenized")
        r = self.e.score(m)
        self.assertEqual(r["decision"], "clean")


if __name__ == "__main__":
    unittest.main(verbosity=2)
