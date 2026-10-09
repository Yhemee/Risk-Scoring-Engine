"""30 test cases across 5 risk profiles.

Expected decisions are written by hand from the intended policy, NOT copied
from the engine's output. Success criterion: >= 27/30 correct (90%).

Run:  python test_risk_engine.py
"""
import unittest
from datetime import datetime

from risk_engine import AccessRequest, evaluate, PERMIT, STEP_UP, DENY

# 5-11 Oct 2026 = Mon..Sun
MON, TUE, WED, THU, FRI, SAT, SUN = (datetime(2026, 10, d) for d in range(5, 12))


def at(day, hour):
    return day.replace(hour=hour)


# (id, profile, role, device, location, time, failed_attempts, expected)
CASES = [
    # --- Profile 1: low-risk routine access ---
    ("T01", "P1 routine", "standard", "compliant", "usual", at(TUE, 10), 0, PERMIT),
    ("T02", "P1 routine", "standard", "compliant", "usual", at(WED, 14), 1, PERMIT),
    ("T03", "P1 routine", "standard", "compliant", "usual", at(MON, 8), 2, PERMIT),
    ("T04", "P1 routine", "standard", "unmanaged", "usual", at(THU, 11), 0, PERMIT),
    ("T05", "P1 routine", "standard", "compliant", "usual", at(TUE, 19), 0, PERMIT),
    ("T06", "P1 routine", "elevated", "compliant", "usual", at(TUE, 10), 0, PERMIT),
    # --- Profile 2: medium-risk raised-privilege request ---
    ("T07", "P2 raised privilege", "elevated", "unmanaged", "usual", at(WED, 10), 0, STEP_UP),
    ("T08", "P2 raised privilege", "privileged", "compliant", "usual", at(WED, 10), 0, STEP_UP),
    ("T09", "P2 raised privilege", "elevated", "compliant", "usual", at(THU, 10), 3, STEP_UP),
    ("T10", "P2 raised privilege", "elevated", "unmanaged", "usual", at(THU, 19), 0, STEP_UP),
    ("T11", "P2 raised privilege", "privileged", "compliant", "usual", at(FRI, 11), 1, STEP_UP),
    ("T12", "P2 raised privilege", "elevated", "compliant", "new_country", at(FRI, 11), 0, STEP_UP),
    # --- Profile 3: high-risk abnormal location ---
    ("T13", "P3 abnormal location", "standard", "unmanaged", "new_country", at(TUE, 10), 0, STEP_UP),
    ("T14", "P3 abnormal location", "standard", "compliant", "high_risk", at(TUE, 10), 0, STEP_UP),
    ("T15", "P3 abnormal location", "standard", "unmanaged", "high_risk", at(TUE, 10), 0, STEP_UP),
    ("T16", "P3 abnormal location", "elevated", "unmanaged", "high_risk", at(TUE, 10), 0, DENY),
    ("T17", "P3 abnormal location", "standard", "non_compliant", "high_risk", at(TUE, 3), 0, DENY),
    ("T18", "P3 abnormal location", "privileged", "compliant", "high_risk", at(TUE, 10), 0, DENY),
    # --- Profile 4: adversarial brute-force credential input ---
    ("T19", "P4 brute force", "standard", "compliant", "usual", at(TUE, 10), 5, DENY),
    ("T20", "P4 brute force", "standard", "compliant", "usual", at(TUE, 10), 10, DENY),
    ("T21", "P4 brute force", "privileged", "compliant", "usual", at(TUE, 10), 6, DENY),
    ("T22", "P4 brute force", "standard", "unmanaged", "new_country", at(TUE, 2), 4, DENY),
    ("T23", "P4 brute force", "standard", "compliant", "usual", at(TUE, 10), 4, STEP_UP),
    ("T24", "P4 brute force", "standard", "unmanaged", "usual", at(TUE, 10), 3, STEP_UP),
    # --- Profile 5: out-of-hours privileged access ---
    ("T25", "P5 out-of-hours privileged", "privileged", "compliant", "usual", at(TUE, 2), 0, STEP_UP),
    ("T26", "P5 out-of-hours privileged", "privileged", "unmanaged", "usual", at(TUE, 2), 0, STEP_UP),
    ("T27", "P5 out-of-hours privileged", "privileged", "non_compliant", "usual", at(TUE, 2), 0, DENY),
    ("T28", "P5 out-of-hours privileged", "privileged", "unmanaged", "new_country", at(TUE, 2), 0, DENY),
    ("T29", "P5 out-of-hours privileged", "elevated", "unmanaged", "usual", at(SUN, 3), 0, STEP_UP),
    ("T30", "P5 out-of-hours privileged", "privileged", "compliant", "usual", at(WED, 20), 0, STEP_UP),
]


class TestRiskEngine(unittest.TestCase):
    def test_all_cases_report(self):
        passed = 0
        print(f"\n{'ID':<4} {'Profile':<27} {'Score':>5}  {'Expected':<21} {'Actual':<21} Result")
        for cid, profile, role, dev, loc, ts, fails, expected in CASES:
            result = evaluate(AccessRequest(role, dev, loc, ts, fails))
            ok = result.decision == expected
            passed += ok
            print(f"{cid:<4} {profile:<27} {result.score:>5}  {expected:<21} {result.decision:<21} {'PASS' if ok else 'FAIL'}")
        pct = passed / len(CASES) * 100
        print(f"\n{passed}/{len(CASES)} correct ({pct:.1f}%). Target: >= 27/30 (90%).")
        self.assertEqual(len(CASES), 30)
        self.assertGreaterEqual(passed, 27)

    def test_invalid_input_rejected(self):
        with self.assertRaises(ValueError):
            evaluate(AccessRequest("admin", "compliant", "usual", at(TUE, 10), 0))
        with self.assertRaises(ValueError):
            evaluate(AccessRequest("standard", "compliant", "usual", at(TUE, 10), -1))


if __name__ == "__main__":
    unittest.main(verbosity=1)
