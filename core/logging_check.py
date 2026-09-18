"""
core/logging_check.py

Read-only checks for detection posture: CloudTrail and GuardDuty.
These determine whether an attack would even be noticed — the gap that
let the real Capital One breach go undetected for ~4 months.

Dynamic — reads the actual configuration of the connected account.
"""

from botocore.exceptions import ClientError


def run(session, findings: list):
    print("[*] Checking CloudTrail and GuardDuty status...")
    _check_cloudtrail(session, findings)
    _check_guardduty(session, findings)


def _check_cloudtrail(session, findings):
    ct = session.client("cloudtrail")
    try:
        trails = ct.describe_trails()["trailList"]
    except ClientError as e:
        print(f"[WARN] Could not describe CloudTrail trails: {e}")
        return

    if not trails:
        findings.append({
            "severity": "HIGH",
            "category": "LOGGING",
            "issue": "No CloudTrail trail configured — no audit log of API "
                     "activity in this account",
        })
        return

    if not any(t.get("IsMultiRegionTrail") for t in trails):
        findings.append({
            "severity": "MEDIUM",
            "category": "LOGGING",
            "issue": "No multi-region CloudTrail trail found — activity in "
                     "other regions may go unlogged",
        })


def _check_guardduty(session, findings):
    gd = session.client("guardduty")
    try:
        detector_ids = gd.list_detectors()["DetectorIds"]
    except ClientError as e:
        print(f"[WARN] Could not list GuardDuty detectors: {e}")
        return

    if not detector_ids:
        findings.append({
            "severity": "MEDIUM",
            "category": "LOGGING",
            "issue": "GuardDuty is not enabled — no automated threat detection active",
        })
