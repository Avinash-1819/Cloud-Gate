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
            "resource": "CloudTrail",
            "service": "cloudtrail",
            "issue": "No CloudTrail trail configured — no audit log of API activity in this account",
            "remediation": "aws cloudtrail create-trail --name security-audit-trail --s3-bucket-name <BUCKET> && aws cloudtrail start-logging --name security-audit-trail",
        })
        return

    if not any(t.get("IsMultiRegionTrail") for t in trails):
        findings.append({
            "severity": "MEDIUM",
            "category": "LOGGING",
            "resource": "CloudTrail",
            "service": "cloudtrail",
            "issue": "No multi-region CloudTrail trail found — activity in other regions may go unlogged",
            "remediation": "aws cloudtrail update-trail --name <TRAIL> --is-multi-region-trail",
        })


def _check_guardduty(session, findings):
    gd = session.client("guardduty")
    try:
        detector_ids = gd.list_detectors()["DetectorIds"]
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code in ("SubscriptionRequiredException", "OptInRequired"):
            findings.append({
                "severity": "MEDIUM",
                "category": "LOGGING",
                "resource": "GuardDuty",
                "service": "guardduty",
                "issue": "GuardDuty automated threat detection is not enabled or subscribed in this account",
                "remediation": "aws guardduty create-detector --enable",
            })
            return
        print(f"[WARN] Could not check GuardDuty status: {e}")
        return

    if not detector_ids:
        findings.append({
            "severity": "MEDIUM",
            "category": "LOGGING",
            "resource": "GuardDuty",
            "service": "guardduty",
            "issue": "GuardDuty is not enabled — no automated threat detection active",
            "remediation": "aws guardduty create-detector --enable",
        })
