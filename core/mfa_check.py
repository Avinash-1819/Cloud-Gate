"""
core/mfa_check.py

Read-only checks on root account hygiene and MFA enforcement — a common
gap that turns a single leaked credential into full account compromise.

Dynamic — reads the account's actual IAM summary and credential report.
"""

import time
from botocore.exceptions import ClientError


def run(session, findings: list):
    iam = session.client("iam")
    print("[*] Checking root account and MFA hygiene...")

    _check_account_summary(iam, findings)
    _check_users_without_mfa(iam, findings)


def _check_account_summary(iam, findings):
    try:
        summary = iam.get_account_summary()["SummaryMap"]
    except ClientError as e:
        print(f"[WARN] Could not get account summary: {e}")
        return

    if summary.get("AccountMFAEnabled", 0) == 0:
        findings.append({
            "severity": "CRITICAL",
            "category": "IAM",
            "issue": "MFA is not enabled on the root account — a leaked root "
                     "password/key alone would be enough to fully compromise "
                     "this account",
        })

    if summary.get("AccountAccessKeysPresent", 0) > 0:
        findings.append({
            "severity": "CRITICAL",
            "category": "IAM",
            "issue": "Root account has active CLI access keys — root should "
                     "never have programmatic access keys",
        })


def _check_users_without_mfa(iam, findings):
    try:
        iam.generate_credential_report()
        time.sleep(2)  # report generation is async; brief wait before fetching
        report = iam.get_credential_report()
    except ClientError as e:
        print(f"[WARN] Could not fetch IAM credential report: {e}")
        return

    import csv
    import io

    csv_data = report["Content"].decode("utf-8")
    reader = csv.DictReader(io.StringIO(csv_data))

    for row in reader:
        user = row.get("user")
        if user == "<root_account>":
            continue
        if row.get("password_enabled") == "true" and row.get("mfa_active") == "false":
            findings.append({
                "severity": "HIGH",
                "category": "IAM",
                "issue": f"IAM user '{user}' has console password access but "
                         f"no MFA enabled",
            })
