#!/usr/bin/env python3
"""
cloudgate.py

CloudGate — a real, dynamic AWS security auditing tool.

Connects to whatever AWS account you point it at (via your own AWS
credentials) and scans its ACTUAL live configuration — nothing hardcoded,
nothing simulated. Every finding reflects the real state of the account
at the moment you run it.

Checks performed:
  - IAM: over-privileged roles, missing MFA, root account hygiene
  - S3: public buckets, missing encryption
  - EC2: internet-facing instances with attached IAM roles, IMDSv2 status
  - Logging: CloudTrail coverage, GuardDuty status

This is the same category of misconfiguration that led to the 2019
Capital One breach (public proxy -> IMDS -> stolen IAM credentials ->
S3 data theft). Running this regularly catches that pattern before it
can be exploited.

SCOPE & SAFETY
- Every check is a READ-ONLY AWS API call. Nothing is ever modified.
- Network checks read security group RULES via the API only — no
  packets are ever sent to any host.
- Run this only against an AWS account you own or are authorized to audit.

USAGE
    python3 cloudgate.py                # guided setup if needed, then full scan
    python3 cloudgate.py --profile work
    python3 cloudgate.py --iam --s3 --ports --ec2 --logging --mfa
    python3 cloudgate.py --output report.json
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

from utils.aws_client import get_session
from core import iam_check, s3_check, ports_check, ec2_check, logging_check, mfa_check, reporter

CREDENTIALS_PATH = os.path.expanduser("~/.aws/credentials")


def ensure_credentials_exist():
    """
    Guided auth workflow: if no AWS credentials file exists at all,
    walk the user through `aws configure` instead of failing with a
    raw boto3 error.
    """
    if os.path.exists(CREDENTIALS_PATH):
        return

    print("=" * 60)
    print("No AWS credentials found.")
    print("=" * 60)
    print("CloudGate needs AWS credentials for the account you want to")
    print("check. This will run `aws configure` for you now.")
    print("You'll need your own IAM user's Access Key ID and Secret")
    print("Access Key (from AWS Console -> IAM -> Users -> your user ->")
    print("Security credentials).")
    print("=" * 60)

    answer = input("Run `aws configure` now? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes"):
        subprocess.run(["aws", "configure"])
    else:
        print("\n[ABORTED] Run `aws configure` manually, then re-run CloudGate.")
        sys.exit(1)


def list_profiles():
    """Return profile names found in ~/.aws/credentials, if any."""
    if not os.path.exists(CREDENTIALS_PATH):
        return []
    profiles = []
    with open(CREDENTIALS_PATH) as f:
        for line in f:
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                profiles.append(line[1:-1])
    return profiles


def choose_profile(explicit_profile: str):
    """
    If the user passed --profile, use it. Otherwise, if multiple profiles
    exist, let them pick one interactively. If only one exists, use it.
    """
    if explicit_profile:
        return explicit_profile

    profiles = list_profiles()

    if len(profiles) <= 1:
        return None  # let boto3 use its default resolution

    print("\nMultiple AWS profiles found:")
    for i, name in enumerate(profiles, 1):
        print(f"  {i}. {name}")

    choice = input(f"Select a profile [1-{len(profiles)}]: ").strip()
    try:
        idx = int(choice) - 1
        return profiles[idx]
    except (ValueError, IndexError):
        print("[ERROR] Invalid selection.")
        sys.exit(1)


def write_json_report(findings: list, identity: dict, path: str):
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account": identity.get("Account"),
        "scanned_as": identity.get("Arn"),
        "finding_count": len(findings),
        "findings": findings,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="CloudGate — real-time AWS security auditor "
                     "(read-only, run against your own account)."
    )
    parser.add_argument("--profile", default=None, help="AWS CLI profile to use")
    parser.add_argument("--iam", action="store_true", help="Run IAM over-privilege check")
    parser.add_argument("--s3", action="store_true", help="Run S3 exposure check")
    parser.add_argument("--ports", action="store_true", help="Run open-ports/security-group check")
    parser.add_argument("--ec2", action="store_true", help="Run EC2/IMDS exposure check")
    parser.add_argument("--logging", action="store_true", help="Run CloudTrail/GuardDuty check")
    parser.add_argument("--mfa", action="store_true", help="Run root/MFA hygiene check")
    parser.add_argument("--all", action="store_true", help="Run all checks (default if none specified)")
    parser.add_argument("--output", default=None, help="Write findings to a JSON file")
    args = parser.parse_args()

    any_specific = any([args.iam, args.s3, args.ports, args.ec2, args.logging, args.mfa])
    run_all = args.all or not any_specific

    ensure_credentials_exist()
    profile = choose_profile(args.profile)
    session, identity = get_session(profile)

    findings = []

    if run_all or args.iam:
        iam_check.run(session, findings)
    if run_all or args.s3:
        s3_check.run(session, findings)
    if run_all or args.ports:
        ports_check.run(session, findings)
    if run_all or args.ec2:
        ec2_check.run(session, findings)
    if run_all or args.logging:
        logging_check.run(session, findings)
    if run_all or args.mfa:
        mfa_check.run(session, findings)

    reporter.print_report(findings)

    if args.output:
        write_json_report(findings, identity, args.output)
        print(f"\n[*] JSON report written to {args.output}")


if __name__ == "__main__":
    main()
