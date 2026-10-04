#!/usr/bin/env python3
"""
cloudgate.py

CloudGate 2.0 — Real-Time AWS Security Gatekeeper & Compliance Engine.

Integrates fast pre-logout posture checks with Prowler-powered deep
compliance audits (CIS AWS Benchmark, NIST, AWS Best Practices) to take
cloud security scanning to the next stage.

USAGE:
    python3 cloudgate.py                            # Fast pre-logout security gate (~3s)
    python3 cloudgate.py --level 2                  # Core infrastructure security audit
    python3 cloudgate.py --compliance cis_3.0_aws   # Audit against CIS AWS Benchmark 3.0
    python3 cloudgate.py --prowler                  # Next-stage deep Prowler audit
    python3 cloudgate.py --all-prowler              # Full enterprise audit across all AWS services
    python3 cloudgate.py --hybrid                   # Fast gate + deep compliance scan
    python3 cloudgate.py -i                         # Interactive guided mode
    python3 cloudgate.py --output report.json       # Export findings as JSON
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Optional, List

from utils.aws_client import get_session
from core import (
    iam_check,
    s3_check,
    ports_check,
    ec2_check,
    logging_check,
    mfa_check,
    kms_check,
    vpc_check,
    reporter,
    ui,
    prowler_engine,
)

CREDENTIALS_PATH = os.path.expanduser("~/.aws/credentials")
VERSION = "2.0"


def configure_credentials(profile_name: str = "default") -> bool:
    """
    Interactive AWS credentials configuration wizard.
    Saves securely to ~/.aws/credentials and ~/.aws/config with 0600 permissions.
    """
    print("\n" + "=" * 65)
    print(f"      CloudGate 2.0 — AWS Credential Setup ({profile_name})")
    print("=" * 65)
    print("🔒 PRIVACY GUARANTEE: CloudGate runs 100% client-side audits.")
    print("   Credentials are saved strictly on your local machine in ~/.aws/credentials.")
    print("   Zero credentials are ever sent to CloudGate or any remote server.")
    print("-" * 65)

    key_id = input("Enter AWS Access Key ID (e.g. AKIA...): ").strip()
    if not key_id:
        print("[ERROR] AWS Access Key ID cannot be empty.")
        return False

    secret_key = ""
    try:
        import getpass
        secret_key = getpass.getpass("Enter AWS Secret Access Key: ").strip()
    except Exception:
        secret_key = input("Enter AWS Secret Access Key: ").strip()

    if not secret_key:
        print("[ERROR] AWS Secret Access Key cannot be empty.")
        return False

    region = input("Enter Default AWS Region [us-east-1]: ").strip() or "us-east-1"
    session_token = input("Enter AWS Session Token (optional, press Enter to skip): ").strip()

    # Save to ~/.aws/credentials and ~/.aws/config
    aws_dir = os.path.expanduser("~/.aws")
    os.makedirs(aws_dir, exist_ok=True)
    try:
        os.chmod(aws_dir, 0o700)
    except Exception:
        pass

    cred_file = os.path.join(aws_dir, "credentials")
    config_file = os.path.join(aws_dir, "config")

    import configparser
    cp = configparser.ConfigParser()
    if os.path.exists(cred_file):
        cp.read(cred_file)

    if not cp.has_section(profile_name):
        cp.add_section(profile_name)

    cp.set(profile_name, "aws_access_key_id", key_id)
    cp.set(profile_name, "aws_secret_access_key", secret_key)
    if session_token:
        cp.set(profile_name, "aws_session_token", session_token)
    elif cp.has_option(profile_name, "aws_session_token"):
        cp.remove_option(profile_name, "aws_session_token")

    with open(cred_file, "w", encoding="utf-8") as f:
        cp.write(f)
    try:
        os.chmod(cred_file, 0o600)
    except Exception:
        pass

    cfg = configparser.ConfigParser()
    if os.path.exists(config_file):
        cfg.read(config_file)

    cfg_sec = "default" if profile_name == "default" else f"profile {profile_name}"
    if not cfg.has_section(cfg_sec):
        cfg.add_section(cfg_sec)
    cfg.set(cfg_sec, "region", region)

    with open(config_file, "w", encoding="utf-8") as f:
        cfg.write(f)
    try:
        os.chmod(config_file, 0o600)
    except Exception:
        pass

    print(f"\n[✓] AWS credentials for [{profile_name}] successfully saved in ~/.aws/credentials!")
    return True


def ensure_credentials_exist(requested_profile: Optional[str] = None):
    """
    Guided auth workflow: if no AWS credentials exist,
    prompt the user with the built-in credential configuration wizard.
    """
    has_env = bool(os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"))
    has_file = os.path.exists(CREDENTIALS_PATH) and len(list_profiles()) > 0

    if has_env or has_file:
        return

    print("\n" + "=" * 65)
    print("  🔑  First-Time Setup: AWS Credentials Required")
    print("=" * 65)
    print("CloudGate needs read-only AWS credentials to audit your cloud environment.")
    print("No existing credentials were found in ~/.aws/credentials or environment.")
    print("=" * 65)

    answer = input("Configure AWS credentials now? [Y/n]: ").strip().lower()
    if answer in ("", "y", "yes"):
        prof = requested_profile or "default"
        success = configure_credentials(prof)
        if not success:
            sys.exit(1)
    else:
        print("\n[ABORTED] Run `cloudgate --configure` or `aws configure` to set credentials, then re-run.")
        sys.exit(1)


def list_profiles() -> List[str]:
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


def choose_profile(explicit_profile: Optional[str]) -> Optional[str]:
    if explicit_profile:
        return explicit_profile

    profiles = list_profiles()
    if len(profiles) <= 1:
        return None

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


def write_json_report(findings: list, identity: dict, path: str, extra_meta: Optional[dict] = None):
    report = {
        "generator": f"CloudGate v{VERSION}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account": identity.get("Account"),
        "scanned_as": identity.get("Arn"),
        "finding_count": len(findings),
        "metadata": extra_meta or {},
        "findings": findings,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def run_interactive_menu():
    print("\n" + "=" * 65)
    print("      CloudGate 2.0 — Security Audit Level Selection")
    print("=" * 65)
    print("1. [Level 1: Fast Gate]       Quick pre-logout security scan (~3s)")
    print("2. [Level 2: Core Posture]    Core checks (IAM, S3, EC2, KMS, VPC, Logging)")
    print("3. [Level 3: CIS Benchmark]   CIS AWS Foundations Benchmark v3.0")
    print("4. [Level 4: ThreatScore]     Prowler ThreatScore & Attack-Path Analysis")
    print("5. [Level 5: Full Enterprise] Complete audit across all 89 AWS services")
    print("6. [Hybrid Engine]            Fast Gate + Core Prowler Audit + HTML Report")
    print("7. [Configure Credentials]    Setup or update AWS Access Keys / Profiles")
    print("=" * 65)

    choice = input("Select an option [1-7] (default: 1): ").strip()
    if choice == "2":
        return {"mode": "deep", "level": "2", "html": True}
    elif choice == "3":
        return {"mode": "deep", "compliance": "cis_3.0_aws", "html": True}
    elif choice == "4":
        return {"mode": "deep", "compliance": "prowler_threatscore_aws", "html": True}
    elif choice == "5":
        return {"mode": "deep", "all_prowler": True, "html": True}
    elif choice == "6":
        return {"mode": "hybrid", "html": True}
    elif choice == "7":
        prof = input("Enter profile name to configure [default]: ").strip() or "default"
        configure_credentials(prof)
        print("\nNow select a scan mode:")
        return run_interactive_menu()
    return {"mode": "fast", "level": "1"}



def main():
    parser = argparse.ArgumentParser(
        description="CloudGate 2.0 — Real-Time AWS Security Gatekeeper & Compliance Engine."
    )
    # Execution Modes & Levels
    parser.add_argument(
        "--mode",
        choices=["fast", "deep", "hybrid"],
        default="fast",
        help="Scanning mode: 'fast' (native 3s gate), 'deep' (Prowler audit), or 'hybrid' (both)",
    )
    parser.add_argument(
        "--level",
        choices=["1", "2", "3", "4", "5", "fast", "core", "cis", "threat", "full"],
        default=None,
        help="Security testing level (1: Fast, 2: Core, 3: CIS 3.0, 4: ThreatScore, 5: Full Enterprise)",
    )
    parser.add_argument(
        "--prowler",
        "--deep",
        dest="prowler",
        action="store_true",
        help="Shortcut to run Prowler Next-Stage deep audit",
    )
    parser.add_argument(
        "--all-prowler",
        "--all-services",
        dest="all_prowler",
        action="store_true",
        help="Run comprehensive Prowler audit across all 89 AWS services",
    )
    parser.add_argument(
        "--hybrid",
        action="store_true",
        help="Run both Fast Gate and Prowler deep compliance scan",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Launch interactive terminal menu to configure scan level",
    )

    # AWS & Scope Controls
    parser.add_argument("--profile", default=None, help="AWS CLI profile to use")
    parser.add_argument(
        "-r",
        "--region",
        default=None,
        help="Target AWS region (e.g. us-east-1, ap-south-1). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--compliance",
        default=None,
        help="Prowler compliance framework (e.g. cis_3.0_aws, aws_foundational_security_best_practices_aws)",
    )
    parser.add_argument(
        "-s",
        "--services",
        nargs="+",
        default=None,
        help="Specific AWS services to audit in Prowler (e.g. iam s3 ec2 kms vpc cloudtrail)",
    )
    parser.add_argument(
        "--severity",
        nargs="+",
        default=None,
        choices=["critical", "high", "medium", "low"],
        help="Filter Prowler findings by severity",
    )

    # Output & Remediation Controls
    parser.add_argument("--html", action="store_true", help="Force interactive Prowler HTML dashboard report generation")
    parser.add_argument("--output", default=None, help="Write normalized findings to a JSON file")
    parser.add_argument(
        "--no-fix",
        action="store_true",
        help="Suppress actionable AWS CLI remediation guidance table",
    )

    # Legacy / Granular module flags
    parser.add_argument("--iam", action="store_true", help="Run native IAM check")
    parser.add_argument("--s3", action="store_true", help="Run native S3 check")
    parser.add_argument("--ports", action="store_true", help="Run native open-ports check")
    parser.add_argument("--ec2", action="store_true", help="Run native EC2/IMDS check")
    parser.add_argument("--logging", action="store_true", help="Run native CloudTrail/GuardDuty check")
    parser.add_argument("--mfa", action="store_true", help="Run native root/MFA hygiene check")
    parser.add_argument("--kms", action="store_true", help="Run native KMS rotation check")
    parser.add_argument("--vpc", action="store_true", help="Run native VPC Flow Logs check")
    parser.add_argument("--all", action="store_true", help="Run all native checks")
    parser.add_argument(
        "--configure",
        "--setup",
        dest="configure",
        action="store_true",
        help="Interactively configure or update AWS credentials and profiles in ~/.aws/credentials",
    )

    args = parser.parse_args()


    # Direct credentials configuration flow
    if args.configure:
        prof = args.profile or "default"
        configure_credentials(prof)
        sys.exit(0)

    # Interactive flow if requested
    if args.interactive:

        selected = run_interactive_menu()
        if selected.get("mode"):
            args.mode = selected["mode"]
        if selected.get("level"):
            args.level = selected["level"]
        if selected.get("compliance"):
            args.compliance = selected["compliance"]
        if selected.get("all_prowler"):
            args.all_prowler = True
        if selected.get("html"):
            args.html = True

    # Normalize level argument
    level_map = {"fast": "1", "core": "2", "cis": "3", "threat": "4", "full": "5"}
    if args.level and args.level in level_map:
        args.level = level_map[args.level]

    if args.level in ("2", "3", "4", "5") or args.all_prowler or args.compliance or args.prowler:
        if args.mode != "hybrid":
            args.mode = "deep"

    if args.hybrid:
        args.mode = "hybrid"

    ensure_credentials_exist(args.profile)
    profile = choose_profile(args.profile)
    session, identity = get_session(profile)

    active_region = args.region or session.region_name or prowler_engine.get_default_region(session)

    mode_label = (
        "Fast Pre-Logout Gate"
        if args.mode == "fast"
        else ("Prowler Next-Stage Deep Audit" if args.mode == "deep" else "Hybrid (Gate + Prowler)")
    )
    ui.print_banner(version=VERSION, mode_label=mode_label)

    findings = []
    html_report_path = None
    extra_meta = {"mode": args.mode, "region": active_region}

    # 1. RUN FAST GATE CHECKS (if mode is 'fast' or 'hybrid')
    if args.mode in ("fast", "hybrid"):
        any_specific = any([
            getattr(args, "iam", False),
            getattr(args, "s3", False),
            getattr(args, "ports", False),
            getattr(args, "ec2", False),
            getattr(args, "logging", False),
            getattr(args, "mfa", False),
            getattr(args, "kms", False),
            getattr(args, "vpc", False),
        ])
        run_all_native = getattr(args, "all", False) or not any_specific


        print("[*] Executing Native Fast Gate checks...")
        if run_all_native or args.iam:
            iam_check.run(session, findings)
        if run_all_native or args.s3:
            s3_check.run(session, findings)
        if run_all_native or args.ports:
            ports_check.run(session, findings)
        if run_all_native or args.ec2:
            ec2_check.run(session, findings)
        if run_all_native or args.logging:
            logging_check.run(session, findings)
        if run_all_native or args.mfa:
            mfa_check.run(session, findings)
        if run_all_native or args.kms:
            kms_check.run(session, findings)
        if run_all_native or args.vpc:
            vpc_check.run(session, findings)

    # 2. RUN PROWLER NEXT-STAGE ENGINE (if mode is 'deep' or 'hybrid')
    if args.mode in ("deep", "hybrid"):
        if not prowler_engine.is_prowler_available():
            print("[WARN] Prowler tool not detected in PATH. Skipping deep compliance stage.")
            print("[TIP]  Install with: pip3 install prowler --break-system-packages")
        else:
            # HTML generation is active for all deep and hybrid scans
            generate_html = True
            prowler_findings, p_meta = prowler_engine.run_prowler_scan(
                profile=profile,
                region=active_region,
                services=args.services,
                compliance=args.compliance,
                severity=args.severity,
                level=args.level,
                all_services=args.all_prowler or (args.level == "5"),
                generate_html=generate_html,
                output_dir="reports",
            )
            html_report_path = p_meta.get("html_report")
            extra_meta.update(p_meta)
            findings.extend(prowler_findings)

    # 3. RENDER RESULTS & VERDICT
    reporter.print_report(
        findings=findings,
        identity=identity,
        region=active_region,
        profile=profile,
        mode=mode_label,
        html_report_path=html_report_path,
        show_remediations=not args.no_fix,
    )

    # 4. EXPORT JSON REPORT IF SPECIFIED
    if args.output:
        write_json_report(findings, identity, args.output, extra_meta=extra_meta)
        print(f"\n[💾] Full JSON report saved to: {args.output}")


if __name__ == "__main__":
    main()
