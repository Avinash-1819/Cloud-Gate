"""
core/prowler_engine.py

Prowler Next-Stage Integration Engine for CloudGate.
Orchestrates deep compliance audits, CIS AWS benchmarks, multi-level posture
assessments, and full enterprise scans using Prowler.
"""

import os
import sys
import json
import shutil
import subprocess
import glob
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional

CANDIDATE_PATHS = [
    shutil.which("prowler"),
    os.path.expanduser("~/.local/bin/prowler"),
    "/usr/local/bin/prowler",
    "/usr/bin/prowler",
]

# Security Testing Levels
LEVEL_PRESETS = {
    "1": {"name": "Fast Gate", "desc": "Pre-logout instant checks (~3s)"},
    "2": {"name": "Core Posture", "services": ["iam", "s3", "ec2", "cloudtrail", "guardduty", "kms", "vpc"], "desc": "Core infrastructure security"},
    "3": {"name": "CIS Benchmark", "compliance": "cis_3.0_aws", "desc": "CIS AWS Foundations Benchmark v3.0"},
    "4": {"name": "High ThreatScore", "compliance": "prowler_threatscore_aws", "desc": "Threat modeling & attack-path posture"},
    "5": {"name": "Full Enterprise", "all_services": True, "desc": "Complete audit across all available AWS services"},
}


def find_prowler() -> Optional[str]:
    for path in CANDIDATE_PATHS:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def is_prowler_available() -> bool:
    return find_prowler() is not None


def get_default_region(session=None) -> str:
    if session and session.region_name:
        return session.region_name
    env_region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")
    if env_region:
        return env_region
    return "us-east-1"


def run_prowler_scan(
    profile: Optional[str] = None,
    region: Optional[str] = None,
    services: Optional[List[str]] = None,
    checks: Optional[List[str]] = None,
    compliance: Optional[str] = None,
    severity: Optional[List[str]] = None,
    level: Optional[str] = None,
    all_services: bool = False,
    generate_html: bool = True,
    output_dir: str = "reports",
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Executes Prowler with specified parameters and returns normalized findings.
    """
    prowler_bin = find_prowler()
    if not prowler_bin:
        print("[ERROR] Prowler is not installed or not in PATH.")
        print("To install Prowler: pip3 install prowler --break-system-packages")
        return [], {"error": "Prowler not installed"}

    target_region = region or get_default_region()
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    file_prefix = f"prowler_scan_{timestamp}"

    # Build Prowler CLI command
    cmd = [prowler_bin, "aws"]

    if profile:
        cmd.extend(["--profile", profile])

    cmd.extend(["-f", target_region])

    # Apply Level preset if specified
    active_compliance = compliance
    active_services = services
    scan_all = all_services

    if level and str(level) in LEVEL_PRESETS:
        preset = LEVEL_PRESETS[str(level)]
        if "compliance" in preset and not active_compliance:
            active_compliance = preset["compliance"]
        if "services" in preset and not active_services and not active_compliance:
            active_services = preset["services"]
        if preset.get("all_services"):
            scan_all = True

    # Scan selector: compliance vs specific services vs checks vs all
    if active_compliance:
        cmd.extend(["--compliance", active_compliance])
        label = f"Compliance Framework ({active_compliance})"
    elif checks:
        cmd.append("-c")
        cmd.extend(checks)
        label = f"Checks ({', '.join(checks[:3])}...)"
    elif active_services:
        cmd.append("-s")
        cmd.extend(active_services)
        label = f"Services ({', '.join(active_services)})"
    elif scan_all:
        # Full scan: do not pass -s or -c, prowler scans all services in account
        label = "Full Enterprise (All Services)"
    else:
        # Default high-value core services
        cmd.extend(["-s", "iam", "s3", "ec2", "cloudtrail", "guardduty", "kms", "vpc"])
        label = "Core Posture (IAM, S3, EC2, CloudTrail, GuardDuty, KMS, VPC)"

    # Severity filtering
    if severity:
        cmd.append("--severity")
        cmd.extend(severity)

    # Focus on actionable security defects
    cmd.extend(["--status", "FAIL"])

    # Output modes
    modes = ["json-ocsf"]
    if generate_html:
        modes.append("html")
    cmd.append("-M")
    cmd.extend(modes)

    cmd.extend(["-o", output_dir])
    cmd.extend(["-F", file_prefix])
    cmd.append("--no-banner")

    print(f"\n[*] Launching Prowler Security Audit — {label}")
    print(f"[*] Target Region: {target_region} | Reports Directory: {output_dir}")
    print(f"[*] Command: {' '.join(cmd[:6])} ... [flags]")

    try:
        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except Exception as e:
        print(f"[ERROR] Failed to execute Prowler: {e}")
        return [], {"error": str(e)}

    # Locate generated output files
    ocsf_files = glob.glob(os.path.join(output_dir, f"{file_prefix}*.ocsf.json"))
    html_files = glob.glob(os.path.join(output_dir, f"{file_prefix}*.html"))

    html_report_path = os.path.abspath(html_files[0]) if html_files else None
    ocsf_report_path = os.path.abspath(ocsf_files[0]) if ocsf_files else None

    findings = []
    if ocsf_report_path and os.path.exists(ocsf_report_path):
        findings = parse_ocsf_findings(ocsf_report_path)

    metadata = {
        "timestamp": timestamp,
        "region": target_region,
        "scan_level": label,
        "html_report": html_report_path,
        "ocsf_report": ocsf_report_path,
        "raw_stdout_sample": process.stdout[-500:] if process.stdout else "",
        "finding_count": len(findings),
    }

    return findings, metadata


def parse_ocsf_findings(ocsf_path: str) -> List[Dict[str, Any]]:
    """
    Parses Prowler OCSF JSON findings into CloudGate's unified finding schema.
    """
    try:
        with open(ocsf_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[WARN] Could not parse Prowler OCSF output: {e}")
        return []

    if isinstance(data, dict):
        data = [data]

    findings = []
    for item in data:
        if item.get("status_code") != "FAIL":
            continue

        raw_sev = (item.get("severity") or "MEDIUM").upper()
        if raw_sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            raw_sev = "MEDIUM"

        finding_info = item.get("finding_info") or {}
        unmapped = item.get("unmapped") or {}
        resources = item.get("resources") or [{}]
        primary_resource = resources[0] if resources else {}
        remediation_info = item.get("remediation") or {}

        # Category / Service
        group = primary_resource.get("group") or {}
        service = group.get("name") or finding_info.get("analytic", {}).get("category", "CLOUD")
        category = service.upper()

        # Resource identifier
        resource_id = (
            primary_resource.get("name")
            or primary_resource.get("uid")
            or primary_resource.get("data", {}).get("metadata", {}).get("user")
            or "Account-Level"
        )
        if resource_id.startswith("arn:aws:"):
            resource_id = resource_id.split("/")[-1] if "/" in resource_id else resource_id.split(":")[-1]

        # Issue description
        issue_text = (
            item.get("status_detail")
            or item.get("message")
            or finding_info.get("desc")
            or finding_info.get("title")
            or "Security compliance check failed"
        )

        # Remediation
        remediation_desc = remediation_info.get("desc", "")
        remediation_urls = remediation_info.get("references") or unmapped.get("additional_urls") or []
        ref_str = f" (Ref: {remediation_urls[0]})" if remediation_urls else ""
        full_remediation = f"{remediation_desc}{ref_str}".strip()

        # Compliance standards (CIS, NIST, etc.)
        compliance_dict = unmapped.get("compliance") or {}
        compliance_tags = []
        for std, controls in compliance_dict.items():
            if controls and isinstance(controls, list):
                compliance_tags.append(f"{std}:{controls[0]}")

        findings.append({
            "severity": raw_sev,
            "category": category,
            "issue": issue_text,
            "resource": resource_id,
            "service": service.lower(),
            "remediation": full_remediation,
            "compliance_tags": compliance_tags,
            "risk_details": item.get("risk_details", ""),
            "source": "Prowler",
        })

    return findings
