"""
core/reporter.py

Formats and visualizes findings into the CloudGate security gate report,
deduplicates findings across Native and Prowler engines,
displays actionable remediation steps, and prints the final gatekeeper verdict.
"""

import os
from typing import List, Dict, Any, Optional
from core import ui

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

REMEDIATION_KNOWLEDGE_BASE = {
    "root account has active cli access keys": (
        "aws iam delete-access-key --user-name <ROOT_KEY_ID> (Delete via AWS Console -> Security Credentials)"
    ),
    "root account has one active access key": (
        "aws iam delete-access-key --user-name <ROOT_KEY_ID> (Delete via AWS Console -> Security Credentials)"
    ),
    "mfa is not enabled on the root account": (
        "AWS Console -> Root Account -> Security credentials -> Assign MFA device (Enable FIDO2 / Authenticator)"
    ),
    "has console password access but no mfa enabled": (
        "aws iam enable-mfa-device --user-name <USER_NAME> --serial-number ... (Enforce MFA policy for console users)"
    ),
    "console password enabled but mfa disabled": (
        "aws iam enable-mfa-device --user-name <USER_NAME> --serial-number ... (Enable MFA device or delete console password)"
    ),
    "no cloudtrail trail configured": (
        "aws cloudtrail create-trail --name security-audit-trail --s3-bucket-name <BUCKET> && "
        "aws cloudtrail start-logging --name security-audit-trail"
    ),
    "no cloudtrail trails enabled with logging": (
        "aws cloudtrail create-trail --name security-audit-trail --s3-bucket-name <BUCKET> && "
        "aws cloudtrail start-logging --name security-audit-trail"
    ),
    "guardduty": (
        "aws guardduty create-detector --enable"
    ),
    "public access block not fully enabled": (
        "aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    ),
    "default encryption not enabled": (
        "aws s3api put-bucket-encryption --bucket {bucket} --server-side-encryption-configuration "
        "'{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'"
    ),
    "does not enforce imdsv2": (
        "aws ec2 modify-instance-metadata-options --instance-id {instance} --http-tokens required --http-endpoint enabled"
    ),
    "allows all ports/protocols from 0.0.0.0/0": (
        "aws ec2 revoke-security-group-ingress --group-id {sg} --protocol -1 --cidr 0.0.0.0/0"
    ),
    "exposes ssh (port 22)": (
        "aws ec2 revoke-security-group-ingress --group-id {sg} --protocol tcp --port 22 --cidr 0.0.0.0/0"
    ),
    "exposes rdp (port 3389)": (
        "aws ec2 revoke-security-group-ingress --group-id {sg} --protocol tcp --port 3389 --cidr 0.0.0.0/0"
    ),
}


def get_finding_fingerprint(f: Dict[str, Any]) -> str:
    """Generate a semantic fingerprint to merge overlapping Native and Prowler checks."""
    issue = f.get("issue", "").lower()
    res = f.get("resource", "").lower()
    cat = f.get("category", "").lower()

    if "root" in issue and ("key" in issue or "access" in issue):
        return "iam:root_access_key"
    if "root" in issue and "mfa" in issue:
        return "iam:root_mfa"

    # Match user MFA and console policies generically without hardcoded usernames
    if "console password" in issue or "console access" in issue or "mfa" in issue:
        u_target = res if (res and res != "-") else "target_user"
        if "console" in issue and "mfa" in issue:
            return f"iam:user_console_mfa:{u_target}"
        if "any type of mfa" in issue or "without mfa" in issue:
            return f"iam:user_any_mfa:{u_target}"
        if "45 days" in issue or "unused" in issue:
            return f"iam:user_unused_console:{u_target}"
        if "never used access key" in issue:
            return f"iam:user_unused_key:{u_target}"

    if "cloudtrail" in cat or "cloudtrail" in issue:
        if "no cloudtrail trail" in issue or "no cloudtrail trails enabled" in issue:
            return "cloudtrail:none_enabled"
        if "multi-region" in issue or "multi_region" in issue:
            return "cloudtrail:no_multiregion"
        if "bedrock" in issue:
            return "cloudtrail:bedrock_api"
    if "guardduty" in cat or "guardduty" in issue:
        return "logging:guardduty"
    if "password policy" in issue:
        for p_term in ("length", "uppercase", "lowercase", "number", "symbol", "reuse", "expires"):
            if p_term in issue:
                return f"iam:password_policy:{p_term}"

    return f"{cat}:{res}:{issue[:40]}"


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merges duplicate findings across Native and Prowler engines."""
    seen: Dict[str, Dict[str, Any]] = {}
    deduped = []

    for f in findings:
        fp = get_finding_fingerprint(f)
        if fp not in seen:
            seen[fp] = f
            deduped.append(f)
        else:
            existing = seen[fp]
            # Merge compliance tags
            existing_tags = set(existing.get("compliance_tags", []))
            new_tags = set(f.get("compliance_tags", []))
            combined_tags = list(existing_tags.union(new_tags))
            existing["compliance_tags"] = combined_tags

            # Prefer Prowler finding with richer details or references
            if f.get("source") == "Prowler" and existing.get("source") != "Prowler":
                if f.get("resource") and f.get("resource") != "-":
                    existing["resource"] = f["resource"]
                if f.get("remediation") and len(f["remediation"]) > len(existing.get("remediation", "")):
                    existing["remediation"] = f["remediation"]

    return deduped


def enrich_remediations(findings: List[Dict[str, Any]]):
    """Enriches findings with actionable remediation commands if missing."""
    for f in findings:
        if f.get("remediation"):
            continue
        issue_lower = f.get("issue", "").lower()
        for key, rem_cmd in REMEDIATION_KNOWLEDGE_BASE.items():
            if key in issue_lower:
                f["remediation"] = rem_cmd
                break
        if not f.get("remediation"):
            f["remediation"] = "Inspect AWS configuration in console or IAM policy and restrict to least privilege."


def print_report(
    findings: List[Dict[str, Any]],
    identity: Optional[dict] = None,
    region: Optional[str] = None,
    profile: Optional[str] = None,
    mode: str = "Fast Gate",
    html_report_path: Optional[str] = None,
    show_remediations: bool = True,
):
    """Renders comprehensive CloudGate security gate report."""
    findings = deduplicate_findings(findings)
    enrich_remediations(findings)

    # Sort findings by severity
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99))

    # Print Session Context Card if available
    if identity:
        ui.print_session_card(identity, region or "us-east-1", profile, mode)

    # Print Findings Table
    if findings:
        ui.render_findings_table(findings, show_remediations=show_remediations)
        if show_remediations:
            ui.render_remediation_guide(findings)
    else:
        print("\n[OK] Zero misconfigurations detected! All security checks passed.")

    # Render Final Verdict Banner
    ui.render_verdict_banner(findings)

    # If Prowler generated an HTML report, highlight it with clickable markdown
    if html_report_path and os.path.exists(html_report_path):
        abs_path = os.path.abspath(html_report_path)
        print(f"\n📊 Interactive Prowler HTML Dashboard: file://{abs_path}")
        print(f"👉 Open with: xdg-open \"{abs_path}\"\n")
