# CloudGate 2.0

A real, dynamic, read-only AWS security auditing and gatekeeping tool. Connects to your AWS account with your credentials and scans its live configuration — IAM, S3, EC2/IMDS, security groups, CloudTrail, GuardDuty, KMS, VPC, root/MFA hygiene, and industry compliance standards — then reports risks in a rich, color-coded terminal UI.

CloudGate 2.0 integrates **Prowler** as its next-stage engine, enabling deep compliance audits (CIS AWS Foundations Benchmark, NIST, ISO 27001, AWS Well-Architected Framework) alongside instant pre-logout security gates.

---

## Architecture: Dual-Engine Scanning

```
               ┌────────────────────────────────────────────────────────┐
               │                     CloudGate 2.0                      │
               │        (Interactive CLI & Pre-Logout Gatekeeper)       │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
     ┌────────────────────────┐                     ┌────────────────────────┐
     │   Fast Gate (Native)   │                     │  Next-Stage (Prowler)  │
     │      ~3s scan time     │                     │   Enterprise audits    │
     ├────────────────────────┤                     ├────────────────────────┤
     │ • Root access keys     │                     │ • CIS AWS Benchmark    │
     │ • Open ports (0.0.0.0) │                     │ • NIST / ISO27001 / PCI│
     │ • Public S3 buckets    │                     │ • 300+ Security checks │
     │ • IMDSv2 enforcement   │                     │ • Interactive HTML rep.│
     │ • Missing CloudTrail   │                     │ • 89 AWS services      │
     │ • KMS & VPC Flow Logs  │                     │ • ThreatScore analysis │
     └────────────────────────┘                     └────────────────────────┘
```

---

## Security Testing Levels

| Level | Name | Scan Scope | Speed |
|---|---|---|---|
| **Level 1** | **Fast Gate** | Instant pre-logout checks (IAM root keys, S3 public, open ports 0.0.0.0, IMDSv2, CloudTrail, MFA) | ~3s |
| **Level 2** | **Core Posture** | Fast Gate + KMS rotation, VPC Flow Logs, and Prowler Core (IAM, S3, EC2, CloudTrail, GuardDuty, KMS, VPC) | ~30s |
| **Level 3** | **CIS Benchmark** | Full CIS AWS Foundations Benchmark v3.0 standard compliance audit | ~60s |
| **Level 4** | **ThreatScore** | Prowler ThreatScore & Attack Path Analysis (ransomware & privilege escalation risks) | ~60s |
| **Level 5** | **Full Enterprise** | Complete audit across all 89 available AWS services with Prowler | ~2-3m |

---

## Installation & Setup

```bash
# Clone repository and enter directory
git clone https://github.com/cloudgate-sec/cloudgate.git
cd cloudgate

# Run 1-click installer (installs dependencies & sets up `cloudgate` CLI)
chmod +x install.sh && ./install.sh

# Or install manually via pip
pip3 install -r requirements.txt --break-system-packages

# Configure read-only AWS credentials (guided wizard on first launch):
cloudgate --configure

# Or configure a specific named profile:
cloudgate --configure --profile production
```


---

## How to Run

### 1. Instant Fast Pre-Logout Gate (~3 seconds)
Runs the lightweight native gate to check for critical misconfigurations before logging out:
```bash
python3 cloudgate.py
```

### 2. Run by Security Testing Level
```bash
# Level 2: Core Posture Scan
python3 cloudgate.py --level 2

# Level 3: CIS AWS Foundations Benchmark 3.0
python3 cloudgate.py --level 3

# Level 4: ThreatScore & Attack Path Analysis
python3 cloudgate.py --level 4

# Level 5: Full Enterprise (All 89 AWS Services)
python3 cloudgate.py --all-prowler
```

### 3. Industry Compliance Frameworks
Audit directly against recognized security standards:
```bash
# CIS AWS Foundations Benchmark 3.0
python3 cloudgate.py --compliance cis_3.0_aws

# AWS Foundational Security Best Practices
python3 cloudgate.py --compliance aws_foundational_security_best_practices_aws

# Prowler ThreatScore
python3 cloudgate.py --compliance prowler_threatscore_aws

# NIST 800-53 Revision 5
python3 cloudgate.py --compliance nist_800_53_revision_5_aws

# PCI-DSS 4.0
python3 cloudgate.py --compliance pci_4.0_aws
```

### 4. Hybrid Scan (Fast Gate + Prowler Deep Audit)
Runs the fast gate first for immediate blockers, followed by deep Prowler compliance checks and HTML report generation:
```bash
python3 cloudgate.py --hybrid
```

### 5. Interactive Guided Mode
Interactive menu allowing you to choose scan levels with a single keypress:
```bash
python3 cloudgate.py -i
```

### 6. Export Reports
```bash
# Export normalized findings to JSON
python3 cloudgate.py --output report.json

# Interactive HTML dashboard reports are saved automatically to:
# ./reports/prowler_scan_<timestamp>.html
# Open in browser:
xdg-open reports/*.html
```

---

## CLI Options & Flags

| Flag | Description |
|---|---|
| `--mode {fast,deep,hybrid}` | Choose scan engine mode (default: `fast`) |
| `--level {1,2,3,4,5}` | Security testing level (1: Fast, 2: Core, 3: CIS, 4: ThreatScore, 5: Full) |
| `--prowler`, `--deep` | Run deep compliance checks via Prowler |
| `--all-prowler` | Run comprehensive audit across all 89 AWS services |
| `--hybrid` | Run both Fast Gate and Prowler deep audit |
| `-i`, `--interactive` | Launch interactive terminal selection menu |
| `-r`, `--region <reg>` | Target specific AWS region (defaults to active configured region) |
| `--compliance <name>` | Audit against compliance framework (`cis_3.0_aws`, etc.) |
| `-s`, `--services <list>` | Limit Prowler scan to specific services (`iam`, `s3`, `ec2`, `kms`, `vpc`) |
| `--severity <list>` | Filter findings by severity (`critical`, `high`, `medium`, `low`) |
| `--html` | Force interactive HTML dashboard report generation |
| `--output <file.json>` | Write normalized findings to JSON file |
| `--no-fix` | Suppress the actionable AWS CLI remediation table |
| `--profile <name>` | Select specific AWS CLI profile from `~/.aws/credentials` |

---

## Scope & Safety

- **Read-Only**: Every scan is strictly read-only AWS API calls (`list_*`, `describe_*`, `get_*`).
- **No Writes**: CloudGate never modifies or writes to your AWS account.
- **No Packet Sending**: Network security group checks inspect API security group rules only — zero network packets are sent to any host.
- **Live Ground Truth**: All findings reflect the real-time configuration of your connected AWS account.
- **Recommended Permission**: AWS Managed Policy `SecurityAudit` or `ViewOnlyAccess`. Do **not** use `AdministratorAccess` for auditing.
