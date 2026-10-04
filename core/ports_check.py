"""
core/ports_check.py

Read-only security group check — the "pre-logout gate" core feature.
Flags security groups that expose risky ports (SSH, RDP, or all ports)
to the entire internet (0.0.0.0/0).

This never sends a single packet to anything — it only reads the
security group *rules* via the EC2 API.
"""

from botocore.exceptions import ClientError

RISKY_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

OPEN_CIDR = "0.0.0.0/0"


def run(session, findings: list):
    ec2 = session.client("ec2")
    print("[*] Checking security groups for open ports to the internet...")

    try:
        groups = ec2.describe_security_groups()["SecurityGroups"]
    except ClientError as e:
        print(f"[WARN] Could not describe security groups: {e}")
        return

    for sg in groups:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)

        for rule in sg.get("IpPermissions", []):
            if not _is_open_to_internet(rule):
                continue

            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            if from_port is None and to_port is None:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "NETWORK",
                    "issue": f"Security group '{sg_name}' ({sg_id}) allows ALL "
                             f"ports/protocols from {OPEN_CIDR} — fully exposed",
                })
                continue

            for port, service in RISKY_PORTS.items():
                if from_port <= port <= to_port:
                    findings.append({
                        "severity": "CRITICAL" if port in (22, 3389) else "HIGH",
                        "category": "NETWORK",
                        "issue": f"Security group '{sg_name}' ({sg_id}) exposes "
                                 f"{service} (port {port}) to {OPEN_CIDR} — "
                                 f"reachable from anywhere on the internet",
                    })


def _is_open_to_internet(rule: dict) -> bool:
    for ip_range in rule.get("IpRanges", []):
        if ip_range.get("CidrIp") == OPEN_CIDR:
            return True
    return False
