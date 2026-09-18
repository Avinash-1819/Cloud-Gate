"""
core/ec2_check.py

Read-only EC2 configuration checks. Flags the exact root-cause pattern
behind the 2019 Capital One breach: an internet-facing instance with an
attached IAM role, where IMDSv2 is not enforced.

Dynamic — reads whatever EC2 instances actually exist in the connected
AWS account. No hardcoded/sample data.
"""

from botocore.exceptions import ClientError


def run(session, findings: list):
    ec2 = session.client("ec2")
    print("[*] Checking EC2 instances for public exposure and IMDS configuration...")

    try:
        reservations = ec2.describe_instances()["Reservations"]
    except ClientError as e:
        print(f"[WARN] Could not describe EC2 instances: {e}")
        return

    instances = [i for r in reservations for i in r["Instances"]]

    for inst in instances:
        instance_id = inst["InstanceId"]
        state = inst.get("State", {}).get("Name")
        if state == "terminated":
            continue

        public_ip = inst.get("PublicIpAddress")
        iam_profile = inst.get("IamInstanceProfile")
        metadata_opts = inst.get("MetadataOptions", {})
        http_tokens = metadata_opts.get("HttpTokens")

        if public_ip and iam_profile:
            findings.append({
                "severity": "HIGH",
                "category": "EC2",
                "issue": f"Instance {instance_id} has public IP {public_ip} AND an "
                         f"attached IAM instance profile ({iam_profile.get('Arn', 'unknown')}) "
                         f"— this is the exact pattern exploited via SSRF in the "
                         f"2019 Capital One breach",
            })

        if iam_profile and http_tokens != "required":
            findings.append({
                "severity": "CRITICAL" if public_ip else "MEDIUM",
                "category": "EC2",
                "issue": f"Instance {instance_id} does not enforce IMDSv2 "
                         f"(HttpTokens='{http_tokens}') — metadata service can be "
                         f"queried without a session token, enabling simple SSRF "
                         f"credential theft",
            })
