"""
core/s3_check.py

Read-only S3 bucket checks for CloudGate's pre-logout gate.
"""

from botocore.exceptions import ClientError


def run(session, findings: list):
    s3 = session.client("s3")
    print("[*] Checking S3 buckets for public access / encryption...")

    try:
        buckets = s3.list_buckets()["Buckets"]
    except ClientError as e:
        print(f"[WARN] Could not list S3 buckets: {e}")
        return

    for b in buckets:
        name = b["Name"]
        _check_public_access(s3, name, findings)
        _check_encryption(s3, name, findings)


def _check_public_access(s3, bucket_name, findings):
    try:
        cfg = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        if not all(cfg.values()):
            findings.append({
                "severity": "HIGH",
                "category": "S3",
                "issue": f"Bucket '{bucket_name}' — Public Access Block not fully enabled",
            })
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            findings.append({
                "severity": "HIGH",
                "category": "S3",
                "issue": f"Bucket '{bucket_name}' — no Public Access Block configured",
            })


def _check_encryption(s3, bucket_name, findings):
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append({
                "severity": "MEDIUM",
                "category": "S3",
                "issue": f"Bucket '{bucket_name}' — default encryption not enabled",
            })
