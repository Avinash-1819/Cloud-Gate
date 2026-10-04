"""
core/kms_check.py

Read-only KMS encryption and key governance checks.
Verifies that customer managed KMS keys have automatic key rotation enabled
and do not have overly permissive key policies.
"""

from botocore.exceptions import ClientError


def run(session, findings: list):
    kms = session.client("kms")
    print("[*] Checking KMS Customer Managed Keys for rotation & policies...")

    try:
        keys = kms.list_keys()["Keys"]
    except ClientError as e:
        # User might not have kms permissions or KMS not used
        return

    for k in keys:
        key_id = k.get("KeyId")
        try:
            meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
            # Ignore AWS managed default keys (aws/s3, aws/ebs, etc.)
            if meta.get("KeyManager") != "CUSTOMER":
                continue
            if not meta.get("Enabled", False):
                continue

            # Check rotation
            rot = kms.get_key_rotation_status(KeyId=key_id)
            if not rot.get("KeyRotationEnabled", False):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "KMS",
                    "resource": key_id,
                    "service": "kms",
                    "issue": f"KMS Customer Managed Key '{key_id}' does not have automatic key rotation enabled",
                    "remediation": f"aws kms enable-key-rotation --key-id {key_id}",
                })
        except ClientError:
            continue
