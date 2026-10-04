"""
utils/aws_client.py
Creates a boto3 session for the chosen AWS profile and verifies the
credentials work by calling STS get_caller_identity.
"""
import sys

import boto3
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
    PartialCredentialsError,
)


def mask_account(acc: str | None) -> str:
    if acc and len(acc) == 12 and acc.isdigit():
        return f"{acc[:4]}****{acc[-4:]}"
    return acc or "Unknown"


def mask_arn(arn_str: str | None) -> str:
    if not arn_str:
        return "Unknown"
    parts = arn_str.split(":")
    if len(parts) >= 5 and len(parts[4]) == 12 and parts[4].isdigit():
        parts[4] = f"{parts[4][:4]}****{parts[4][-4:]}"
        return ":".join(parts)
    return arn_str


def get_session(profile: str | None = None):
    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    except ProfileNotFound:
        print(f"[ERROR] AWS profile '{profile}' not found in ~/.aws/credentials or ~/.aws/config")
        sys.exit(1)

    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
    except (NoCredentialsError, PartialCredentialsError):
        print("[ERROR] No valid AWS credentials found. Run `aws configure` and try again.")
        sys.exit(1)
    except ClientError as e:
        print(f"[ERROR] AWS rejected these credentials: {e}")
        sys.exit(1)

    print(f"[*] Authenticated as: {mask_arn(identity.get('Arn'))}")
    print(f"[*] Account: {mask_account(identity.get('Account'))}")

    return session, identity

