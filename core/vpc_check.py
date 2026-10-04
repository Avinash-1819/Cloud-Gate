"""
core/vpc_check.py

Read-only VPC network architecture checks.
Verifies VPC Flow Logs are enabled to capture IP traffic and flags
unmonitored network environments.
"""

from botocore.exceptions import ClientError


def run(session, findings: list):
    ec2 = session.client("ec2")
    print("[*] Checking VPC network telemetry & Flow Logs...")

    try:
        vpcs = ec2.describe_vpcs()["Vpcs"]
    except ClientError:
        return

    try:
        flow_logs = ec2.describe_flow_logs()["FlowLogs"]
        monitored_vpc_ids = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"}
    except ClientError:
        monitored_vpc_ids = set()

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        is_default = vpc.get("IsDefault", False)

        if vpc_id not in monitored_vpc_ids:
            findings.append({
                "severity": "MEDIUM",
                "category": "NETWORK",
                "resource": vpc_id,
                "service": "vpc",
                "issue": f"VPC '{vpc_id}' {'(default VPC) ' if is_default else ''}does not have active VPC Flow Logs enabled — network traffic is unmonitored",
                "remediation": f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vpc_id} --traffic-type ALL --log-destination-type cloud-watch-logs ...",
            })
