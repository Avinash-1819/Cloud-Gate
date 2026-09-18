"""
core/iam_check.py

Read-only IAM policy risk check for CloudGate's pre-logout gate.
Flags wildcard/over-privileged permissions on IAM roles and users.
"""

from botocore.exceptions import ClientError


def run(session, findings: list):
    iam = session.client("iam")
    print("[*] Checking IAM roles for over-privileged policies...")

    try:
        role_names = [r["RoleName"] for r in iam.list_roles()["Roles"]]
    except ClientError as e:
        print(f"[WARN] Could not list IAM roles: {e}")
        return

    for role_name in role_names:
        try:
            _check_role(iam, role_name, findings)
        except ClientError as e:
            print(f"[WARN] Skipping role '{role_name}': {e}")


def _check_role(iam, role_name, findings):
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    for pol in attached:
        name = pol["PolicyName"]
        if "FullAccess" in name or name == "AdministratorAccess":
            findings.append({
                "severity": "HIGH",
                "category": "IAM",
                "issue": f"Role '{role_name}' has broad managed policy '{name}' attached",
            })

    inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    for pname in inline_names:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            if any(a == "*" for a in actions) and any(r == "*" for r in resources):
                findings.append({
                    "severity": "CRITICAL",
                    "category": "IAM",
                    "issue": f"Role '{role_name}' inline policy '{pname}' grants "
                             f"Action:* on Resource:* (full admin)",
                })
