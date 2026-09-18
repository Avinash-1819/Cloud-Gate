"""
core/reporter.py

Formats findings into the CloudGate "pre-logout gate" report and
prints a final SAFE / DO NOT LOG OUT verdict.
"""

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def print_report(findings: list):
    print("\n" + "=" * 60)
    print("        CloudGate — Pre-Logout Security Check")
    print("=" * 60)

    if not findings:
        print("\n[OK] No issues detected.")
        _print_verdict(findings)
        return

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = " | ".join(
        f"{k}: {v}" for k, v in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))
    )
    print(f"\nSUMMARY: {len(findings)} finding(s)  ({summary})\n")

    for f in findings:
        print(f"[{f['severity']}] ({f['category']}) {f['issue']}")

    _print_verdict(findings)


def _print_verdict(findings: list):
    critical_or_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]

    print("\n" + "=" * 60)
    if critical_or_high:
        print("  ⚠️  DO NOT LOG OUT — fix the findings above first")
        print(f"     ({len(critical_or_high)} critical/high issue(s) found)")
    else:
        print("  ✅  SAFE TO LOG OUT")
    print("=" * 60 + "\n")
