"""
core/ui.py

Rich terminal UI, banners, colorized tables, and gate verdict rendering
for CloudGate 2.0.
"""

from typing import List, Dict, Any, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.box import ROUNDED, DOUBLE, HEAVY, SIMPLE
    from rich.columns import Columns
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


BANNER_TEXT = r"""
 ██████╗██╗      ██████╗ ██╗   ██╗██████╗  ██████╗  █████╗ ████████╗███████╗
██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
██║     ██║     ██║   ██║██║   ██║██║  ██║██║  ███╗███████║   ██║   █████╗  
██║     ██║     ██║   ██║██║   ██║██║  ██║██║   ██║██╔══██║   ██║   ██╔══╝  
╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝██║  ██║   ██║   ███████╗
 ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝
"""


def print_banner(version: str = "2.0", mode_label: str = "Fast Gate"):
    if not RICH_AVAILABLE:
        print("=" * 65)
        print(f"        CloudGate v{version} — AWS Security & Compliance Gate")
        print(f"        Mode: {mode_label}")
        print("=" * 65)
        return

    banner = Text(BANNER_TEXT, style="bold cyan")
    subtitle = Text(f"Next-Gen AWS Security & Compliance Gatekeeper • v{version}\nEngine Mode: {mode_label}", style="bold bright_white justify=center")
    console.print(Panel(
        Text.assemble(banner, "\n", subtitle),
        box=ROUNDED,
        border_style="bright_cyan",
        padding=(0, 2),
        expand=False
    ))


def mask_account(acc: str) -> str:
    if acc and len(acc) == 12 and acc.isdigit():
        return f"{acc[:4]}****{acc[-4:]}"
    return acc


def mask_arn(arn_str: str) -> str:
    if not arn_str:
        return "Unknown"
    # Mask 12 digit account id in ARN
    parts = arn_str.split(":")
    if len(parts) >= 5 and len(parts[4]) == 12 and parts[4].isdigit():
        parts[4] = f"{parts[4][:4]}****{parts[4][-4:]}"
        return ":".join(parts)
    return arn_str


def print_session_card(identity: dict, region: str, profile: Optional[str], mode: str):
    raw_account = identity.get("Account", "Unknown")
    raw_arn = identity.get("Arn", "Unknown")
    account = mask_account(raw_account)
    arn = mask_arn(raw_arn)
    prof = profile or "default"

    if not RICH_AVAILABLE:
        print(f"[*] Account: {account} | Profile: {prof} | Region: {region} | Mode: {mode}")
        print(f"[*] Identity: {arn}")
        print("-" * 65)
        return

    table = Table(box=SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("Key", style="bold bright_blue")
    table.add_column("Value", style="bold white")

    table.add_row("🔑 Account ID:", f"[cyan]{account}[/cyan]")
    table.add_row("👤 Identity ARN:", f"[yellow]{arn}[/yellow]")
    table.add_row("🌐 AWS Region:", f"[green]{region}[/green]")
    table.add_row("💼 Profile / Mode:", f"[magenta]{prof}[/magenta] [dim]({mode})[/dim]")

    console.print(Panel(table, title="[bold bright_white]Session Context[/bold bright_white]", border_style="blue", box=ROUNDED))


def get_severity_badge(severity: str) -> str:
    s = severity.upper()
    if s == "CRITICAL":
        return "[bold white on red] CRITICAL [/bold white on red]"
    elif s == "HIGH":
        return "[bold black on bright_yellow]  HIGH   [/bold black on bright_yellow]"
    elif s == "MEDIUM":
        return "[bold black on yellow] MEDIUM  [/bold black on yellow]"
    elif s == "LOW":
        return "[bold white on blue]   LOW   [/bold white on blue]"
    return f"[bold white on grey50]  {s}  [/bold white on grey50]"


def render_findings_table(findings: List[Dict[str, Any]], show_remediations: bool = False):
    if not findings:
        return

    if not RICH_AVAILABLE:
        print("\nFINDINGS:")
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            cat = f.get("category", "GENERAL")
            issue = f.get("issue", "")
            res = f.get("resource", "")
            res_str = f" [{res}]" if res else ""
            print(f" {idx}. [{sev}] ({cat}){res_str} {issue}")
            if show_remediations and f.get("remediation"):
                print(f"    -> FIX: {f.get('remediation')}")
        return

    table = Table(box=ROUNDED, border_style="bright_black", show_lines=True)
    table.add_column("#", style="dim", justify="right", width=3)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Category", style="cyan bold", width=11)
    table.add_column("Resource / Service", style="magenta", width=22)
    table.add_column("Finding & Risk Impact", style="white")

    for idx, f in enumerate(findings, 1):
        sev_badge = get_severity_badge(f.get("severity", "INFO"))
        cat = f.get("category", "GENERAL")
        resource = f.get("resource") or f.get("service") or "-"
        issue_text = f.get("issue", "")
        
        # If compliance tags exist, append them
        if f.get("compliance_tags"):
            tags = ", ".join(f["compliance_tags"][:3])
            issue_text += f"\n[dim italic cyan]Standards: {tags}[/dim italic cyan]"

        table.add_row(str(idx), sev_badge, cat, resource, issue_text)

    console.print(table)


def render_remediation_guide(findings: List[Dict[str, Any]]):
    remediations = [f for f in findings if f.get("remediation")]
    if not remediations:
        return

    if not RICH_AVAILABLE:
        print("\n" + "=" * 65)
        print("ACTIONABLE REMEDIATION GUIDANCE")
        print("=" * 65)
        for idx, f in enumerate(remediations, 1):
            print(f"{idx}. [{f['severity']}] {f['issue']}")
            print(f"   Command / Fix: {f['remediation']}\n")
        return

    table = Table(box=ROUNDED, border_style="green", show_lines=True)
    table.add_column("Risk", style="bold", width=25)
    table.add_column("Recommended Fix / AWS CLI Command", style="bright_green")

    for f in remediations:
        sev_badge = get_severity_badge(f.get("severity", "INFO"))
        short_issue = f.get("issue", "").split("—")[0].strip()
        risk_label = f"{sev_badge}\n[bold white]{f.get('category')}:[/bold white] {short_issue}"
        fix_content = f.get("remediation", "")
        if "\n" in fix_content or "aws " in fix_content:
            fix_content = f"[bold bright_yellow]{fix_content}[/bold bright_yellow]"
        table.add_row(risk_label, fix_content)

    console.print(Panel(table, title="[bold bright_green]🛠️  Actionable Remediation Guidance[/bold bright_green]", border_style="bright_green", box=ROUNDED))


def render_verdict_banner(findings: List[Dict[str, Any]], stats: Optional[Dict[str, Any]] = None):
    critical_or_high = [f for f in findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH")]
    crit_count = sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity", "").upper() == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity", "").upper() == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity", "").upper() == "LOW")

    summary_counts = f"CRITICAL: {crit_count} | HIGH: {high_count} | MEDIUM: {med_count} | LOW: {low_count}"

    if not RICH_AVAILABLE:
        print("\n" + "=" * 65)
        if critical_or_high:
            print("  ⚠️  DO NOT LOG OUT — FIX CRITICAL/HIGH FINDINGS FIRST")
            print(f"     ({len(critical_or_high)} blocker issue(s) detected | {summary_counts})")
        else:
            print("  ✅  SAFE TO LOG OUT — ALL SECURITY GATES PASSED")
            print(f"     (0 critical/high issues | {summary_counts})")
        print("=" * 65 + "\n")
        return

    if critical_or_high:
        verdict_text = Text()
        verdict_text.append("🛑 GATE BLOCKED — DO NOT LOG OUT\n", style="bold red blink")
        verdict_text.append(f"Account security posture has {len(critical_or_high)} blocking defect(s)!\n", style="bold white")
        verdict_text.append(f"Breakdown: {summary_counts}\n", style="bright_yellow")
        verdict_text.append("Resolve active root keys, open ports, or missing trails before leaving session.", style="dim italic")

        console.print("\n", Panel(
            verdict_text,
            title="[bold red]PRE-LOGOUT GATE VERDICT[/bold red]",
            border_style="bold red",
            box=HEAVY,
            padding=(1, 3),
        ))
    else:
        verdict_text = Text()
        verdict_text.append("✅ GATE OPEN — SAFE TO LOG OUT\n", style="bold bright_green")
        verdict_text.append("No critical or high severity misconfigurations detected.\n", style="bold white")
        verdict_text.append(f"Summary: {summary_counts}", style="green")

        console.print("\n", Panel(
            verdict_text,
            title="[bold bright_green]PRE-LOGOUT GATE VERDICT[/bold bright_green]",
            border_style="bold bright_green",
            box=ROUNDED,
            padding=(1, 3),
        ))
