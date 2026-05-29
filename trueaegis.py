#!/usr/bin/env python3
import os
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import Counter
import shutil
import subprocess

try:
    from intelligence.correlation_engine import build_intelligence
    INTELLIGENCE_AVAILABLE = True
except ImportError:
    INTELLIGENCE_AVAILABLE = False

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table as PDFTable,
        TableStyle,
        PageBreak
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from validators.validator_engine import validate_dataset
    VALIDATORS_AVAILABLE = True
except ImportError:
    VALIDATORS_AVAILABLE = False


console = Console()
TRUEAEGIS_VERSION = "v1.0-beta"

BASE_DIR = Path(__file__).resolve().parent
REMEDIATION_DB = BASE_DIR / "remediations" / "exposures.json"
REPORT_DIR = BASE_DIR / "reports"
VALIDATION_DIR = BASE_DIR / "validation_results"
WORKSPACE_DIR = BASE_DIR / "workspace"
SCAN_HISTORY_DIR = WORKSPACE_DIR / "scans"
SNAPSHOT_DIR = WORKSPACE_DIR / "snapshots"
DELTA_DIR = WORKSPACE_DIR / "deltas"
WORKSPACE_METADATA = WORKSPACE_DIR / "metadata.json"


def load_json(path):
    path = Path(path).expanduser()

    try:
        with open(path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        console.print(f"[red]JSON file not found:[/red] {path}")
        raise
    except json.JSONDecodeError as error:
        console.print(f"[red]Invalid JSON file:[/red] {path}")
        console.print(f"[yellow]JSON error:[/yellow] {error}")
        raise


def normalize_netsniper_data(raw_data):
    """Normalize supported NetSniper JSON shapes into a list of host records.

    TrueAegis primarily expects a list of host dictionaries. This function also
    supports common wrapper formats so future NetSniper exports do not break
    TrueAegis immediately.
    """
    if isinstance(raw_data, list):
        return raw_data

    if isinstance(raw_data, dict):
        for key in ("hosts", "results", "data", "scan_results"):
            value = raw_data.get(key)
            if isinstance(value, list):
                return value

        if "host" in raw_data and "findings" in raw_data:
            return [raw_data]

    console.print("[red]Unsupported NetSniper JSON format.[/red]")
    console.print("[yellow]Expected a list of host objects or an object containing hosts/results/data/scan_results.[/yellow]")
    sys.exit(1)


def load_netsniper_data(path):
    return normalize_netsniper_data(load_json(path))


def replace_target(commands, target):
    return [cmd.replace("TARGET", target) for cmd in commands]


def calculate_priority(remediation):
    return (
        remediation.get("exploitability", 0)
        + remediation.get("impact", 0)
        + remediation.get("priority", 0)
    )


def priority_label(score):
    if score >= 27:
        return "CRITICAL"
    if score >= 22:
        return "HIGH"
    if score >= 15:
        return "MEDIUM"
    if score >= 8:
        return "LOW"
    return "INFO"


def confidence_modifier(confidence):
    modifiers = {
        "HIGH": 5,
        "MEDIUM": 2,
        "LOW": 0,
        "NONE": -5,
        "UNKNOWN": 0
    }
    return modifiers.get(confidence, 0)


def adjusted_priority_score(base_score, validation):
    if not validation:
        return base_score

    adjusted = base_score + confidence_modifier(validation.get("confidence", "UNKNOWN"))

    if validation.get("validated") is False:
        adjusted -= 3

    return max(0, min(30, adjusted))


def validation_status_label(validation):
    if not validation:
        return "NOT VALIDATED"

    if validation.get("validated") and validation.get("confidence") == "HIGH":
        return "CONFIRMED"
    if validation.get("validated") and validation.get("confidence") == "MEDIUM":
        return "PARTIALLY CONFIRMED"
    if validation.get("validated") and validation.get("confidence") == "LOW":
        return "REACHABLE"
    if validation.get("validated") is False:
        return "NOT REACHABLE"
    return "UNKNOWN"


def find_latest_netsniper_file():
    search_dirs = [
        Path(os.environ.get("NETSNIPER_BASE", "")).expanduser() / "targets"
        if os.environ.get("NETSNIPER_BASE")
        else None,
        Path.home() / "NetSniper" / "targets",
        Path.home() / "netsniper" / "targets",
    ]

    json_files = []

    for directory in search_dirs:
        if directory and directory.exists():
            json_files.extend(directory.glob("analysis_*.json"))

    if not json_files:
        console.print("[red]No NetSniper analysis JSON files found.[/red]")
        console.print("[yellow]Expected location:[/yellow] ~/NetSniper/targets/analysis_*.json")
        console.print("[yellow]Also checked:[/yellow] ~/netsniper/targets/analysis_*.json")
        console.print("[yellow]Or set:[/yellow] export NETSNIPER_BASE=\"$HOME/NetSniper\"")
        sys.exit(1)

    latest_file = max(json_files, key=lambda path: path.stat().st_mtime)
    console.print(f"[green]Using latest NetSniper file:[/green] {latest_file}")
    return latest_file


def run_validation_if_requested(netsniper_data, enabled):
    if not enabled:
        return {}

    if not VALIDATORS_AVAILABLE:
        console.print("[red]Validators are not installed or could not be imported.[/red]")
        console.print("[yellow]Expected:[/yellow] ~/TrueAegis/validators/")
        return {}

    console.print("[cyan]Running safe exposure validation checks...[/cyan]")
    results = validate_dataset(netsniper_data)

    VALIDATION_DIR.mkdir(parents=True, exist_ok=True)
    out_file = VALIDATION_DIR / f"validation_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out_file.write_text(json.dumps(results, indent=2))

    console.print(f"[green]Validation results saved:[/green] {out_file}")

    return {
        (item["host"], item["finding_id"], int(item["port"])): item
        for item in results
    }


def collect_prioritized_findings(netsniper_data, remediation_db, validation_map=None):
    validation_map = validation_map or {}
    prioritized = []

    for host_entry in netsniper_data:
        host = host_entry.get("host", "Unknown")
        host_severity = host_entry.get("severity", "UNKNOWN")
        host_score = host_entry.get("score", 0)
        device_type = host_entry.get("device_type", "Unknown")

        for finding in host_entry.get("findings", []):
            finding_id = finding.get("id", "UNKNOWN")
            port = int(finding.get("port", 0) or 0)
            remediation = remediation_db.get(finding_id)
            validation = validation_map.get((host, finding_id, port))

            if remediation:
                base_score = calculate_priority(remediation)
                final_score = adjusted_priority_score(base_score, validation)
                category = remediation.get("category", "Unknown")
                label = priority_label(final_score)
            else:
                base_score = 0
                final_score = 0
                category = "Unmapped"
                label = "UNMAPPED"

            prioritized.append({
                "host": host,
                "device_type": device_type,
                "host_severity": host_severity,
                "host_score": host_score,
                "finding_id": finding_id,
                "finding_name": finding.get("name", "Unknown finding"),
                "category": category,
                "base_priority_score": base_score,
                "priority_score": final_score,
                "priority_label": label,
                "port": port,
                "service": finding.get("service", "unknown"),
                "evidence": finding.get("evidence", "No evidence provided"),
                "mapped": remediation is not None,
                "validation": validation,
                "validation_status": validation_status_label(validation)
            })

    return sorted(prioritized, key=lambda item: item["priority_score"], reverse=True)


def build_summary(netsniper_data, prioritized_findings):
    total_hosts = len(netsniper_data)
    total_findings = len(prioritized_findings)
    affected_hosts = len(set(item["host"] for item in prioritized_findings))

    priority_counts = Counter(item["priority_label"] for item in prioritized_findings)
    category_counts = Counter(item["category"] for item in prioritized_findings)
    validation_counts = Counter(item["validation_status"] for item in prioritized_findings)

    top_risks = prioritized_findings[:10]

    return {
        "total_hosts": total_hosts,
        "affected_hosts": affected_hosts,
        "total_findings": total_findings,
        "priority_counts": priority_counts,
        "category_counts": category_counts,
        "validation_counts": validation_counts,
        "top_risks": top_risks
    }


def executive_summary_text(summary, validation_enabled):
    critical = summary["priority_counts"].get("CRITICAL", 0)
    high = summary["priority_counts"].get("HIGH", 0)
    medium = summary["priority_counts"].get("MEDIUM", 0)

    confirmed = summary["validation_counts"].get("CONFIRMED", 0)
    partially_confirmed = summary["validation_counts"].get("PARTIALLY CONFIRMED", 0)
    reachable = summary["validation_counts"].get("REACHABLE", 0)

    if critical or high:
        posture = "elevated"
        recommendation = "The highest priority should be reviewing confirmed or partially confirmed exposures involving remote access, databases, and infrastructure services."
    elif medium:
        posture = "moderate"
        recommendation = "The environment has moderate exposure and should be reviewed for unnecessary services and weak configurations."
    else:
        posture = "low"
        recommendation = "The current scan shows limited high-risk exposure, but exposed services should still be validated."

    validation_sentence = ""
    if validation_enabled:
        validation_sentence = (
            f" Safe validation identified {confirmed} confirmed finding(s), "
            f"{partially_confirmed} partially confirmed finding(s), and "
            f"{reachable} reachable finding(s) without stronger risk indicators."
        )

    return (
        f"TrueAegis analyzed {summary['total_hosts']} host(s) and identified "
        f"{summary['total_findings']} finding(s) across {summary['affected_hosts']} affected host(s). "
        f"The current exposure posture is assessed as {posture}."
        f"{validation_sentence} "
        f"{recommendation}"
    )


def show_top_risks(prioritized_findings):
    if not prioritized_findings:
        console.print(
            Panel(
                "[yellow]No mapped findings available for priority ranking.[/yellow]",
                title="Priority Summary",
                border_style="yellow"
            )
        )
        return

    table = Table(title="Top Priority Findings")
    table.add_column("Rank", style="cyan", justify="right")
    table.add_column("Priority", style="red")
    table.add_column("Score", style="yellow", justify="right")
    table.add_column("Validation", style="green")
    table.add_column("Host", style="white")
    table.add_column("Finding", style="magenta")
    table.add_column("Category", style="cyan")

    for index, item in enumerate(prioritized_findings[:10], start=1):
        table.add_row(
            str(index),
            item["priority_label"],
            f'{item["priority_score"]}/30',
            item["validation_status"],
            item["host"],
            item["finding_id"],
            item["category"]
        )

    console.print(table)


def show_category_summary(prioritized_findings):
    category_counts = Counter(item["category"] for item in prioritized_findings)
    validation_counts = Counter(item["validation_status"] for item in prioritized_findings)

    if category_counts:
        table = Table(title="Exposure Categories")
        table.add_column("Category", style="cyan")
        table.add_column("Findings", style="white", justify="right")

        for category, count in category_counts.most_common():
            table.add_row(category, str(count))

        console.print(table)

    if validation_counts:
        table = Table(title="Validation Status")
        table.add_column("Status", style="cyan")
        table.add_column("Findings", style="white", justify="right")

        for status, count in validation_counts.most_common():
            table.add_row(status, str(count))

        console.print(table)


def generate_markdown_report(findings_file, netsniper_data, remediation_db, prioritized_findings, validation_enabled=False, intelligence=None):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = REPORT_DIR / f"trueaegis_intelligence_report_{timestamp}.md"

    summary = build_summary(netsniper_data, prioritized_findings)

    lines = []
    lines.append("# TrueAegis Exposure Intelligence Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Source File: `{findings_file}`")
    lines.append(f"Validation Enabled: `{validation_enabled}`")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(executive_summary_text(summary, validation_enabled))
    lines.append("")
    lines.append("## Attack Surface Narrative")
    lines.append("")
    if intelligence:
        lines.append(intelligence.get("narrative", "No intelligence narrative available."))
    else:
        lines.append("Intelligence engine was not available for this report.")
    lines.append("")
    lines.append("## Environment Overview")
    lines.append("")
    lines.append(f"- Hosts analyzed: {summary['total_hosts']}")
    lines.append(f"- Affected hosts: {summary['affected_hosts']}")
    lines.append(f"- Total findings: {summary['total_findings']}")
    lines.append("")
    lines.append("## Priority Breakdown")
    lines.append("")
    for priority in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNMAPPED"]:
        lines.append(f"- {priority}: {summary['priority_counts'].get(priority, 0)}")
    lines.append("")
    lines.append("## Validation Breakdown")
    lines.append("")
    for status in ["CONFIRMED", "PARTIALLY CONFIRMED", "REACHABLE", "NOT REACHABLE", "NOT VALIDATED", "UNKNOWN"]:
        lines.append(f"- {status}: {summary['validation_counts'].get(status, 0)}")
    lines.append("")
    lines.append("## Exposure Categories")
    lines.append("")
    for category, count in summary["category_counts"].most_common():
        lines.append(f"- {category}: {count}")
    lines.append("")
    lines.append("## Correlated Attack Surface Findings")
    lines.append("")
    if intelligence and intelligence.get("correlations"):
        lines.append("| Severity | Host | Correlation | Matched Findings |")
        lines.append("|---|---|---|---|")
        for item in intelligence.get("correlations", []):
            lines.append(f"| {item['severity']} | {item['host']} | {item['name']} | {', '.join(item['matched_findings'])} |")
    else:
        lines.append("No attack surface correlations detected.")
    lines.append("")
    lines.append("## Top Priority Findings")
    lines.append("")
    lines.append("| Rank | Priority | Score | Validation | Host | Finding | Category |")
    lines.append("|---:|---|---:|---|---|---|---|")
    for index, item in enumerate(summary["top_risks"], start=1):
        lines.append(
            f"| {index} | {item['priority_label']} | {item['priority_score']}/30 | "
            f"{item['validation_status']} | {item['host']} | {item['finding_id']} | {item['category']} |"
        )
    lines.append("")
    lines.append("## Host Intelligence Details")
    lines.append("")

    prioritized_lookup = {
        (item["host"], item["finding_id"], item["port"]): item
        for item in prioritized_findings
    }

    for host_entry in netsniper_data:
        host = host_entry.get("host", "Unknown")
        lines.append(f"### Host: {host}")
        lines.append("")
        lines.append(f"- Device type: {host_entry.get('device_type', 'Unknown')}")
        lines.append(f"- NetSniper severity: {host_entry.get('severity', 'UNKNOWN')}")
        lines.append(f"- NetSniper score: {host_entry.get('score', 0)}")
        lines.append("")

        for finding in host_entry.get("findings", []):
            finding_id = finding.get("id", "UNKNOWN")
            port = int(finding.get("port", 0) or 0)
            remediation = remediation_db.get(finding_id)
            priority_item = prioritized_lookup.get((host, finding_id, port), {})
            validation = priority_item.get("validation")

            lines.append(f"#### {finding_id}")
            lines.append("")
            lines.append(f"- Finding: {finding.get('name', 'Unknown finding')}")
            lines.append(f"- Service: {finding.get('service', 'unknown')}")
            lines.append(f"- Port: {port}")
            lines.append(f"- Evidence: {finding.get('evidence', 'No evidence provided')}")
            lines.append(f"- Validation status: {priority_item.get('validation_status', 'NOT VALIDATED')}")
            lines.append(f"- Aegis priority: {priority_item.get('priority_label', 'UNKNOWN')}")
            lines.append(f"- Priority score: {priority_item.get('priority_score', 0)}/30")

            if validation:
                lines.append(f"- Validation confidence: {validation.get('confidence', 'UNKNOWN')}")
                lines.append(f"- Validation summary: {validation.get('summary', 'No validation summary available.')}")
                for detail in validation.get("details", []):
                    lines.append(f"  - {detail}")

            if not remediation:
                lines.append("- Status: No remediation mapping currently exists.")
                lines.append("")
                continue

            lines.append(f"- Category: {remediation.get('category', 'Unknown')}")
            lines.append("")
            lines.append("Risk:")
            lines.append("")
            lines.append(remediation.get("risk", "No risk explanation available."))
            lines.append("")
            lines.append("Likely threats:")
            lines.append("")
            for threat in remediation.get("threats", []):
                lines.append(f"- {threat}")
            lines.append("")
            lines.append("Recommended review actions:")
            lines.append("")
            for step in remediation.get("remediation", []):
                lines.append(f"- {step}")
            lines.append("")

    report_path.write_text("\n".join(lines))
    return report_path


def pdf_paragraph(text, style):
    safe = (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return Paragraph(safe, style)


def generate_pdf_report(findings_file, netsniper_data, remediation_db, prioritized_findings, validation_enabled=False, intelligence=None):
    if not REPORTLAB_AVAILABLE:
        console.print("[red]ReportLab is not installed. Run:[/red] pip install reportlab")
        return None

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = REPORT_DIR / f"trueaegis_intelligence_report_{timestamp}.pdf"

    summary = build_summary(netsniper_data, prioritized_findings)

    doc = SimpleDocTemplate(
        str(report_path),
        pagesize=LETTER,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="SectionTitle", parent=styles["Heading2"], spaceBefore=14, spaceAfter=8))

    story = []

    story.append(Paragraph("TrueAegis Exposure Intelligence Report", styles["Title"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["BodyText"]))
    story.append(Paragraph(f"Source File: {findings_file}", styles["Small"]))
    story.append(Paragraph(f"Validation Enabled: {validation_enabled}", styles["Small"]))
    story.append(Spacer(1, 0.25 * inch))

    story.append(Paragraph("Executive Summary", styles["SectionTitle"]))
    story.append(pdf_paragraph(executive_summary_text(summary, validation_enabled), styles["BodyText"]))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("Attack Surface Narrative", styles["SectionTitle"]))
    if intelligence:
        story.append(pdf_paragraph(intelligence.get("narrative", "No intelligence narrative available."), styles["BodyText"]))
    else:
        story.append(pdf_paragraph("Intelligence engine was not available for this report.", styles["BodyText"]))
    story.append(Spacer(1, 0.2 * inch))

    overview_data = [
        ["Metric", "Value"],
        ["Hosts analyzed", str(summary["total_hosts"])],
        ["Affected hosts", str(summary["affected_hosts"])],
        ["Total findings", str(summary["total_findings"])],
        ["Confirmed findings", str(summary["validation_counts"].get("CONFIRMED", 0))],
        ["Partially confirmed findings", str(summary["validation_counts"].get("PARTIALLY CONFIRMED", 0))],
        ["Reachable findings", str(summary["validation_counts"].get("REACHABLE", 0))]
    ]

    overview_table = PDFTable(overview_data, colWidths=[2.7 * inch, 3.8 * inch])
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6)
    ]))
    story.append(overview_table)
    story.append(Spacer(1, 0.25 * inch))

    story.append(Paragraph("Top Priority Findings", styles["SectionTitle"]))

    top_table_data = [["Rank", "Priority", "Score", "Validation", "Host", "Finding"]]
    for index, item in enumerate(summary["top_risks"], start=1):
        top_table_data.append([
            str(index),
            item["priority_label"],
            f'{item["priority_score"]}/30',
            item["validation_status"],
            item["host"],
            item["finding_id"]
        ])

    top_table = PDFTable(
        top_table_data,
        colWidths=[0.4 * inch, 0.75 * inch, 0.55 * inch, 1.15 * inch, 1.05 * inch, 2.0 * inch]
    )
    top_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 4)
    ]))
    story.append(top_table)
    story.append(PageBreak())

    story.append(Paragraph("Host Intelligence Details", styles["Heading1"]))

    prioritized_lookup = {
        (item["host"], item["finding_id"], item["port"]): item
        for item in prioritized_findings
    }

    for host_entry in netsniper_data:
        host = host_entry.get("host", "Unknown")
        story.append(Paragraph(f"Host: {host}", styles["Heading2"]))
        story.append(Paragraph(f"Device type: {host_entry.get('device_type', 'Unknown')}", styles["BodyText"]))
        story.append(Paragraph(f"NetSniper severity: {host_entry.get('severity', 'UNKNOWN')}", styles["BodyText"]))
        story.append(Paragraph(f"NetSniper score: {host_entry.get('score', 0)}", styles["BodyText"]))
        story.append(Spacer(1, 0.1 * inch))

        for finding in host_entry.get("findings", []):
            finding_id = finding.get("id", "UNKNOWN")
            port = int(finding.get("port", 0) or 0)
            remediation = remediation_db.get(finding_id)
            priority_item = prioritized_lookup.get((host, finding_id, port), {})
            validation = priority_item.get("validation")

            story.append(Paragraph(finding_id, styles["Heading3"]))
            story.append(Paragraph(f"Finding: {finding.get('name', 'Unknown finding')}", styles["BodyText"]))
            story.append(Paragraph(f"Service: {finding.get('service', 'unknown')} | Port: {port}", styles["BodyText"]))
            story.append(Paragraph(f"Evidence: {finding.get('evidence', 'No evidence provided')}", styles["Small"]))
            story.append(Paragraph(f"Validation: {priority_item.get('validation_status', 'NOT VALIDATED')}", styles["BodyText"]))
            story.append(Paragraph(f"Priority: {priority_item.get('priority_label', 'UNKNOWN')} ({priority_item.get('priority_score', 0)}/30)", styles["BodyText"]))

            if validation:
                story.append(pdf_paragraph(f"Validation summary: {validation.get('summary', 'No validation summary available.')}", styles["BodyText"]))
                for detail in validation.get("details", []):
                    story.append(pdf_paragraph(f"- {detail}", styles["Small"]))

            if remediation:
                story.append(Paragraph("Risk", styles["Heading4"]))
                story.append(pdf_paragraph(remediation.get("risk", "No risk explanation available."), styles["BodyText"]))

            story.append(Spacer(1, 0.15 * inch))

    doc.build(story)
    return report_path


def run_terminal_view(netsniper_data, remediation_db, prioritized_findings):
    console.print(
        Panel.fit(
            f"[bold cyan]TrueAegis {TRUEAEGIS_VERSION}[/bold cyan]\nValidation-Aware Exposure Intelligence Engine",
            border_style="cyan"
        )
    )

    show_top_risks(prioritized_findings)
    show_category_summary(prioritized_findings)

    prioritized_lookup = {
        (item["host"], item["finding_id"], item["port"]): item
        for item in prioritized_findings
    }

    for host_entry in netsniper_data:
        host = host_entry.get("host", "Unknown")
        device_type = host_entry.get("device_type", "Unknown")
        severity = host_entry.get("severity", "UNKNOWN")
        score = host_entry.get("score", 0)
        scanner_version = host_entry.get("scanner_version", "Unknown")
        timestamp = host_entry.get("timestamp", "Unknown")

        host_table = Table(title=f"Host Analysis: {host}")
        host_table.add_column("Field", style="cyan")
        host_table.add_column("Value", style="white")

        host_table.add_row("Host", host)
        host_table.add_row("Device Type", device_type)
        host_table.add_row("NetSniper Severity", severity)
        host_table.add_row("NetSniper Score", str(score))
        host_table.add_row("Scanner Version", scanner_version)
        host_table.add_row("Timestamp", timestamp)

        console.print(host_table)

        for finding in host_entry.get("findings", []):
            finding_id = finding.get("id", "UNKNOWN")
            finding_name = finding.get("name", "Unknown finding")
            service = finding.get("service", "unknown")
            port = int(finding.get("port", 0) or 0)
            evidence = finding.get("evidence", "No evidence provided")
            priority_item = prioritized_lookup.get((host, finding_id, port), {})
            validation = priority_item.get("validation")

            if finding_id not in remediation_db:
                console.print(
                    Panel(
                        f"[yellow]No remediation found for:[/yellow] {finding_id}\n"
                        f"Finding: {finding_name}\n"
                        f"Service: {service}\n"
                        f"Port: {port}\n"
                        f"Evidence: {evidence}",
                        title="Unmapped Finding",
                        border_style="yellow"
                    )
                )
                continue

            remediation = remediation_db[finding_id]

            threats = remediation.get("threats", [])
            threat_output = "\n".join(f"* {threat}" for threat in threats) or "* No threat context available"

            remediation_steps = "\n".join(
                f"* {step}" for step in remediation.get("remediation", [])
            )

            validation_details = "No validation was run for this finding."
            if validation:
                detail_lines = "\n".join(f"* {detail}" for detail in validation.get("details", []))
                validation_details = f"{validation.get('summary', '')}\n{detail_lines}"

            output = f"""
[bold red]Finding ID:[/bold red] {finding_id}
[bold yellow]Finding:[/bold yellow] {finding_name}
[bold yellow]Service:[/bold yellow] {service}
[bold yellow]Port:[/bold yellow] {port}
[bold yellow]Evidence:[/bold yellow] {evidence}

[bold red]TrueAegis Priority:[/bold red] {priority_item.get("priority_label", "UNKNOWN")}
[bold red]Priority Score:[/bold red] {priority_item.get("priority_score", 0)}/30
[bold magenta]Category:[/bold magenta] {remediation.get("category", "Unknown")}

[bold cyan]Validation Status:[/bold cyan] {priority_item.get("validation_status", "NOT VALIDATED")}
[bold cyan]Validation Details:[/bold cyan]
{validation_details}

[bold magenta]Risk:[/bold magenta]
{remediation.get("risk", "No risk explanation available.")}

[bold magenta]Likely Threats:[/bold magenta]
{threat_output}

[bold green]Recommended Review Actions:[/bold green]
{remediation_steps}
"""

            console.print(
                Panel(
                    output.strip(),
                    title=f"{finding_id}",
                    border_style="green"
                )
            )



def show_intelligence_summary(intelligence):
    if not intelligence:
        console.print("[yellow]Intelligence engine not available.[/yellow]")
        return

    console.print(
        Panel(
            intelligence.get("narrative", "No intelligence narrative available."),
            title="Attack Surface Narrative",
            border_style="cyan"
        )
    )

    profile = intelligence.get("profile", {})
    service_counts = Counter(profile.get("service_counts", {}))
    device_types = Counter(profile.get("device_types", {}))

    if device_types:
        table = Table(title="Environment Profile")
        table.add_column("Device Type", style="cyan")
        table.add_column("Count", style="white", justify="right")

        for device, count in device_types.most_common():
            table.add_row(device, str(count))

        console.print(table)

    if service_counts:
        table = Table(title="Observed Services")
        table.add_column("Service", style="cyan")
        table.add_column("Findings", style="white", justify="right")

        for service, count in service_counts.most_common(10):
            table.add_row(service, str(count))

        console.print(table)

    correlations = intelligence.get("correlations", [])

    if correlations:
        table = Table(title="Correlated Attack Surface Findings")
        table.add_column("Severity", style="red")
        table.add_column("Host", style="white")
        table.add_column("Correlation", style="magenta")
        table.add_column("Matched Findings", style="cyan")

        for item in correlations:
            table.add_row(
                item["severity"],
                item["host"],
                item["name"],
                ", ".join(item["matched_findings"])
            )

        console.print(table)
    else:
        console.print(
            Panel(
                "No attack surface correlations detected.",
                title="Correlations",
                border_style="green"
            )
        )


def run_selected_mode(validate_mode=False, report_mode=False, pdf_mode=False, quiet_mode=False):
    findings_file = find_latest_netsniper_file()

    if not findings_file.exists():
        console.print(f"[red]File not found:[/red] {findings_file}")
        return

    if not REMEDIATION_DB.exists():
        console.print(f"[red]Remediation database not found:[/red] {REMEDIATION_DB}")
        return

    netsniper_data = load_netsniper_data(findings_file)
    remediation_db = load_json(REMEDIATION_DB)

    validation_map = run_validation_if_requested(netsniper_data, validate_mode)
    prioritized_findings = collect_prioritized_findings(netsniper_data, remediation_db, validation_map)

    intelligence = None
    if INTELLIGENCE_AVAILABLE:
        intelligence = build_intelligence(netsniper_data, prioritized_findings)

    if not quiet_mode:
        run_terminal_view(netsniper_data, remediation_db, prioritized_findings)

        if intelligence:
            show_intelligence_summary(intelligence)

    if report_mode:
        md_report = generate_markdown_report(
            findings_file,
            netsniper_data,
            remediation_db,
            prioritized_findings,
            validation_enabled=validate_mode,
            intelligence=intelligence
        )
        console.print(f"[green]Markdown report created:[/green] {md_report}")

    if pdf_mode:
        pdf_report = generate_pdf_report(
            findings_file,
            netsniper_data,
            remediation_db,
            prioritized_findings,
            validation_enabled=validate_mode,
            intelligence=intelligence
        )
        if pdf_report:
            console.print(f"[green]PDF report created:[/green] {pdf_report}")


def run_file_mode(args, validate_mode=False, report_mode=False, pdf_mode=False, quiet_mode=False):
    if len(args) == 1:
        findings_file = Path(args[0])
    else:
        findings_file = find_latest_netsniper_file()

    if not findings_file.exists():
        console.print(f"[red]File not found:[/red] {findings_file}")
        sys.exit(1)

    if not REMEDIATION_DB.exists():
        console.print(f"[red]Remediation database not found:[/red] {REMEDIATION_DB}")
        sys.exit(1)

    netsniper_data = load_netsniper_data(findings_file)
    remediation_db = load_json(REMEDIATION_DB)

    validation_map = run_validation_if_requested(netsniper_data, validate_mode)
    prioritized_findings = collect_prioritized_findings(netsniper_data, remediation_db, validation_map)

    intelligence = None
    if INTELLIGENCE_AVAILABLE:
        intelligence = build_intelligence(netsniper_data, prioritized_findings)

    if not quiet_mode:
        run_terminal_view(netsniper_data, remediation_db, prioritized_findings)

        if intelligence:
            show_intelligence_summary(intelligence)

    if report_mode:
        md_report = generate_markdown_report(
            findings_file,
            netsniper_data,
            remediation_db,
            prioritized_findings,
            validation_enabled=validate_mode,
            intelligence=intelligence
        )
        console.print(f"[green]Markdown report created:[/green] {md_report}")

    if pdf_mode:
        pdf_report = generate_pdf_report(
            findings_file,
            netsniper_data,
            remediation_db,
            prioritized_findings,
            validation_enabled=validate_mode,
            intelligence=intelligence
        )
        if pdf_report:
            console.print(f"[green]PDF report created:[/green] {pdf_report}")



# =========================
# PLATFORM / WORKSPACE LAYER
# =========================

def ensure_workspace():
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    SCAN_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    DELTA_DIR.mkdir(parents=True, exist_ok=True)

    if not WORKSPACE_METADATA.exists():
        metadata = {
            "platform_version": "v0.8",
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "snapshots": []
        }
        WORKSPACE_METADATA.write_text(json.dumps(metadata, indent=2))


def finding_key(host, finding):
    return f"{host}|{finding.get('id', 'UNKNOWN')}|{finding.get('port', 'unknown')}"


def build_snapshot(findings_file, netsniper_data, prioritized_findings, intelligence=None, validation_enabled=False):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    priority_counts = Counter(item["priority_label"] for item in prioritized_findings)
    validation_counts = Counter(item["validation_status"] for item in prioritized_findings)
    category_counts = Counter(item["category"] for item in prioritized_findings)

    finding_records = []

    prioritized_lookup = {
        (item["host"], item["finding_id"], item["port"]): item
        for item in prioritized_findings
    }

    for host_entry in netsniper_data:
        host = host_entry.get("host", "Unknown")

        for finding in host_entry.get("findings", []):
            finding_id = finding.get("id", "UNKNOWN")
            port = int(finding.get("port", 0) or 0)
            priority_item = prioritized_lookup.get((host, finding_id, port), {})

            finding_records.append({
                "key": finding_key(host, finding),
                "host": host,
                "finding_id": finding_id,
                "name": finding.get("name", "Unknown finding"),
                "service": finding.get("service", "unknown"),
                "port": port,
                "evidence": finding.get("evidence", "No evidence provided"),
                "priority_label": priority_item.get("priority_label", "UNKNOWN"),
                "priority_score": priority_item.get("priority_score", 0),
                "validation_status": priority_item.get("validation_status", "NOT VALIDATED"),
                "category": priority_item.get("category", "Unknown")
            })

    snapshot = {
        "snapshot_id": timestamp,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_file": str(findings_file),
        "validation_enabled": validation_enabled,
        "host_count": len(netsniper_data),
        "finding_count": len(finding_records),
        "priority_counts": dict(priority_counts),
        "validation_counts": dict(validation_counts),
        "category_counts": dict(category_counts),
        "correlation_count": len(intelligence.get("correlations", [])) if intelligence else 0,
        "narrative": intelligence.get("narrative", "") if intelligence else "",
        "findings": finding_records
    }

    return snapshot


def save_snapshot(snapshot, source_file=None):
    ensure_workspace()

    snapshot_id = snapshot["snapshot_id"]
    snapshot_path = SNAPSHOT_DIR / f"snapshot_{snapshot_id}.json"
    snapshot_path.write_text(json.dumps(snapshot, indent=2))

    if source_file and Path(source_file).exists():
        copied_scan = SCAN_HISTORY_DIR / f"netsniper_{snapshot_id}.json"
        shutil.copy2(source_file, copied_scan)
        snapshot["archived_scan"] = str(copied_scan)
        snapshot_path.write_text(json.dumps(snapshot, indent=2))

    metadata = load_json(WORKSPACE_METADATA)
    metadata.setdefault("snapshots", [])

    metadata["snapshots"].append({
        "snapshot_id": snapshot_id,
        "created": snapshot["created"],
        "path": str(snapshot_path),
        "source_file": snapshot["source_file"],
        "host_count": snapshot["host_count"],
        "finding_count": snapshot["finding_count"],
        "critical": snapshot["priority_counts"].get("CRITICAL", 0),
        "high": snapshot["priority_counts"].get("HIGH", 0),
        "confirmed": snapshot["validation_counts"].get("CONFIRMED", 0),
        "correlations": snapshot["correlation_count"]
    })

    metadata["snapshots"] = metadata["snapshots"][-50:]
    WORKSPACE_METADATA.write_text(json.dumps(metadata, indent=2))

    return snapshot_path


def get_snapshot_paths():
    ensure_workspace()
    return sorted(SNAPSHOT_DIR.glob("snapshot_*.json"))


def get_latest_snapshots(count=2):
    paths = get_snapshot_paths()
    latest = paths[-count:]
    return [load_json(path) for path in latest]


def compare_snapshots(previous, current):
    previous_findings = {item["key"]: item for item in previous.get("findings", [])}
    current_findings = {item["key"]: item for item in current.get("findings", [])}

    previous_keys = set(previous_findings.keys())
    current_keys = set(current_findings.keys())

    new_keys = sorted(current_keys - previous_keys)
    removed_keys = sorted(previous_keys - current_keys)
    persistent_keys = sorted(current_keys & previous_keys)

    score_previous = sum(item.get("priority_score", 0) for item in previous_findings.values())
    score_current = sum(item.get("priority_score", 0) for item in current_findings.values())

    changed_priority = []

    for key in persistent_keys:
        old = previous_findings[key]
        new = current_findings[key]

        if old.get("priority_score") != new.get("priority_score") or old.get("validation_status") != new.get("validation_status"):
            changed_priority.append({
                "key": key,
                "host": new.get("host"),
                "finding_id": new.get("finding_id"),
                "port": new.get("port"),
                "previous_score": old.get("priority_score", 0),
                "current_score": new.get("priority_score", 0),
                "previous_validation": old.get("validation_status", "UNKNOWN"),
                "current_validation": new.get("validation_status", "UNKNOWN")
            })

    delta = {
        "delta_id": datetime.now().strftime("%Y%m%d-%H%M%S"),
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "previous_snapshot": previous.get("snapshot_id"),
        "current_snapshot": current.get("snapshot_id"),
        "previous_finding_count": len(previous_findings),
        "current_finding_count": len(current_findings),
        "new_findings": [current_findings[key] for key in new_keys],
        "removed_findings": [previous_findings[key] for key in removed_keys],
        "changed_findings": changed_priority,
        "previous_total_risk_score": score_previous,
        "current_total_risk_score": score_current,
        "risk_score_change": score_current - score_previous,
        "previous_correlation_count": previous.get("correlation_count", 0),
        "current_correlation_count": current.get("correlation_count", 0),
        "correlation_change": current.get("correlation_count", 0) - previous.get("correlation_count", 0)
    }

    return delta


def save_delta(delta):
    ensure_workspace()

    delta_path = DELTA_DIR / f"delta_{delta['delta_id']}.json"
    delta_path.write_text(json.dumps(delta, indent=2))
    return delta_path


def show_workspace_dashboard():
    ensure_workspace()

    metadata = load_json(WORKSPACE_METADATA)
    snapshots = metadata.get("snapshots", [])

    console.print(
        Panel.fit(
            "[bold cyan]TrueAegis Platform Dashboard[/bold cyan]\nWorkspace Intelligence",
            border_style="cyan"
        )
    )

    if not snapshots:
        console.print("[yellow]No snapshots stored yet.[/yellow]")
        console.print("Run an analysis with snapshot storage first.")
        return

    latest = snapshots[-1]

    summary_table = Table(title="Latest Snapshot")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Snapshot ID", latest.get("snapshot_id", "Unknown"))
    summary_table.add_row("Created", latest.get("created", "Unknown"))
    summary_table.add_row("Hosts", str(latest.get("host_count", 0)))
    summary_table.add_row("Findings", str(latest.get("finding_count", 0)))
    summary_table.add_row("Critical", str(latest.get("critical", 0)))
    summary_table.add_row("High", str(latest.get("high", 0)))
    summary_table.add_row("Confirmed", str(latest.get("confirmed", 0)))
    summary_table.add_row("Correlations", str(latest.get("correlations", 0)))

    console.print(summary_table)

    history_table = Table(title="Recent Snapshot History")
    history_table.add_column("Snapshot", style="cyan")
    history_table.add_column("Created", style="white")
    history_table.add_column("Hosts", justify="right")
    history_table.add_column("Findings", justify="right")
    history_table.add_column("Critical", justify="right")
    history_table.add_column("High", justify="right")

    for item in snapshots[-10:]:
        history_table.add_row(
            item.get("snapshot_id", "Unknown"),
            item.get("created", "Unknown"),
            str(item.get("host_count", 0)),
            str(item.get("finding_count", 0)),
            str(item.get("critical", 0)),
            str(item.get("high", 0))
        )

    console.print(history_table)


def show_delta(delta):
    console.print(
        Panel.fit(
            f"[bold cyan]TrueAegis Delta Report[/bold cyan]\n"
            f"{delta.get('previous_snapshot')} → {delta.get('current_snapshot')}",
            border_style="cyan"
        )
    )

    overview = Table(title="Delta Overview")
    overview.add_column("Metric", style="cyan")
    overview.add_column("Value", style="white")

    overview.add_row("Previous findings", str(delta.get("previous_finding_count", 0)))
    overview.add_row("Current findings", str(delta.get("current_finding_count", 0)))
    overview.add_row("New findings", str(len(delta.get("new_findings", []))))
    overview.add_row("Removed findings", str(len(delta.get("removed_findings", []))))
    overview.add_row("Changed findings", str(len(delta.get("changed_findings", []))))
    overview.add_row("Risk score change", str(delta.get("risk_score_change", 0)))
    overview.add_row("Correlation change", str(delta.get("correlation_change", 0)))

    console.print(overview)

    if delta.get("new_findings"):
        table = Table(title="New Findings")
        table.add_column("Host", style="white")
        table.add_column("Finding", style="red")
        table.add_column("Port", justify="right")
        table.add_column("Priority", style="yellow")
        table.add_column("Validation", style="cyan")

        for item in delta["new_findings"]:
            table.add_row(
                item.get("host", "Unknown"),
                item.get("finding_id", "Unknown"),
                str(item.get("port", "")),
                item.get("priority_label", "UNKNOWN"),
                item.get("validation_status", "UNKNOWN")
            )

        console.print(table)

    if delta.get("removed_findings"):
        table = Table(title="Removed Findings")
        table.add_column("Host", style="white")
        table.add_column("Finding", style="green")
        table.add_column("Port", justify="right")

        for item in delta["removed_findings"]:
            table.add_row(
                item.get("host", "Unknown"),
                item.get("finding_id", "Unknown"),
                str(item.get("port", ""))
            )

        console.print(table)

    if delta.get("changed_findings"):
        table = Table(title="Changed Findings")
        table.add_column("Host", style="white")
        table.add_column("Finding", style="magenta")
        table.add_column("Port", justify="right")
        table.add_column("Old Score", justify="right")
        table.add_column("New Score", justify="right")
        table.add_column("Old Validation")
        table.add_column("New Validation")

        for item in delta["changed_findings"]:
            table.add_row(
                item.get("host", "Unknown"),
                item.get("finding_id", "Unknown"),
                str(item.get("port", "")),
                str(item.get("previous_score", 0)),
                str(item.get("current_score", 0)),
                item.get("previous_validation", "UNKNOWN"),
                item.get("current_validation", "UNKNOWN")
            )

        console.print(table)


def run_platform_snapshot(validate_mode=True, show_output=True):
    findings_file = find_latest_netsniper_file()

    if not findings_file.exists():
        console.print(f"[red]File not found:[/red] {findings_file}")
        return None

    if not REMEDIATION_DB.exists():
        console.print(f"[red]Remediation database not found:[/red] {REMEDIATION_DB}")
        return None

    netsniper_data = load_netsniper_data(findings_file)
    remediation_db = load_json(REMEDIATION_DB)

    validation_map = run_validation_if_requested(netsniper_data, validate_mode)
    prioritized_findings = collect_prioritized_findings(netsniper_data, remediation_db, validation_map)

    intelligence = None
    if INTELLIGENCE_AVAILABLE:
        intelligence = build_intelligence(netsniper_data, prioritized_findings)

    snapshot = build_snapshot(
        findings_file=findings_file,
        netsniper_data=netsniper_data,
        prioritized_findings=prioritized_findings,
        intelligence=intelligence,
        validation_enabled=validate_mode
    )

    snapshot_path = save_snapshot(snapshot, findings_file)

    if show_output:
        console.print(f"[green]Snapshot saved:[/green] {snapshot_path}")

    return snapshot


def run_delta_against_previous():
    snapshots = get_latest_snapshots(2)

    if len(snapshots) < 2:
        console.print("[yellow]At least two snapshots are required for delta analysis.[/yellow]")
        console.print("Create another platform snapshot first.")
        return None

    previous, current = snapshots[0], snapshots[1]
    delta = compare_snapshots(previous, current)
    delta_path = save_delta(delta)

    show_delta(delta)
    console.print(f"[green]Delta saved:[/green] {delta_path}")

    return delta


def launch_web_dashboard():
    console.print("[cyan]Launching TrueAegis Web Dashboard...[/cyan]")
    console.print("[green]Open:[/green] http://127.0.0.1:8088")

    try:
        subprocess.run(["trueaegis-web"])
    except FileNotFoundError:
        console.print("[red]trueaegis-web launcher not found.[/red]")
        fallback_app = BASE_DIR / "web" / "app.py"
        console.print(f"[yellow]Install the web launcher or run:[/yellow] python3 {fallback_app}")


def show_diagnostics():
    console.print(
        Panel.fit(
            f"[bold cyan]TrueAegis {TRUEAEGIS_VERSION} Diagnostics[/bold cyan]",
            border_style="cyan"
        )
    )

    table = Table(title="Path Configuration")
    table.add_column("Item", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("TrueAegis base", str(BASE_DIR))
    table.add_row("Remediation DB", str(REMEDIATION_DB))
    table.add_row("Remediation DB exists", str(REMEDIATION_DB.exists()))
    table.add_row("NETSNIPER_BASE override", str(NETSNIPER_BASE_OVERRIDE or "Not set"))

    console.print(table)

    candidates = Table(title="NetSniper Candidate Locations")
    candidates.add_column("Path", style="white")
    candidates.add_column("Exists", style="cyan")
    candidates.add_column("Analysis files", justify="right")

    for base_dir in netsniper_base_candidates():
        count = 0
        if base_dir.exists():
            for analysis_dir in netsniper_analysis_locations(base_dir):
                if analysis_dir.exists():
                    for pattern in NETSNIPER_ANALYSIS_PATTERNS:
                        count += len(list(analysis_dir.glob(pattern)))

        candidates.add_row(str(base_dir), str(base_dir.exists()), str(count))

    console.print(candidates)

    files = find_netsniper_analysis_files()
    if files:
        latest = max(files, key=lambda path: path.stat().st_mtime)
        console.print(f"[green]Latest detected NetSniper file:[/green] {latest}")
    else:
        console.print("[yellow]No NetSniper analysis files detected.[/yellow]")
        console.print('Set the path with: export NETSNIPER_BASE="$HOME/NetSniper"')


def show_menu():
    while True:
        console.print(
            Panel.fit(
                f"[bold cyan]TrueAegis {TRUEAEGIS_VERSION}[/bold cyan]\nExposure Intelligence Tool",
                border_style="cyan"
            )
        )

        console.print("[bold]Select an option:[/bold]")
        console.print("[cyan]1)[/cyan] Analyze latest NetSniper scan")
        console.print("[cyan]2)[/cyan] Validate exposures only")
        console.print("[cyan]3)[/cyan] Generate Markdown report")
        console.print("[cyan]4)[/cyan] Generate PDF report")
        console.print("[cyan]5)[/cyan] Full intelligence report")
        console.print("[cyan]6)[/cyan] Full report quietly")
        console.print("[cyan]7)[/cyan] Show latest NetSniper JSON file")
        console.print("[cyan]8)[/cyan] Save platform snapshot")
        console.print("[cyan]9)[/cyan] Show platform dashboard")
        console.print("[cyan]10)[/cyan] Compare latest snapshots")
        console.print("[cyan]11)[/cyan] Launch Local Web Dashboard")
        console.print("[cyan]12)[/cyan] Show diagnostics")
        console.print("[cyan]0)[/cyan] Exit")

        choice = input("trueaegis> ").strip()

        if choice == "1":
            run_selected_mode(validate_mode=False, report_mode=False, pdf_mode=False, quiet_mode=False)

        elif choice == "2":
            run_selected_mode(validate_mode=True, report_mode=False, pdf_mode=False, quiet_mode=False)

        elif choice == "3":
            run_selected_mode(validate_mode=False, report_mode=True, pdf_mode=False, quiet_mode=True)

        elif choice == "4":
            run_selected_mode(validate_mode=False, report_mode=False, pdf_mode=True, quiet_mode=True)

        elif choice == "5":
            run_selected_mode(validate_mode=True, report_mode=True, pdf_mode=True, quiet_mode=False)

        elif choice == "6":
            run_selected_mode(validate_mode=True, report_mode=True, pdf_mode=True, quiet_mode=True)

        elif choice == "7":
            latest = find_latest_netsniper_file()
            console.print(f"[green]Latest NetSniper file:[/green] {latest}")

        elif choice == "8":
            run_platform_snapshot(validate_mode=True, show_output=True)

        elif choice == "9":
            show_workspace_dashboard()

        elif choice == "10":
            run_delta_against_previous()

        elif choice == "11":
            launch_web_dashboard()

        elif choice == "12":
            show_diagnostics()

        elif choice == "0":
            console.print("[green]Goodbye.[/green]")
            break

        else:
            console.print("[red]Invalid option.[/red]")


def main():
    validate_mode = "--validate" in sys.argv
    report_mode = "--report" in sys.argv
    pdf_mode = "--pdf" in sys.argv
    quiet_mode = "--quiet" in sys.argv
    menu_mode = "--menu" in sys.argv
    snapshot_mode = "--snapshot" in sys.argv
    delta_mode = "--delta" in sys.argv
    dashboard_mode = "--dashboard" in sys.argv
    web_mode = "--web" in sys.argv

    ignored_flags = ("--validate", "--report", "--pdf", "--quiet", "--menu", "--snapshot", "--delta", "--dashboard", "--web")
    args = [arg for arg in sys.argv[1:] if arg not in ignored_flags]

    if snapshot_mode:
        run_platform_snapshot(validate_mode=True, show_output=True)
        return

    if delta_mode:
        run_delta_against_previous()
        return

    if dashboard_mode:
        show_workspace_dashboard()
        return

    if web_mode:
        launch_web_dashboard()
        return

    if len(sys.argv) == 1 or menu_mode:
        show_menu()
        return

    run_file_mode(
        args,
        validate_mode=validate_mode,
        report_mode=report_mode,
        pdf_mode=pdf_mode,
        quiet_mode=quiet_mode
    )


if __name__ == "__main__":
    main()
