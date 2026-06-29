#!/usr/bin/env python3

import json
import os
import subprocess
from pathlib import Path
from collections import Counter
from datetime import datetime

from flask import Flask, render_template, send_from_directory, abort, redirect, url_for, flash, request

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
WORKSPACE_DIR = BASE_DIR / "workspace"
SNAPSHOT_DIR = WORKSPACE_DIR / "snapshots"
DELTA_DIR = WORKSPACE_DIR / "deltas"
VALIDATION_DIR = BASE_DIR / "validation_results"
LOG_DIR = BASE_DIR / "web_logs"

# NetSniper is a separate repository. The web dashboard must use the same
# install location as the terminal tool. The installer should export:
#   NETSNIPER_BASE="$HOME/NetSniper"
# This resolver also checks common fallback paths for manual installs.
NETSNIPER_PATTERNS = (
    "analysis_*.json",
    "netsniper_analysis_*.json",
    "findings_*.json",
)

NETSNIPER_BUNDLE_SCHEMAS = {"netsniper-run-v2", "netsniper-run-v3"}

app = Flask(__name__)
app.secret_key = "trueaegis-local-only"

# Local-only command allowlist.
# Do NOT accept arbitrary shell commands from the browser.
ACTIONS = {
    "netsniper": {
        "label": "Open NetSniper Terminal Menu",
        "command": ["netsniper"],
        "note": "Runs the NetSniper terminal menu in the server process. Best used from terminal."
    },
    "trueaegis_validate": {
        "label": "Run TrueAegis Validation",
        "command": ["trueaegis", "--validate"],
        "note": "Runs validation against the latest NetSniper telemetry."
    },
    "trueaegis_report": {
        "label": "Generate TrueAegis Markdown + PDF Report",
        "command": ["trueaegis", "--validate", "--report", "--pdf", "--quiet"],
        "note": "Creates reports in ~/TrueAegis/reports."
    },
    "trueaegis_snapshot": {
        "label": "Save TrueAegis Snapshot",
        "command": ["trueaegis", "--snapshot"],
        "note": "Stores a platform snapshot in ~/TrueAegis/workspace."
    },
    "trueaegis_delta": {
        "label": "Compare Latest Snapshots",
        "command": ["trueaegis", "--delta"],
        "note": "Compares the two latest snapshots."
    },
    "trueaegis_dashboard": {
        "label": "Print TrueAegis Terminal Dashboard",
        "command": ["trueaegis", "--dashboard"],
        "note": "Runs the terminal dashboard and captures output."
    }
}


def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def unique_paths(paths):
    seen = set()
    output = []

    for path in paths:
        if not path:
            continue

        expanded = Path(path).expanduser()
        key = str(expanded)

        if key not in seen:
            seen.add(key)
            output.append(expanded)

    return output


def netsniper_base_candidates():
    env_base = os.environ.get("NETSNIPER_BASE") or os.environ.get("NETSNIPER_HOME")

    return unique_paths([
        env_base,
        Path.home() / "NetSniper",
        Path.home() / "netsniper",
        Path.home() / "NETSNIPER",
        BASE_DIR / "NetSniper",
        BASE_DIR / "netsniper",
        BASE_DIR.parent / "NetSniper",
        BASE_DIR.parent / "netsniper",
    ])


def netsniper_output_dirs():
    dirs = []

    for base in netsniper_base_candidates():
        dirs.extend([
            base / "targets",
            base / "analysis",
            base / "reports",
            base,
        ])

    return unique_paths(dirs)


def netsniper_run_dirs():
    dirs = []

    for base in netsniper_base_candidates():
        dirs.append(base / "runs")

    return unique_paths(dirs)


def find_netsniper_bundle_manifests():
    manifests = []

    for directory in netsniper_run_dirs():
        if not directory.exists():
            continue

        manifests.extend(directory.glob("*/manifest.json"))

    return unique_paths([path for path in manifests if path.exists()])


def find_netsniper_analysis_files():
    files = []

    for directory in netsniper_output_dirs():
        if not directory.exists():
            continue

        for pattern in NETSNIPER_PATTERNS:
            files.extend(directory.glob(pattern))

    return unique_paths(files)


def latest_file(directory, pattern):
    files = sorted(Path(directory).glob(pattern), key=lambda path: path.stat().st_mtime)
    return files[-1] if files else None


def normalize_scan_data(data):
    if isinstance(data, dict):
        for key in ("hosts", "results", "data", "scan_results"):
            value = data.get(key)
            if isinstance(value, list):
                data = value
                break
        else:
            data = []

    if not isinstance(data, list):
        data = []

    return data


def normalize_manifest_files(files):
    return files if isinstance(files, dict) else {}


def bundle_file_from_manifest(bundle_dir, manifest, *keys, fallback=None):
    files = normalize_manifest_files(manifest.get("files", {}))

    for key in keys:
        value = files.get(key)
        if isinstance(value, str) and value.strip():
            return bundle_dir / value

    if fallback:
        return bundle_dir / fallback

    return None


def resolve_netsniper_source(source_path):
    source_path = Path(source_path).expanduser()

    if source_path.is_dir():
        bundle_dir = source_path
        manifest_path = bundle_dir / "manifest.json"
    elif source_path.name == "manifest.json":
        manifest_path = source_path
        bundle_dir = manifest_path.parent
    else:
        return {
            "source_kind": "analysis_json",
            "display_path": str(source_path),
            "source_path": str(source_path),
            "analysis_path": str(source_path),
            "schema_version": "legacy-analysis-json",
            "effective_profile": "",
            "requested_profile": "",
            "deltaaegis_ready": "",
            "quality_warnings": [],
            "quality_errors": [],
        }

    if not manifest_path.exists():
        return {
            "source_kind": "missing_bundle_manifest",
            "display_path": str(source_path),
            "source_path": str(source_path),
            "bundle_dir": str(bundle_dir),
            "manifest_path": str(manifest_path),
            "analysis_path": "",
            "schema_version": "",
            "effective_profile": "",
            "requested_profile": "",
            "deltaaegis_ready": "",
            "quality_warnings": [],
            "quality_errors": ["manifest.json not found"],
        }

    manifest = load_json(manifest_path) or {}
    schema_version = manifest.get("schema_version") or manifest.get("manifest_contract")

    analysis_path = bundle_file_from_manifest(
        bundle_dir,
        manifest,
        "analysis_json",
        "analysis",
        "findings_json",
        fallback="analysis.json",
    )

    quality_path = bundle_file_from_manifest(
        bundle_dir,
        manifest,
        "bundle_quality_json",
        fallback="bundle_quality.json",
    )

    quality = load_json(quality_path) if quality_path and quality_path.exists() else {}
    if not isinstance(quality, dict):
        quality = {}

    warnings = list(quality.get("warnings", []) or [])
    errors = list(quality.get("errors", []) or [])

    if schema_version not in NETSNIPER_BUNDLE_SCHEMAS:
        warnings.append(f"Unsupported or unknown NetSniper bundle schema: {schema_version}")

    if not analysis_path or not analysis_path.exists():
        errors.append("analysis.json not found for NetSniper bundle")

    return {
        "source_kind": "netsniper_bundle",
        "display_path": str(manifest_path),
        "source_path": str(source_path),
        "bundle_dir": str(bundle_dir),
        "manifest_path": str(manifest_path),
        "analysis_path": str(analysis_path) if analysis_path else "",
        "quality_path": str(quality_path) if quality_path else "",
        "schema_version": schema_version or "",
        "manifest_contract": manifest.get("manifest_contract", ""),
        "legacy_schema_version": manifest.get("legacy_schema_version", ""),
        "scanner_version": manifest.get("scanner_version", ""),
        "status": manifest.get("status", ""),
        "scan_id": manifest.get("scan_id", ""),
        "target": manifest.get("target") or manifest.get("network_scope", ""),
        "requested_profile": manifest.get("requested_profile") or manifest.get("scan_profile_requested", ""),
        "effective_profile": manifest.get("effective_profile") or manifest.get("scan_profile_effective", ""),
        "profile_contract": manifest.get("profile_contract", ""),
        "runtime_budget_seconds": manifest.get("profile_runtime_budget_seconds", ""),
        "profile_duration_seconds": manifest.get("profile_duration_seconds", ""),
        "profile_budget_exceeded": manifest.get("profile_budget_exceeded", ""),
        "deltaaegis_ready": quality.get("deltaaegis_ready", ""),
        "quality_schema_version": quality.get("schema_version", ""),
        "quality_warnings": warnings,
        "quality_errors": errors,
    }


def netsniper_source_candidates():
    candidates = []
    candidates.extend(find_netsniper_bundle_manifests())
    candidates.extend(find_netsniper_analysis_files())
    return unique_paths(candidates)


def latest_scan():
    candidates = netsniper_source_candidates()

    if not candidates:
        return None, []

    path = max(candidates, key=lambda item: item.stat().st_mtime)
    source = resolve_netsniper_source(path)

    analysis_path = source.get("analysis_path")
    data = load_json(analysis_path) if analysis_path else []
    data = normalize_scan_data(data or [])

    return Path(source.get("display_path") or str(path)), data


def netsniper_status():
    analysis_files = find_netsniper_analysis_files()
    bundle_manifests = find_netsniper_bundle_manifests()
    candidates = unique_paths(bundle_manifests + analysis_files)
    latest = max(candidates, key=lambda item: item.stat().st_mtime) if candidates else None
    latest_source = resolve_netsniper_source(latest) if latest else None

    return {
        "env_base": os.environ.get("NETSNIPER_BASE") or os.environ.get("NETSNIPER_HOME"),
        "base_candidates": [str(path) for path in netsniper_base_candidates()],
        "output_dirs": [str(path) for path in netsniper_output_dirs()],
        "run_dirs": [str(path) for path in netsniper_run_dirs()],
        "analysis_files": [str(path) for path in sorted(analysis_files, key=lambda item: item.stat().st_mtime, reverse=True)],
        "bundle_manifests": [str(path) for path in sorted(bundle_manifests, key=lambda item: item.stat().st_mtime, reverse=True)],
        "latest": str(latest) if latest else None,
        "latest_source": latest_source,
    }



def latest_snapshot():
    path = latest_file(SNAPSHOT_DIR, "snapshot_*.json")
    data = load_json(path) if path else None
    return path, data


def latest_delta():
    path = latest_file(DELTA_DIR, "delta_*.json")
    data = load_json(path) if path else None
    return path, data


def latest_validation():
    path = latest_file(VALIDATION_DIR, "validation_*.json")
    data = load_json(path) if path else None
    return path, data


def flatten_findings(scan_data):
    findings = []

    for host in scan_data:
        host_ip = host.get("host", "Unknown")
        device_type = host.get("device_type", "Unknown")
        severity = host.get("severity", "UNKNOWN")

        for finding in host.get("findings", []):
            findings.append({
                "host": host_ip,
                "device_type": device_type,
                "host_severity": severity,
                "id": finding.get("id", "UNKNOWN"),
                "name": finding.get("name", "Unknown"),
                "service": finding.get("service", "unknown"),
                "port": finding.get("port", "unknown"),
                "score": finding.get("score", 0),
                "evidence": finding.get("evidence", "No evidence")
            })

    return findings


def report_files():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(REPORTS_DIR.glob("*"), reverse=True)
    return [
        {
            "name": path.name,
            "suffix": path.suffix.lower(),
            "size": path.stat().st_size,
            "path": str(path)
        }
        for path in files
        if path.is_file()
    ]


def run_action(action_name):
    if action_name not in ACTIONS:
        return False, "Unknown action.", ""

    action = ACTIONS[action_name]
    command = action["command"]

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"action_{action_name}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"

    try:
        env = os.environ.copy()
        env.setdefault("TRUEAEGIS_HOME", str(BASE_DIR))
        env.setdefault("NETSNIPER_BASE", str(Path.home() / "NetSniper"))

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            env=env
        )

        output = ""
        if completed.stdout:
            output += completed.stdout
        if completed.stderr:
            output += "\n--- STDERR ---\n" + completed.stderr

        log_path.write_text(output or "Command completed with no output.")

        if completed.returncode == 0:
            return True, f"{action['label']} completed.", str(log_path)

        return False, f"{action['label']} exited with code {completed.returncode}.", str(log_path)

    except subprocess.TimeoutExpired as exc:
        log_path.write_text(f"Command timed out:\n{exc}")
        return False, f"{action['label']} timed out.", str(log_path)

    except FileNotFoundError:
        log_path.write_text(f"Command not found: {command[0]}")
        return False, f"Command not found: {command[0]}", str(log_path)

    except Exception as exc:
        log_path.write_text(str(exc))
        return False, f"Action failed: {exc}", str(log_path)


@app.route("/")
def index():
    scan_path, scan_data = latest_scan()
    snapshot_path, snapshot = latest_snapshot()
    delta_path, delta = latest_delta()
    validation_path, validation = latest_validation()

    findings = flatten_findings(scan_data)
    services = Counter(item["service"] for item in findings)
    host_count = len(scan_data)
    finding_count = len(findings)

    if snapshot:
        priority_counts = snapshot.get("priority_counts", {})
        validation_counts = snapshot.get("validation_counts", {})
        correlation_count = snapshot.get("correlation_count", 0)
        narrative = snapshot.get("narrative", "")
    else:
        priority_counts = {}
        validation_counts = {}
        correlation_count = 0
        narrative = "No platform snapshot has been created yet. Run a snapshot from the Control Center."

    return render_template(
        "index.html",
        scan_path=scan_path,
        snapshot_path=snapshot_path,
        delta_path=delta_path,
        validation_path=validation_path,
        host_count=host_count,
        finding_count=finding_count,
        services=services.most_common(8),
        priority_counts=priority_counts,
        validation_counts=validation_counts,
        correlation_count=correlation_count,
        narrative=narrative,
        delta=delta,
        actions=ACTIONS,
        netsniper_status=netsniper_status()
    )


@app.route("/control")
def control():
    return render_template("control.html", actions=ACTIONS)


@app.route("/run/<action>", methods=["POST"])
def run_control_action(action):
    ok, message, log_path = run_action(action)

    if ok:
        flash(f"{message} Log: {log_path}", "success")
    else:
        flash(f"{message} Log: {log_path}", "error")

    return redirect(request.referrer or url_for("control"))


@app.route("/findings")
def findings():
    scan_path, scan_data = latest_scan()
    rows = flatten_findings(scan_data)
    return render_template(
        "findings.html",
        scan_path=scan_path,
        findings=rows,
        netsniper_status=netsniper_status()
    )


@app.route("/snapshots")
def snapshots():
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    items = []

    for path in sorted(SNAPSHOT_DIR.glob("snapshot_*.json"), reverse=True):
        data = load_json(path)
        if not data:
            continue
        items.append({
            "id": data.get("snapshot_id", path.stem),
            "created": data.get("created", "Unknown"),
            "hosts": data.get("host_count", 0),
            "findings": data.get("finding_count", 0),
            "critical": data.get("priority_counts", {}).get("CRITICAL", 0),
            "high": data.get("priority_counts", {}).get("HIGH", 0),
            "confirmed": data.get("validation_counts", {}).get("CONFIRMED", 0),
            "correlations": data.get("correlation_count", 0),
            "file": path.name
        })

    return render_template("snapshots.html", snapshots=items)


@app.route("/reports")
def reports():
    return render_template("reports.html", reports=report_files())


@app.route("/reports/<path:filename>")
def download_report(filename):
    path = REPORTS_DIR / filename
    if not path.exists() or not path.is_file():
        abort(404)
    return send_from_directory(REPORTS_DIR, filename, as_attachment=False)


@app.route("/deltas")
def deltas():
    DELTA_DIR.mkdir(parents=True, exist_ok=True)
    items = []

    for path in sorted(DELTA_DIR.glob("delta_*.json"), reverse=True):
        data = load_json(path)
        if not data:
            continue
        items.append({
            "id": data.get("delta_id", path.stem),
            "created": data.get("created", "Unknown"),
            "previous": data.get("previous_snapshot", "Unknown"),
            "current": data.get("current_snapshot", "Unknown"),
            "new_count": len(data.get("new_findings", [])),
            "removed_count": len(data.get("removed_findings", [])),
            "changed_count": len(data.get("changed_findings", [])),
            "risk_change": data.get("risk_score_change", 0),
            "correlation_change": data.get("correlation_change", 0)
        })

    return render_template("deltas.html", deltas=items)


@app.route("/logs")
def logs():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    items = sorted(LOG_DIR.glob("*.log"), reverse=True)
    return render_template("logs.html", logs=items)


@app.route("/logs/<path:filename>")
def view_log(filename):
    path = LOG_DIR / filename
    if not path.exists() or not path.is_file():
        abort(404)
    return render_template("log_detail.html", filename=filename, content=path.read_text(errors="replace"))


@app.route("/diagnostics")
def diagnostics():
    status = netsniper_status()
    return {
        "trueaegis_home": str(BASE_DIR),
        "reports_dir": str(REPORTS_DIR),
        "workspace_dir": str(WORKSPACE_DIR),
        "netsniper": status,
    }


def main():
    print("[+] TrueAegis Web Control Center")
    print("[+] Local URL: http://127.0.0.1:8088")
    print("[!] Press CTRL+C to stop")
    app.run(host="127.0.0.1", port=8088, debug=False)


if __name__ == "__main__":
    main()
