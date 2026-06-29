#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

ok() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

python3 -m py_compile trueaegis.py \
    || fail "trueaegis.py has Python syntax errors"

python3 -m py_compile web/app.py \
    || fail "web/app.py has Python syntax errors"

grep -Fq 'TRUEAEGIS_VERSION = "v1.2.0-dev"' trueaegis.py \
    || fail "TrueAegis version marker is not v1.2.0-dev"

grep -Fq 'NETSNIPER_BUNDLE_SCHEMAS = {"netsniper-run-v2", "netsniper-run-v3"}' trueaegis.py \
    || fail "NetSniper bundle schema allow-list missing"

grep -Fq 'bundle_quality.json' trueaegis.py \
    || fail "bundle_quality.json handling missing"

grep -Fq 'TRUEAEGIS_ALLOW_UNREADY_BUNDLE' trueaegis.py \
    || fail "unready bundle override missing"

grep -Fq 'netsniper_source_metadata_record' trueaegis.py \
    || fail "NetSniper source metadata record helper missing"

grep -Fq 'netsniper_source_markdown_lines' trueaegis.py \
    || fail "Markdown source metadata helper missing"

fixture_base="${NETSNIPER_FIXTURE_BASE:-$HOME/NetSniper/examples/deltaaegis-fixtures}"

[ -d "$fixture_base" ] \
    || fail "NetSniper v2 fixture base not found: $fixture_base"

python3 - "$fixture_base" <<'PY'
import os
import sys
from pathlib import Path

fixture_base = Path(sys.argv[1]).expanduser()

import trueaegis

quick_dir = fixture_base / "quick-complete"
balanced_manifest = fixture_base / "balanced-complete" / "manifest.json"
accurate_dir = fixture_base / "accurate-complete"
failed_dir = fixture_base / "failed-quality"

for path in (quick_dir, balanced_manifest, accurate_dir, failed_dir):
    assert path.exists(), path

quick_hosts = trueaegis.load_netsniper_data(quick_dir)
assert isinstance(quick_hosts, list), type(quick_hosts)
assert len(quick_hosts) == 2, len(quick_hosts)
assert trueaegis.LAST_NETSNIPER_SOURCE_METADATA["schema_version"] == "netsniper-run-v3"
assert trueaegis.LAST_NETSNIPER_SOURCE_METADATA["effective_profile"] == "quick"
assert trueaegis.LAST_NETSNIPER_SOURCE_METADATA["deltaaegis_ready"] is True

balanced_hosts = trueaegis.load_netsniper_data(balanced_manifest)
assert isinstance(balanced_hosts, list), type(balanced_hosts)
assert len(balanced_hosts) == 2, len(balanced_hosts)
assert trueaegis.LAST_NETSNIPER_SOURCE_METADATA["effective_profile"] == "balanced"

accurate_hosts = trueaegis.load_netsniper_data(accurate_dir)
assert isinstance(accurate_hosts, list), type(accurate_hosts)
assert len(accurate_hosts) == 2, len(accurate_hosts)
assert trueaegis.LAST_NETSNIPER_SOURCE_METADATA["effective_profile"] == "accurate"

try:
    trueaegis.load_netsniper_data(failed_dir)
except SystemExit as exc:
    assert exc.code != 0
else:
    raise AssertionError("failed-quality fixture should be rejected by default")

os.environ["TRUEAEGIS_ALLOW_UNREADY_BUNDLE"] = "1"
failed_hosts = trueaegis.load_netsniper_data(failed_dir)
assert isinstance(failed_hosts, list), type(failed_hosts)
assert trueaegis.LAST_NETSNIPER_SOURCE_METADATA["deltaaegis_ready"] is False
del os.environ["TRUEAEGIS_ALLOW_UNREADY_BUNDLE"]

legacy_hosts = trueaegis.load_netsniper_data(quick_dir / "analysis.json")
assert isinstance(legacy_hosts, list), type(legacy_hosts)
assert len(legacy_hosts) == 2, len(legacy_hosts)
assert trueaegis.LAST_NETSNIPER_SOURCE_METADATA["source_kind"] == "analysis_json"

hosts = trueaegis.load_netsniper_data(quick_dir)
remediation_db = trueaegis.load_json(trueaegis.REMEDIATION_DB)
prioritized = trueaegis.collect_prioritized_findings(hosts, remediation_db, {})

md_path = trueaegis.generate_markdown_report(
    quick_dir,
    hosts,
    remediation_db,
    prioritized,
    validation_enabled=False,
    intelligence=None,
)
md_text = md_path.read_text(encoding="utf-8")
assert "## NetSniper Source Metadata" in md_text
assert "netsniper-run-v3" in md_text
assert "quick" in md_text

pdf_path = None
if trueaegis.REPORTLAB_AVAILABLE:
    pdf_path = trueaegis.generate_pdf_report(
        quick_dir,
        hosts,
        remediation_db,
        prioritized,
        validation_enabled=False,
        intelligence=None,
    )
    assert pdf_path.exists(), pdf_path
    assert pdf_path.stat().st_size > 0, pdf_path

snapshot = trueaegis.build_snapshot(
    quick_dir,
    hosts,
    prioritized,
    intelligence=None,
    validation_enabled=False,
)
source = snapshot["netsniper_source"]
assert source["schema_version"] == "netsniper-run-v3", source
assert source["effective_profile"] == "quick", source
assert source["deltaaegis_ready"] is True, source
assert source["analysis_path"].endswith("analysis.json"), source

try:
    md_path.unlink()
except FileNotFoundError:
    pass
if pdf_path:
    try:
        pdf_path.unlink()
    except FileNotFoundError:
        pass


import importlib.util

web_spec = importlib.util.spec_from_file_location("trueaegis_web_app", Path("web/app.py"))
web_app = importlib.util.module_from_spec(web_spec)
web_spec.loader.exec_module(web_app)

web_source = web_app.resolve_netsniper_source(quick_dir)
assert web_source["source_kind"] == "netsniper_bundle", web_source
assert web_source["schema_version"] == "netsniper-run-v3", web_source
assert web_source["effective_profile"] == "quick", web_source
assert web_source["deltaaegis_ready"] is True, web_source
assert web_source["analysis_path"].endswith("analysis.json"), web_source

web_hosts = web_app.normalize_scan_data(web_app.load_json(web_source["analysis_path"]))
assert isinstance(web_hosts, list), type(web_hosts)
assert len(web_hosts) == 2, len(web_hosts)

web_legacy = web_app.resolve_netsniper_source(quick_dir / "analysis.json")
assert web_legacy["source_kind"] == "analysis_json", web_legacy
assert web_legacy["schema_version"] == "legacy-analysis-json", web_legacy

web_status = web_app.netsniper_status()
assert "bundle_manifests" in web_status, web_status
assert "latest_source" in web_status, web_status

print("[PASS] TrueAegis NetSniper v2 bundle/report/snapshot compatibility python checks passed")
PY

ok "TrueAegis v1.2 NetSniper v2 compatibility validation passed"
