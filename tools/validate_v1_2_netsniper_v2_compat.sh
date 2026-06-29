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

grep -Fq 'TRUEAEGIS_VERSION = "v1.2.0-dev"' trueaegis.py \
    || fail "TrueAegis version marker is not v1.2.0-dev"

grep -Fq 'NETSNIPER_BUNDLE_SCHEMAS = {"netsniper-run-v2", "netsniper-run-v3"}' trueaegis.py \
    || fail "NetSniper bundle schema allow-list missing"

grep -Fq 'bundle_quality.json' trueaegis.py \
    || fail "bundle_quality.json handling missing"

grep -Fq 'TRUEAEGIS_ALLOW_UNREADY_BUNDLE' trueaegis.py \
    || fail "unready bundle override missing"

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

legacy_hosts = trueaegis.load_netsniper_data(quick_dir / "analysis.json")
assert isinstance(legacy_hosts, list), type(legacy_hosts)
assert len(legacy_hosts) == 2, len(legacy_hosts)
assert trueaegis.LAST_NETSNIPER_SOURCE_METADATA["source_kind"] == "analysis_json"

print("[PASS] TrueAegis NetSniper v2 bundle compatibility python checks passed")
PY

ok "TrueAegis v1.2 NetSniper v2 compatibility validation passed"
