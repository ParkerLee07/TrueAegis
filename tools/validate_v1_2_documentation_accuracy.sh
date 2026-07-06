#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

echo "[TrueAegis documentation accuracy] checking README and roadmap"

python3 - <<'PY'
from pathlib import Path

readme = Path("README.md").read_text(encoding="utf-8")
roadmap = Path("ROADMAP.md").read_text(encoding="utf-8")

required_readme = [
    '"scanner_version": "v2.0.0"',
    "v1.2.0 — NetSniper v2 Bundle Compatibility",
    "stable, versioned defensive tool",
    "docs/",
    "tools/",
]

for marker in required_readme:
    if marker not in readme:
        raise SystemExit(f"README missing current marker: {marker}")

for stale in [
    '"scanner_version": "v1.3"',
    "should still be considered beta software",
    "Current suggested release label",
]:
    if stale in readme:
        raise SystemExit(f"README still contains stale wording: {stale}")

required_roadmap = [
    "## Released",
    "v1.2.0 — NetSniper v2 Bundle Compatibility",
    "## Current Priorities",
    "## Deferred",
]

for marker in required_roadmap:
    if marker not in roadmap:
        raise SystemExit(f"ROADMAP missing current marker: {marker}")

for stale in [
    "Focus: visualization",
    "- [ ] Publish GitHub release",
    "- [ ] TLS metadata collection",
    "## v1.0.0-beta",
]:
    if stale in roadmap:
        raise SystemExit(f"ROADMAP still contains stale item: {stale}")

print("TrueAegis documentation accuracy checks passed")
PY
