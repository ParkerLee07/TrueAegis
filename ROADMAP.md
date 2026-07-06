# Roadmap

This roadmap distinguishes completed release history from future work. See
`CHANGELOG.md` for the detailed implementation record.

## Released

### v1.0.0 — Initial Stable Platform

- Structured NetSniper telemetry intake
- Safe validation engine
- Intelligence and correlation engine
- Markdown and PDF reports
- Snapshots and delta comparison
- Local terminal and web workflows

### v1.1.0 — Validation and Reporting Hardening

- Expanded validation states and protocol-aware checks
- Improved evidence, metadata, reporting, and dashboard behavior
- Additional validator and release-gate coverage

### v1.2.0 — NetSniper v2 Bundle Compatibility

- `netsniper-run-v2` and `netsniper-run-v3` manifest support
- Bundle-quality and readiness checks
- NetSniper source metadata in reports, snapshots, and dashboard views
- Legacy `analysis_*.json` compatibility retained

## Current Priorities

- Expand safe protocol-validator coverage
- Improve fixtures and regression testing
- Improve dashboard usability and evidence drilldown
- Add clearer example telemetry and architecture documentation
- Improve install, upgrade, and release validation
- Add useful export formats without weakening evidence provenance

## Deferred

- Local LLM or Ollama summarization
- Autonomous remediation
- Unrestricted command execution
- Features that require unsafe or unauthorized network interaction
