# TrueAegis

**TrueAegis** is a local exposure intelligence and infrastructure analysis platform built around the NetSniper telemetry engine.

NetSniper discovers and structures network exposure data. TrueAegis validates, enriches, correlates, tracks, and reports on that data through both a terminal interface and a local web dashboard.

> TrueAegis is designed for authorized security assessment, internal exposure review, lab environments, and defensive infrastructure analysis.

---

## Overview

TrueAegis helps answer a better question than “what ports are open?”

It helps answer:

> What does this environment appear to be, what exposures matter most, and what changed over time?

The platform combines:

- host discovery
- structured exposure telemetry
- safe validation checks
- attack surface correlations
- host role inference
- confidence scoring
- Markdown and PDF reporting
- snapshot history
- delta comparison
- local web dashboard
- terminal workflow support

---

## Architecture

```text
NetSniper
    ↓
Structured JSON Telemetry
    ↓
TrueAegis Knowledge Base
    ↓
Validation Engine
    ↓
Intelligence / Correlation Engine
    ↓
Reports + Snapshots + Deltas
    ↓
Terminal UI + Local Web Dashboard
```

---

## Core Components

| Component | Purpose |
|---|---|
| NetSniper | Discovery, scanning, and structured exposure output |
| TrueAegis CLI | Terminal interface for analysis, validation, reports, snapshots, and deltas |
| Validators | Safe exposure validation checks |
| Knowledge Base | Service context, risk metadata, correlation rules, report language |
| Intelligence Engine | Correlations, inferred roles, confidence scoring, analyst questions |
| Web UI | Local dashboard and control center at `127.0.0.1:8088` |
| Reporting Engine | Markdown and PDF intelligence reports |
| Workspace | Stored snapshots, deltas, logs, and historical state |

---

## Features

### Structured Exposure Telemetry

NetSniper outputs TrueAegis-compatible JSON:

```json
{
  "host": "192.168.4.2",
  "device_type": "Web Server",
  "severity": "MEDIUM",
  "score": 4,
  "scanner_version": "v1.2",
  "timestamp": "20260528-145014",
  "findings": [
    {
      "id": "HTTP_EXPOSED",
      "name": "HTTP service exposed",
      "service": "http",
      "port": 80,
      "score": 2,
      "evidence": "Port 80 open"
    }
  ]
}
```

### Validation-Aware Intelligence

TrueAegis can classify findings as:

- Confirmed
- Partially confirmed
- Reachable
- Not reachable
- Not validated

### Attack Surface Correlations

TrueAegis correlates related findings such as:

- SMB + RDP → Windows lateral movement surface
- Jenkins + Docker/Kubernetes → CI/CD to infrastructure pathway
- Elasticsearch + Kibana → logging/data exposure cluster
- RTSP + web management → IoT/camera management surface

### Host Role Inference

TrueAegis can infer likely host roles:

- Active Directory Domain Controller
- Windows Administrative Host
- Database Server
- Container Infrastructure
- Kubernetes Infrastructure
- Monitoring or Logging Host
- Printer / Print Server
- Camera / Embedded Device

### Historical Intelligence

TrueAegis stores snapshots and compares changes over time:

- new findings
- removed findings
- changed validation status
- risk score drift
- correlation changes

### Local Web Dashboard

The web interface runs locally:

```text
http://127.0.0.1:8088
```

It includes:

- dashboard overview
- findings table
- report browser
- snapshots
- deltas
- action logs
- local control center
- loading overlay for long-running actions

---

## Installation

Clone the repository:

```bash
git clone https://github.com/parkerlee07/TrueAegis.git
cd TrueAegis
```

Run the installer:

```bash
chmod +x install.sh
./install.sh
```

Restart your terminal or reload your shell:

```bash
source ~/.bashrc
```

---

## Requirements

System tools:

```text
bash
python3
pip
nmap
jq
```

Python packages:

```text
rich
flask
reportlab
```

Install Python dependencies manually if needed:

```bash
pip install -r requirements.txt
```

---

## Quick Start

Run NetSniper:

```bash
netsniper
```

Run TrueAegis terminal interface:

```bash
trueaegis
```

Launch the local web dashboard:

```bash
trueaegis-web
```

Open:

```text
http://127.0.0.1:8088
```

Generate a full validation-aware report:

```bash
trueaegis --validate --report --pdf
```

Save a snapshot:

```bash
trueaegis --snapshot
```

Compare snapshots:

```bash
trueaegis --delta
```

---

## Recommended Workflow

```text
1. Run NetSniper discovery
2. Run NetSniper TrueAegis-aligned scan
3. Analyze hosts
4. Open TrueAegis
5. Run validation
6. Generate reports
7. Save snapshot
8. Compare future snapshots
9. Review dashboard and reports
```

---

## Project Layout

```text
TrueAegis/
├── trueaegis.py
├── netsniper.sh
├── install.sh
├── uninstall.sh
├── requirements.txt
├── remediations/
│   └── exposures.json
├── knowledge/
│   ├── services.json
│   ├── correlations.json
│   ├── role_signatures.json
│   └── report_language.json
├── intelligence/
│   ├── correlation_engine.py
│   └── knowledge_enrichment.py
├── validators/
│   ├── validator_engine.py
│   ├── smb_validator.py
│   ├── redis_validator.py
│   ├── docker_validator.py
│   ├── http_validator.py
│   └── mongodb_validator.py
├── web/
│   ├── app.py
│   ├── templates/
│   └── static/
├── reports/
├── validation_results/
├── workspace/
└── screenshots/
```

---

## Security and Ethical Use

TrueAegis and NetSniper are intended for:

- authorized security assessments
- internal infrastructure review
- lab environments
- defensive exposure analysis
- educational security research

Do not scan networks, systems, or services without proper authorization.

See [`SECURITY.md`](SECURITY.md) and [`ETHICAL_USE.md`](ETHICAL_USE.md).

---

## Roadmap

See [`ROADMAP.md`](ROADMAP.md).

---

## Status

Current suggested release label:

```text
v1.1.0-beta
```

TrueAegis is stable enough for controlled early release, testing, and portfolio use, but should still be considered beta software.

---

## License

MIT License. See [`LICENSE`](LICENSE).
