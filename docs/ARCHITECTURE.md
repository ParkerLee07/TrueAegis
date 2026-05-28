# Architecture

## High-Level Flow

```text
NetSniper
    discovers hosts
    scans services
    creates structured JSON
        ↓
TrueAegis
    loads scan JSON
    maps findings to knowledge base
    runs safe validators
    applies priority scoring
    correlates related exposures
    infers host roles
    generates reports
    stores snapshots
    compares deltas
        ↓
Interfaces
    terminal menu
    CLI flags
    local web dashboard
```

## Data Model

### NetSniper Host Record

```json
{
  "host": "192.168.4.2",
  "device_type": "Web Server",
  "severity": "MEDIUM",
  "score": 4,
  "scanner_version": "v1.2",
  "timestamp": "20260528-145014",
  "findings": []
}
```

### Finding Record

```json
{
  "id": "HTTP_EXPOSED",
  "name": "HTTP service exposed",
  "service": "http",
  "port": 80,
  "score": 2,
  "evidence": "Port 80 open"
}
```

## Key Directories

```text
remediations/
    exposures.json

knowledge/
    services.json
    correlations.json
    role_signatures.json
    report_language.json

validators/
    validator_engine.py
    service validators

intelligence/
    correlation_engine.py
    knowledge_enrichment.py

web/
    app.py
    templates/
    static/

workspace/
    scans/
    snapshots/
    deltas/
```

## Security Model

The web dashboard is intended to bind only to:

```text
127.0.0.1:8088
```

The web control center should execute only allowlisted commands.
