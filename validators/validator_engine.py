from __future__ import annotations

from . import docker_validator
from . import http_validator
from . import mongodb_validator
from . import redis_validator
from . import smb_validator
from .common import ValidationResult, tcp_probe


VALIDATOR_MAP = {
    "REDIS_EXPOSED": redis_validator.validate,
    "DOCKER_API_EXPOSED": docker_validator.validate,
    "HTTP_EXPOSED": http_validator.validate_http,
    "HTTPS_EXPOSED": http_validator.validate_https,
    "JENKINS_EXPOSED": http_validator.validate_auto,
    "PORTAINER_EXPOSED": http_validator.validate_auto,
    "PORTAINER_CANDIDATE": http_validator.validate_auto,
    "KIBANA_EXPOSED": http_validator.validate_auto,
    "MONGODB_EXPOSED": mongodb_validator.validate,
    "SMB_EXPOSED": smb_validator.validate,
}


def generic_tcp_validator(
    host: str,
    port: int,
    finding_id: str,
) -> ValidationResult:
    """
    Confirm reachability only.

    An open TCP socket does not prove that the expected protocol is present.
    Generic results are recorded as REACHABLE rather than validated services.
    """

    probe = tcp_probe(host, port)

    if probe["reachable"]:
        latency = probe.get("latency_ms")
        details = [
            "Generic TCP connection succeeded.",
            "The expected application protocol has not been confirmed.",
        ]

        if latency is not None:
            details.insert(1, f"TCP connection latency: {latency} ms.")

        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,

            # False is intentional: only reachability was confirmed.
            validated=False,

            confidence="LOW",
            status="REACHABLE",
            reachability="CONFIRMED",
            protocol="UNKNOWN",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary=(
                "Port is reachable, but no service-specific validator is "
                "available yet."
            ),
            details=details,
            metadata={
                "latency_ms": latency,
                "probe_type": "generic_tcp",
            },
        )

    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=False,
        confidence="NONE",
        status="NOT_REACHABLE",
        reachability="NOT_REACHABLE",
        protocol="UNKNOWN",
        exposure="UNKNOWN",
        authentication="UNKNOWN",
        transport="TCP",
        summary="Port is not reachable from this system.",
        details=[
            "Generic TCP connection failed.",
            f"Reason: {probe.get('error') or 'unknown connection error'}",
        ],
        metadata={
            "probe_type": "generic_tcp",
            "error": probe.get("error", ""),
        },
    )


def validate_finding(host: str, finding: dict) -> dict:
    finding_id = finding.get("id", "UNKNOWN")
    port = int(finding.get("port", 0) or 0)
    validator = VALIDATOR_MAP.get(finding_id)

    if validator:
        result = validator(
            host=host,
            port=port,
            finding_id=finding_id,
        )
    else:
        result = generic_tcp_validator(
            host=host,
            port=port,
            finding_id=finding_id,
        )

    return result.to_dict()


def validate_dataset(netsniper_data: list) -> list:
    results = []

    for host_entry in netsniper_data:
        host = host_entry.get("host", "Unknown")

        for finding in host_entry.get("findings", []):
            results.append(validate_finding(host, finding))

    return results
