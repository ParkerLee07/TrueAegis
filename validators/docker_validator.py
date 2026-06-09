from __future__ import annotations

import json
from typing import Any, Dict, Optional

from .common import ValidationResult, http_probe, tls_probe


DOCKER_TLS_PORTS = {
    2376,
}

DOCKER_METADATA_FIELDS = [
    "Version",
    "ApiVersion",
    "MinAPIVersion",
    "GitCommit",
    "GoVersion",
    "Os",
    "Arch",
    "KernelVersion",
    "BuildTime",
    "Experimental",
]


def _connection_failure_status(error: str) -> str:
    lowered = str(error or "").lower()

    if "refused" in lowered:
        return "NOT_REACHABLE"

    if "timed out" in lowered or "timeout" in lowered:
        return "TIMEOUT"

    return "INCONCLUSIVE"


def _parse_status_code(status_line: str) -> Optional[int]:
    parts = str(status_line or "").split()

    if len(parts) < 2:
        return None

    try:
        return int(parts[1])
    except ValueError:
        return None


def _parse_docker_json(body: str) -> Optional[Dict[str, Any]]:
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(payload, dict):
        return None

    # Require Docker-specific keys instead of accepting broad text matches.
    if "Version" not in payload or "ApiVersion" not in payload:
        return None

    return payload


def _selected_metadata(payload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        field: payload[field]
        for field in DOCKER_METADATA_FIELDS
        if field in payload
    }


def _classify_http_response(
    host: str,
    port: int,
    finding_id: str,
    response: Dict[str, Any],
    transport: str,
    tls: Optional[Dict[str, Any]] = None,
) -> ValidationResult:
    status_line = str(response.get("status_line", ""))
    status_code = _parse_status_code(status_line)
    body = str(response.get("body", ""))
    headers = response.get("headers", {})
    latency_ms = response.get("latency_ms")

    details = [
        f"Docker /version probe received: {status_line or 'unknown status'}",
    ]

    if latency_ms is not None:
        details.append(f"HTTP response latency: {latency_ms} ms.")

    if tls:
        details.extend(
            [
                "TLS handshake succeeded.",
                f"TLS version: {tls.get('tls_version', 'UNKNOWN')}",
                f"TLS cipher: {tls.get('cipher', 'UNKNOWN')}",
            ]
        )

    metadata = {
        "probe_type": "docker_version",
        "status_line": status_line,
        "status_code": status_code,
        "headers": headers,
        "latency_ms": latency_ms,
    }

    if tls:
        metadata["tls"] = tls

    if status_code in {401, 403}:
        details.append(
            "The endpoint returned an authentication or authorization response."
        )

        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="MEDIUM",
            status="PROTECTED",
            reachability="CONFIRMED",
            protocol="HTTP_CONFIRMED",
            exposure="PROTECTED",
            authentication="REQUIRED",
            transport=transport,
            summary=(
                "A web service responded on the Docker API port, but access "
                "is protected and the Docker Engine API was not confirmed."
            ),
            details=details,
            metadata=metadata,
        )

    payload = _parse_docker_json(body)

    if payload is None:
        details.append(
            "Response body was not valid Docker Engine /version JSON."
        )

        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="LOW",
            status="PROTOCOL_MISMATCH",
            reachability="CONFIRMED",
            protocol="MISMATCH",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport=transport,
            summary=(
                "A web service responded, but the Docker Engine API "
                "fingerprint was not confirmed."
            ),
            details=details,
            metadata=metadata,
        )

    docker_metadata = _selected_metadata(payload)

    details.append("Docker Engine /version JSON fingerprint confirmed.")

    for key, value in docker_metadata.items():
        details.append(f"{key}: {value}")

    metadata["docker"] = docker_metadata

    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=True,
        confidence="HIGH",
        status="CONFIRMED",
        reachability="CONFIRMED",
        protocol="CONFIRMED",
        exposure="PRESENT",
        authentication="NOT_REQUIRED_FOR_VERSION",
        transport=transport,
        summary=(
            "Docker Engine /version endpoint was confirmed. The endpoint "
            "responded without client authentication."
        ),
        details=details,
        metadata=metadata,
    )


def validate_plaintext(
    host: str,
    port: int = 2375,
    finding_id: str = "DOCKER_API_EXPOSED",
) -> ValidationResult:
    response = http_probe(
        host=host,
        port=port,
        path="/version",
        use_tls=False,
    )

    if not response["success"]:
        status = _connection_failure_status(
            str(response.get("error", ""))
        )

        if status in {"NOT_REACHABLE", "TIMEOUT"}:
            reachability = (
                "NOT_REACHABLE"
                if status == "NOT_REACHABLE"
                else "UNKNOWN"
            )

            return ValidationResult(
                finding_id=finding_id,
                host=host,
                port=port,
                validated=False,
                confidence="NONE" if status == "NOT_REACHABLE" else "LOW",
                status=status,
                reachability=reachability,
                protocol="UNKNOWN",
                exposure="UNKNOWN",
                authentication="UNKNOWN",
                transport="TCP",
                summary="Docker plaintext API probe could not connect.",
                details=[
                    f"HTTP probe failed: {response.get('error') or 'unknown error'}",
                ],
                metadata={
                    "probe_type": "docker_version",
                    "http": response,
                },
            )

        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="LOW",
            status="PROTOCOL_MISMATCH",
            reachability="CONFIRMED",
            protocol="MISMATCH",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary=(
                "Port is reachable, but a valid plaintext Docker API "
                "response was not observed."
            ),
            details=[
                f"HTTP probe failed: {response.get('error') or 'no valid HTTP status line'}",
            ],
            metadata={
                "probe_type": "docker_version",
                "http": response,
            },
        )

    return _classify_http_response(
        host=host,
        port=port,
        finding_id=finding_id,
        response=response,
        transport="HTTP",
    )


def validate_tls(
    host: str,
    port: int = 2376,
    finding_id: str = "DOCKER_API_EXPOSED",
) -> ValidationResult:
    tls = tls_probe(
        host=host,
        port=port,
    )

    if not tls["success"]:
        status = _connection_failure_status(
            str(tls.get("error", ""))
        )

        lowered_error = str(tls.get("error", "")).lower()

        if (
            "certificate required" in lowered_error
            or "unknown ca" in lowered_error
            or "handshake failure" in lowered_error
        ):
            return ValidationResult(
                finding_id=finding_id,
                host=host,
                port=port,
                validated=False,
                confidence="MEDIUM",
                status="PROTECTED",
                reachability="CONFIRMED",
                protocol="TLS_CONFIRMED",
                exposure="PROTECTED",
                authentication="CLIENT_CERTIFICATE_LIKELY_REQUIRED",
                transport="TLS",
                summary=(
                    "TLS-protected Docker API port appears reachable, but "
                    "the server may require a trusted client certificate."
                ),
                details=[
                    f"TLS handshake response: {tls.get('error') or 'unknown TLS error'}",
                ],
                metadata={
                    "probe_type": "docker_version_tls",
                    "tls": tls,
                },
            )

        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="NONE" if status == "NOT_REACHABLE" else "LOW",
            status=status,
            reachability=(
                "NOT_REACHABLE"
                if status == "NOT_REACHABLE"
                else "UNKNOWN"
            ),
            protocol="UNKNOWN",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TLS",
            summary="Docker TLS API handshake could not be completed.",
            details=[
                f"TLS probe failed: {tls.get('error') or 'unknown TLS error'}",
            ],
            metadata={
                "probe_type": "docker_version_tls",
                "tls": tls,
            },
        )

    response = http_probe(
        host=host,
        port=port,
        path="/version",
        use_tls=True,
    )

    if not response["success"]:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="MEDIUM",
            status="PARTIALLY_CONFIRMED",
            reachability="CONFIRMED",
            protocol="TLS_CONFIRMED",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TLS",
            summary=(
                "TLS was confirmed on the Docker API port, but the Docker "
                "Engine /version endpoint did not return a valid HTTPS response."
            ),
            details=[
                "TLS handshake succeeded.",
                f"TLS version: {tls.get('tls_version', 'UNKNOWN')}",
                f"HTTPS probe failed: {response.get('error') or 'no valid HTTP status line'}",
            ],
            metadata={
                "probe_type": "docker_version_tls",
                "tls": tls,
                "https": response,
            },
        )

    return _classify_http_response(
        host=host,
        port=port,
        finding_id=finding_id,
        response=response,
        transport="HTTPS",
        tls=tls,
    )


def _fallback_improves_result(result: ValidationResult) -> bool:
    """
    Accept a fallback transport only when it provides stronger evidence.

    A failed TLS probe must not overwrite a clear plaintext protocol mismatch,
    and a failed plaintext probe must not overwrite a clear TLS result.
    """

    return result.status in {
        "CONFIRMED",
        "PROTECTED",
        "PARTIALLY_CONFIRMED",
    }


def validate(
    host: str,
    port: int = 2375,
    finding_id: str = "DOCKER_API_EXPOSED",
) -> ValidationResult:
    """
    Confirm Docker Engine using a safe read-only /version request.

    Port 2376 is checked with TLS first. Other ports are checked with
    plaintext HTTP first. A secondary transport is attempted only as a
    fallback, and its result replaces the primary result only when it provides
    stronger positive evidence.
    """

    if int(port) in DOCKER_TLS_PORTS:
        primary = validate_tls(
            host=host,
            port=port,
            finding_id=finding_id,
        )

        if _fallback_improves_result(primary):
            return primary

        fallback = validate_plaintext(
            host=host,
            port=port,
            finding_id=finding_id,
        )

        if _fallback_improves_result(fallback):
            fallback.details.insert(
                0,
                "TLS probe did not confirm Docker; plaintext fallback succeeded.",
            )
            fallback.evidence = list(fallback.details)

            return fallback

        return primary

    primary = validate_plaintext(
        host=host,
        port=port,
        finding_id=finding_id,
    )

    if _fallback_improves_result(primary):
        return primary

    fallback = validate_tls(
        host=host,
        port=port,
        finding_id=finding_id,
    )

    if _fallback_improves_result(fallback):
        fallback.details.insert(
            0,
            "Plaintext probe did not confirm Docker; TLS fallback succeeded.",
        )
        fallback.evidence = list(fallback.details)

        return fallback

    return primary
