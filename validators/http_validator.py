from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .common import ValidationResult, http_probe, tcp_probe, tls_probe


PRODUCT_KEYWORDS = {
    "JENKINS_EXPOSED": [
        "jenkins",
        "x-jenkins",
        "hudson",
    ],
    "PORTAINER_EXPOSED": [
        "portainer",
    ],
    "PORTAINER_CANDIDATE": [
        "portainer",
    ],
    "KIBANA_EXPOSED": [
        "kibana",
        "kbn-name",
        "kbn-version",
    ],
}

TLS_LIKELY_PORTS = {
    443,
    465,
    636,
    8443,
    9443,
    10250,
}


def _parse_status_code(status_line: str) -> Optional[int]:
    match = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", status_line or "")

    if not match:
        return None

    try:
        return int(match.group(1))
    except ValueError:
        return None


def _extract_title(body: str) -> str:
    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        body or "",
        flags=re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return ""

    return " ".join(match.group(1).split())[:200]


def _combined_response_text(response: Dict[str, object]) -> str:
    headers = response.get("headers", {})
    body = response.get("body", "")
    status_line = response.get("status_line", "")

    return (
        f"{status_line}\n"
        f"{headers}\n"
        f"{body}"
    ).lower()


def _detect_product_signals(
    finding_id: str,
    response: Dict[str, object],
) -> List[str]:
    keywords = PRODUCT_KEYWORDS.get(finding_id, [])

    if not keywords:
        return []

    combined = _combined_response_text(response)
    signals = []

    for keyword in keywords:
        if keyword.lower() in combined:
            signals.append(f"Product fingerprint observed: {keyword}")

    return signals


def _build_http_evidence(
    response: Dict[str, object],
    finding_id: str,
) -> Tuple[List[str], List[str], Dict[str, object]]:
    headers = response.get("headers", {})
    body = str(response.get("body", ""))
    status_line = str(response.get("status_line", ""))
    latency_ms = response.get("latency_ms")

    details: List[str] = []
    signals: List[str] = []

    details.append(f"HTTP response observed: {status_line or 'unknown status'}")

    if latency_ms is not None:
        details.append(f"HTTP response latency: {latency_ms} ms.")

    server = ""

    if isinstance(headers, dict):
        server = str(headers.get("server", "")).strip()

    if server:
        signals.append(f"Server header observed: {server}")

    title = _extract_title(body)

    if title:
        signals.append(f"HTML title observed: {title}")

    if "index of /" in body.lower():
        signals.append("Directory listing indicator observed.")

    product_signals = _detect_product_signals(finding_id, response)
    signals.extend(product_signals)
    details.extend(signals)

    metadata = {
        "status_line": status_line,
        "status_code": _parse_status_code(status_line),
        "headers": headers,
        "server": server,
        "title": title,
        "latency_ms": latency_ms,
        "product_signals": product_signals,
    }

    return details, signals, metadata


def _classify_http_response(
    host: str,
    port: int,
    finding_id: str,
    response: Dict[str, object],
    transport: str,
    tls_metadata: Optional[Dict[str, object]] = None,
) -> ValidationResult:
    details, signals, metadata = _build_http_evidence(
        response=response,
        finding_id=finding_id,
    )

    if tls_metadata:
        metadata["tls"] = tls_metadata

    status_code = metadata.get("status_code")
    product_expected = finding_id in PRODUCT_KEYWORDS
    product_confirmed = bool(metadata.get("product_signals"))
    authentication = "UNKNOWN"
    exposure = "PRESENT"

    if status_code in {401, 403}:
        authentication = "REQUIRED"
        exposure = "PROTECTED"

    if status_code == 401:
        details.append("Authentication challenge observed.")

    if status_code == 403:
        details.append("Access-control response observed.")

    if product_expected and not product_confirmed:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="MEDIUM",
            status="PARTIALLY_CONFIRMED",
            reachability="CONFIRMED",
            protocol="CONFIRMED",
            exposure=exposure,
            authentication=authentication,
            transport=transport,
            summary=(
                "A web service responded, but the expected product "
                "fingerprint was not confirmed."
            ),
            details=details,
            metadata=metadata,
        )

    if authentication == "REQUIRED":
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="HIGH" if product_confirmed else "MEDIUM",
            status="PROTECTED",
            reachability="CONFIRMED",
            protocol="CONFIRMED",
            exposure="PROTECTED",
            authentication="REQUIRED",
            transport=transport,
            summary=(
                "The expected web service responded and appears to require "
                "authentication or authorization."
            ),
            details=details,
            metadata=metadata,
        )

    if any("Directory listing" in signal for signal in signals):
        summary = "Web service responded and may expose a directory listing."
        confidence = "HIGH"
    elif product_confirmed:
        summary = "Expected web product fingerprint was confirmed."
        confidence = "HIGH"
    else:
        summary = "Web protocol response was confirmed."
        confidence = "MEDIUM"

    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=True,
        confidence=confidence,
        status="CONFIRMED",
        reachability="CONFIRMED",
        protocol="CONFIRMED",
        exposure=exposure,
        authentication=authentication,
        transport=transport,
        summary=summary,
        details=details,
        metadata=metadata,
    )


def validate_http(
    host: str,
    port: int = 80,
    finding_id: str = "HTTP_EXPOSED",
) -> ValidationResult:
    tcp = tcp_probe(host, port)

    if not tcp["reachable"]:
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
            summary="HTTP port is not reachable from this system.",
            details=[
                "TCP connection failed.",
                f"Reason: {tcp.get('error') or 'unknown connection error'}",
            ],
            metadata={
                "probe_type": "http",
                "tcp": tcp,
            },
        )

    response = http_probe(
        host=host,
        port=port,
        use_tls=False,
    )

    if not response["success"]:
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
                "Port is reachable, but a valid plaintext HTTP response "
                "was not observed."
            ),
            details=[
                "TCP connection succeeded.",
                f"HTTP probe error: {response.get('error') or 'no valid HTTP status line'}",
            ],
            metadata={
                "probe_type": "http",
                "tcp": tcp,
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


def validate_https(
    host: str,
    port: int = 443,
    finding_id: str = "HTTPS_EXPOSED",
) -> ValidationResult:
    tcp = tcp_probe(host, port)

    if not tcp["reachable"]:
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
            summary="HTTPS port is not reachable from this system.",
            details=[
                "TCP connection failed.",
                f"Reason: {tcp.get('error') or 'unknown connection error'}",
            ],
            metadata={
                "probe_type": "https",
                "tcp": tcp,
            },
        )

    tls = tls_probe(
        host=host,
        port=port,
    )

    if not tls["success"]:
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
                "Port is reachable, but a TLS handshake could not be "
                "completed."
            ),
            details=[
                "TCP connection succeeded.",
                f"TLS handshake failed: {tls.get('error') or 'unknown TLS error'}",
            ],
            metadata={
                "probe_type": "https",
                "tcp": tcp,
                "tls": tls,
            },
        )

    response = http_probe(
        host=host,
        port=port,
        use_tls=True,
    )

    tls_details = [
        "TLS handshake succeeded.",
        f"TLS version: {tls.get('tls_version', 'UNKNOWN')}",
        f"TLS cipher: {tls.get('cipher', 'UNKNOWN')}",
    ]

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
                "TLS was confirmed, but a valid HTTPS response was not "
                "observed."
            ),
            details=tls_details + [
                f"HTTPS probe error: {response.get('error') or 'no valid HTTP status line'}",
            ],
            metadata={
                "probe_type": "https",
                "tcp": tcp,
                "tls": tls,
                "https": response,
            },
        )

    result = _classify_http_response(
        host=host,
        port=port,
        finding_id=finding_id,
        response=response,
        transport="HTTPS",
        tls_metadata=tls,
    )

    result.details = tls_details + result.details
    result.evidence = list(result.details)

    return result


def _auto_fallback_improves_result(result: ValidationResult) -> bool:
    """
    Replace the primary web-probe result only when the fallback transport
    produces stronger positive evidence.
    """

    return result.status in {
        "CONFIRMED",
        "PROTECTED",
        "PARTIALLY_CONFIRMED",
    }


def validate_auto(
    host: str,
    port: int,
    finding_id: str,
) -> ValidationResult:
    """
    Probe product-oriented web candidates over HTTP and HTTPS.

    Open ports are treated as candidates until a product fingerprint is
    confirmed. Failed HTTPS fallback attempts do not overwrite clearer
    plaintext protocol mismatch results.
    """

    if int(port) in TLS_LIKELY_PORTS:
        primary = validate_https(
            host=host,
            port=port,
            finding_id=finding_id,
        )

        if _auto_fallback_improves_result(primary):
            return primary

        fallback = validate_http(
            host=host,
            port=port,
            finding_id=finding_id,
        )

        if _auto_fallback_improves_result(fallback):
            fallback.details.insert(
                0,
                "HTTPS probe did not confirm the service; "
                "plaintext fallback produced stronger evidence.",
            )

            fallback.evidence = list(fallback.details)
            return fallback

        return primary

    primary = validate_http(
        host=host,
        port=port,
        finding_id=finding_id,
    )

    if _auto_fallback_improves_result(primary):
        return primary

    fallback = validate_https(
        host=host,
        port=port,
        finding_id=finding_id,
    )

    if _auto_fallback_improves_result(fallback):
        fallback.details.insert(
            0,
            "Plaintext probe did not confirm the service; "
            "HTTPS fallback produced stronger evidence.",
        )

        fallback.evidence = list(fallback.details)
        return fallback

    return primary

def validate(
    host: str,
    port: int = 80,
    finding_id: str = "HTTP_EXPOSED",
) -> ValidationResult:
    """
    Backward-compatible entry point.
    """

    if finding_id == "HTTPS_EXPOSED":
        return validate_https(
            host=host,
            port=port,
            finding_id=finding_id,
        )

    if finding_id == "HTTP_EXPOSED":
        return validate_http(
            host=host,
            port=port,
            finding_id=finding_id,
        )

    return validate_auto(
        host=host,
        port=port,
        finding_id=finding_id,
    )
