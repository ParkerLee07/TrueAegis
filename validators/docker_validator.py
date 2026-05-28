import json
from .common import ValidationResult, tcp_connect, recv_banner


def validate(host: str, port: int = 2375, finding_id: str = "DOCKER_API_EXPOSED") -> ValidationResult:
    details = []

    if not tcp_connect(host, port):
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="NONE",
            summary="Docker API port is not reachable from this system.",
            details=["TCP connection failed."]
        )

    details.append("TCP connection to Docker API port succeeded.")

    request = (
        f"GET /version HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    response = recv_banner(host, port, payload=request, read_size=4096)

    if "ApiVersion" in response or "Docker" in response or '"Version"' in response:
        details.append("Docker API /version endpoint returned Docker-related data.")
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="HIGH",
            summary="Docker API appears accessible without client authentication.",
            details=details
        )

    if "400 Bad Request" in response or "client sent an HTTP request to an HTTPS server" in response.lower():
        details.append("Service may require TLS or is not plain HTTP Docker API.")
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="MEDIUM",
            summary="Docker-related port is reachable, but unauthenticated API access was not confirmed.",
            details=details
        )

    details.append(f"Received unexpected or empty response: {response[:200] if response else 'no banner'}")
    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=True,
        confidence="LOW",
        summary="Docker API port is reachable, but API exposure could not be confirmed.",
        details=details
    )
