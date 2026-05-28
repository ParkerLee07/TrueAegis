from .common import ValidationResult, tcp_connect, recv_banner


def validate(host: str, port: int = 6379, finding_id: str = "REDIS_EXPOSED") -> ValidationResult:
    details = []

    if not tcp_connect(host, port):
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="NONE",
            summary="Redis port is not reachable from this system.",
            details=["TCP connection failed."]
        )

    details.append("TCP connection to Redis port succeeded.")

    response = recv_banner(host, port, payload=b"PING\r\n")
    normalized = response.upper()

    if "PONG" in normalized:
        details.append("Redis responded to PING without authentication.")
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="HIGH",
            summary="Redis appears reachable without authentication.",
            details=details
        )

    if "NOAUTH" in normalized or "AUTH" in normalized:
        details.append("Redis responded but requires authentication.")
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="MEDIUM",
            summary="Redis is reachable but appears to require authentication.",
            details=details
        )

    details.append(f"Received unexpected or empty response: {response or 'no banner'}")
    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=True,
        confidence="LOW",
        summary="Redis port is reachable, but authentication state could not be confirmed.",
        details=details
    )
