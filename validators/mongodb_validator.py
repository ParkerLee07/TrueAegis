from .common import ValidationResult, tcp_connect, recv_banner


def validate(host: str, port: int = 27017, finding_id: str = "MONGODB_EXPOSED") -> ValidationResult:
    details = []

    if not tcp_connect(host, port):
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="NONE",
            summary="MongoDB port is not reachable from this system.",
            details=["TCP connection failed."]
        )

    details.append("TCP connection to MongoDB port succeeded.")
    details.append("Authentication state was not tested with credentials.")

    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=True,
        confidence="LOW",
        summary="MongoDB port is reachable. Additional authorized testing is required to confirm authentication posture.",
        details=details
    )
