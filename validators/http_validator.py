from .common import ValidationResult, tcp_connect, recv_banner


SUSPICIOUS_TITLES = [
    "jenkins",
    "kibana",
    "portainer",
    "grafana",
    "phpmyadmin",
    "admin",
    "login",
    "dashboard"
]


def validate(host: str, port: int = 80, finding_id: str = "HTTP_EXPOSED") -> ValidationResult:
    details = []

    if not tcp_connect(host, port):
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="NONE",
            summary="HTTP port is not reachable from this system.",
            details=["TCP connection failed."]
        )

    details.append("TCP connection to web service succeeded.")

    scheme_payload = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: AegisCore-Validator\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    response = recv_banner(host, port, payload=scheme_payload, read_size=4096)
    lower = response.lower()

    signals = []

    if "server:" in lower:
        server_line = next((line for line in response.splitlines() if line.lower().startswith("server:")), "")
        if server_line:
            signals.append(f"Server header observed: {server_line}")

    for title in SUSPICIOUS_TITLES:
        if title in lower:
            signals.append(f"Potential web/admin keyword observed: {title}")

    if "index of /" in lower:
        signals.append("Directory listing indicator observed.")

    details.extend(signals)

    if any("Directory listing" in s for s in signals):
        confidence = "HIGH"
        summary = "Web service is reachable and may expose directory listing."
    elif signals:
        confidence = "MEDIUM"
        summary = "Web service is reachable and contains potentially relevant exposure indicators."
    else:
        confidence = "LOW"
        summary = "Web service is reachable, but no obvious high-risk indicators were observed."

    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=True,
        confidence=confidence,
        summary=summary,
        details=details
    )
