from __future__ import annotations

import socket
import ssl
import subprocess
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


VALIDATION_STATUSES = {
    "CONFIRMED",
    "PARTIALLY_CONFIRMED",
    "REACHABLE",
    "NOT_REACHABLE",
    "PROTOCOL_MISMATCH",
    "PROTECTED",
    "INCONCLUSIVE",
    "DEPENDENCY_MISSING",
    "TIMEOUT",
    "UNKNOWN",
}


@dataclass
class ValidationResult:
    """
    Structured safe-validation result.

    The legacy `validated` boolean remains temporarily available so the
    existing dashboard, CLI, report generator, and intelligence engine
    continue working during the TrueAegis v1.1 migration.
    """

    finding_id: str
    host: str
    port: int
    validated: bool
    confidence: str
    summary: str
    details: List[str] = field(default_factory=list)
    safe: bool = True

    # TrueAegis v1.1 evidence fields
    status: str = "UNKNOWN"
    reachability: str = "UNKNOWN"
    protocol: str = "UNKNOWN"
    exposure: str = "UNKNOWN"
    authentication: str = "UNKNOWN"
    transport: str = "UNKNOWN"
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.confidence = str(self.confidence or "UNKNOWN").upper()
        self.status = str(self.status or "UNKNOWN").upper()
        self.reachability = str(self.reachability or "UNKNOWN").upper()
        self.protocol = str(self.protocol or "UNKNOWN").upper()
        self.exposure = str(self.exposure or "UNKNOWN").upper()
        self.authentication = str(self.authentication or "UNKNOWN").upper()
        self.transport = str(self.transport or "UNKNOWN").upper()

        if self.reachability == "UNKNOWN":
            self.reachability = "CONFIRMED" if self.validated else "NOT_REACHABLE"

        # Compatibility behavior for original validators that have not yet
        # been converted to explicit v1.1 statuses.
        if self.status == "UNKNOWN":
            if not self.validated:
                self.status = "NOT_REACHABLE"
            elif self.confidence == "HIGH":
                self.status = "CONFIRMED"
            elif self.confidence == "MEDIUM":
                self.status = "PARTIALLY_CONFIRMED"
            else:
                self.status = "REACHABLE"

        if self.status not in VALIDATION_STATUSES:
            self.status = "UNKNOWN"

        if not self.evidence and self.details:
            self.evidence = list(self.details)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def tcp_probe(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    started = time.monotonic()

    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            latency_ms = round((time.monotonic() - started) * 1000, 2)

            return {
                "reachable": True,
                "transport": "TCP",
                "latency_ms": latency_ms,
                "error": "",
            }

    except socket.timeout:
        return {
            "reachable": False,
            "transport": "TCP",
            "latency_ms": None,
            "error": "Connection timed out.",
        }

    except OSError as exc:
        return {
            "reachable": False,
            "transport": "TCP",
            "latency_ms": None,
            "error": str(exc),
        }


def tcp_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    """
    Legacy wrapper retained for the original validators.
    """

    return bool(tcp_probe(host, port, timeout=timeout)["reachable"])


def udp_probe(
    host: str,
    port: int,
    payload: bytes = b"",
    timeout: float = 3.0,
    read_size: int = 4096,
) -> Dict[str, Any]:
    started = time.monotonic()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (host, int(port)))
            response, address = sock.recvfrom(read_size)

            return {
                "responded": True,
                "transport": "UDP",
                "latency_ms": round((time.monotonic() - started) * 1000, 2),
                "response": response,
                "address": address,
                "error": "",
            }

    except socket.timeout:
        return {
            "responded": False,
            "transport": "UDP",
            "latency_ms": None,
            "response": b"",
            "address": None,
            "error": "UDP response timed out.",
        }

    except OSError as exc:
        return {
            "responded": False,
            "transport": "UDP",
            "latency_ms": None,
            "response": b"",
            "address": None,
            "error": str(exc),
        }


def tls_probe(
    host: str,
    port: int,
    timeout: float = 3.0,
    server_hostname: Optional[str] = None,
    verify_certificate: bool = False,
) -> Dict[str, Any]:
    """
    Perform a safe TLS handshake and collect transport metadata.

    Verification is disabled by default because internal services may use
    private or self-signed certificates. This records encryption metadata
    without claiming that the certificate is trusted.
    """

    started = time.monotonic()

    try:
        if verify_certificate:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context()

        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            raw.settimeout(timeout)

            with context.wrap_socket(
                raw,
                server_hostname=server_hostname or host,
            ) as tls_socket:
                certificate_der = tls_socket.getpeercert(binary_form=True)
                certificate = tls_socket.getpeercert() or {}
                cipher = tls_socket.cipher()

                return {
                    "success": True,
                    "transport": "TLS",
                    "latency_ms": round(
                        (time.monotonic() - started) * 1000,
                        2,
                    ),
                    "tls_version": tls_socket.version() or "UNKNOWN",
                    "cipher": cipher[0] if cipher else "UNKNOWN",
                    "certificate_present": bool(certificate_der),
                    "certificate": certificate,
                    "error": "",
                }

    except socket.timeout:
        return {
            "success": False,
            "transport": "TLS",
            "latency_ms": None,
            "tls_version": "UNKNOWN",
            "cipher": "UNKNOWN",
            "certificate_present": False,
            "certificate": {},
            "error": "TLS handshake timed out.",
        }

    except (ssl.SSLError, OSError) as exc:
        return {
            "success": False,
            "transport": "TLS",
            "latency_ms": None,
            "tls_version": "UNKNOWN",
            "cipher": "UNKNOWN",
            "certificate_present": False,
            "certificate": {},
            "error": str(exc),
        }


def recv_banner(
    host: str,
    port: int,
    payload: bytes = b"",
    timeout: float = 3.0,
    read_size: int = 1024,
) -> str:
    """
    Receive up to `read_size` bytes and support multi-packet responses.

    The function signature remains compatible with the original validators.
    """

    chunks: List[bytes] = []
    bytes_read = 0

    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)

            if payload:
                sock.sendall(payload)

            while bytes_read < read_size:
                try:
                    chunk = sock.recv(min(1024, read_size - bytes_read))
                except socket.timeout:
                    break

                if not chunk:
                    break

                chunks.append(chunk)
                bytes_read += len(chunk)

            return b"".join(chunks).decode(errors="replace").strip()

    except OSError:
        return ""


def http_probe(
    host: str,
    port: int,
    path: str = "/",
    use_tls: bool = False,
    timeout: float = 3.0,
    read_size: int = 65536,
) -> Dict[str, Any]:
    """
    Perform a safe HTTP or HTTPS GET request and parse basic response data.
    """

    transport = "HTTPS" if use_tls else "HTTP"
    started = time.monotonic()

    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            raw.settimeout(timeout)
            sock = raw

            if use_tls:
                context = ssl._create_unverified_context()
                sock = context.wrap_socket(raw, server_hostname=host)
                sock.settimeout(timeout)

            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: TrueAegis-v1.1-Validator\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode()

            sock.sendall(request)

            chunks: List[bytes] = []
            bytes_read = 0

            while bytes_read < read_size:
                try:
                    chunk = sock.recv(min(4096, read_size - bytes_read))
                except socket.timeout:
                    break

                if not chunk:
                    break

                chunks.append(chunk)
                bytes_read += len(chunk)

            raw_response = b"".join(chunks).decode(errors="replace")
            head, _, body = raw_response.partition("\r\n\r\n")
            lines = head.splitlines()
            status_line = lines[0] if lines else ""

            headers: Dict[str, str] = {}

            for line in lines[1:]:
                if ":" not in line:
                    continue

                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

            return {
                "success": status_line.startswith("HTTP/"),
                "transport": transport,
                "latency_ms": round(
                    (time.monotonic() - started) * 1000,
                    2,
                ),
                "status_line": status_line,
                "headers": headers,
                "body": body,
                "raw_response": raw_response,
                "error": "",
            }

    except socket.timeout:
        return {
            "success": False,
            "transport": transport,
            "latency_ms": None,
            "status_line": "",
            "headers": {},
            "body": "",
            "raw_response": "",
            "error": f"{transport} request timed out.",
        }

    except (ssl.SSLError, OSError) as exc:
        return {
            "success": False,
            "transport": transport,
            "latency_ms": None,
            "status_line": "",
            "headers": {},
            "body": "",
            "raw_response": "",
            "error": str(exc),
        }


def run_command(command: list, timeout: int = 8) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()

    except FileNotFoundError:
        return 127, "", f"Command not found: {command[0]}"

    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out"

    except Exception as exc:
        return 1, "", str(exc)


def confidence_from_details(
    validated: bool,
    high_signal: bool = False,
    medium_signal: bool = False,
) -> str:
    if high_signal:
        return "HIGH"

    if medium_signal:
        return "MEDIUM"

    if validated:
        return "LOW"

    return "NONE"
