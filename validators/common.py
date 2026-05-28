import socket
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class ValidationResult:
    finding_id: str
    host: str
    port: int
    validated: bool
    confidence: str
    summary: str
    details: List[str] = field(default_factory=list)
    safe: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "host": self.host,
            "port": self.port,
            "validated": self.validated,
            "confidence": self.confidence,
            "summary": self.summary,
            "details": self.details,
            "safe": self.safe
        }


def tcp_connect(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def recv_banner(host: str, port: int, payload: bytes = b"", timeout: float = 3.0, read_size: int = 1024) -> str:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if payload:
                sock.sendall(payload)
            try:
                data = sock.recv(read_size)
                return data.decode(errors="replace").strip()
            except socket.timeout:
                return ""
    except Exception:
        return ""


def run_command(command: list, timeout: int = 8) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Command not found: {command[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out"
    except Exception as exc:
        return 1, "", str(exc)


def confidence_from_details(validated: bool, high_signal: bool = False, medium_signal: bool = False) -> str:
    if high_signal:
        return "HIGH"
    if medium_signal:
        return "MEDIUM"
    if validated:
        return "LOW"
    return "NONE"
