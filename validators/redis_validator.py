from __future__ import annotations

import socket
from typing import Dict

from .common import ValidationResult


RESP_PING = b"*1\r\n$4\r\nPING\r\n"
MAX_RESPONSE_SIZE = 4096


def _send_resp_ping(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> Dict[str, str]:
    """
    Send one safe RESP-formatted PING command.

    The protocol exchange itself is also the reachability check, avoiding a
    redundant preliminary TCP connection.
    """

    with socket.create_connection(
        (host, int(port)),
        timeout=timeout,
    ) as sock:
        sock.settimeout(timeout)
        sock.sendall(RESP_PING)

        response = sock.recv(MAX_RESPONSE_SIZE)

        return {
            "raw": response.decode(
                "utf-8",
                errors="replace",
            ).strip(),
        }


def _is_resp_response(response: str) -> bool:
    """
    Determine whether a response resembles a RESP value.

    RESP2 responses begin with one of these markers:
      + simple string
      - error
      : integer
      $ bulk string
      * array
    """

    return bool(response) and response[0] in {
        "+",
        "-",
        ":",
        "$",
        "*",
    }


def validate(
    host: str,
    port: int = 6379,
    finding_id: str = "REDIS_EXPOSED",
) -> ValidationResult:
    """
    Validate Redis with a safe RESP-formatted PING request.

    This confirms the Redis protocol and distinguishes unauthenticated access
    from an authentication-protected service. It does not read or modify data.
    """

    try:
        probe = _send_resp_ping(
            host=host,
            port=port,
        )

    except socket.timeout:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="LOW",
            status="TIMEOUT",
            reachability="UNKNOWN",
            protocol="UNKNOWN",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary=(
                "Redis PING request timed out. The port may be filtered, "
                "slow to respond, or running an unrelated service."
            ),
            details=[
                "RESP-formatted Redis PING timed out.",
            ],
            metadata={
                "probe_type": "redis_resp_ping",
            },
        )

    except ConnectionRefusedError as exc:
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
            summary="Redis port refused the connection.",
            details=[
                f"Connection refused: {exc}",
            ],
            metadata={
                "probe_type": "redis_resp_ping",
                "error": str(exc),
            },
        )

    except OSError as exc:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="LOW",
            status="INCONCLUSIVE",
            reachability="UNKNOWN",
            protocol="UNKNOWN",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary="Redis protocol exchange could not be completed.",
            details=[
                f"Redis PING exchange failed: {exc}",
            ],
            metadata={
                "probe_type": "redis_resp_ping",
                "error": str(exc),
            },
        )

    response = probe["raw"]
    normalized = response.upper()

    metadata = {
        "probe_type": "redis_resp_ping",
        "response": response[:1000],
    }

    if normalized.startswith("+PONG"):
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
            authentication="NOT_REQUIRED_FOR_PING",
            transport="TCP",
            summary=(
                "Redis RESP protocol was confirmed. The service responded "
                "to PING without requiring authentication."
            ),
            details=[
                "TCP connection succeeded.",
                "RESP-formatted PING returned +PONG.",
                "Redis accepted PING without authentication.",
            ],
            metadata=metadata,
        )

    if normalized.startswith("-NOAUTH"):
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="HIGH",
            status="PROTECTED",
            reachability="CONFIRMED",
            protocol="CONFIRMED",
            exposure="PROTECTED",
            authentication="REQUIRED",
            transport="TCP",
            summary=(
                "Redis RESP protocol was confirmed. The service requires "
                "authentication before accepting commands."
            ),
            details=[
                "TCP connection succeeded.",
                "RESP-formatted PING returned a Redis NOAUTH error.",
                "Redis authentication appears to be required.",
            ],
            metadata=metadata,
        )

    if normalized.startswith("-NOPERM"):
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="HIGH",
            status="PROTECTED",
            reachability="CONFIRMED",
            protocol="CONFIRMED",
            exposure="PROTECTED",
            authentication="REQUIRED_OR_RESTRICTED",
            transport="TCP",
            summary=(
                "Redis RESP protocol was confirmed. Access appears to be "
                "restricted by authentication or ACL policy."
            ),
            details=[
                "TCP connection succeeded.",
                "RESP-formatted PING returned a Redis NOPERM error.",
                "Redis ACL restrictions appear to be active.",
            ],
            metadata=metadata,
        )

    if _is_resp_response(response):
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="MEDIUM",
            status="PARTIALLY_CONFIRMED",
            reachability="CONFIRMED",
            protocol="RESP_CONFIRMED",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary=(
                "A RESP-compatible service responded, but the expected Redis "
                "PING behavior was not confirmed."
            ),
            details=[
                "TCP connection succeeded.",
                "A RESP-formatted response was received.",
                f"Unexpected RESP response: {response or 'empty response'}",
            ],
            metadata=metadata,
        )

    if not response:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="LOW",
            status="INCONCLUSIVE",
            reachability="CONFIRMED",
            protocol="UNKNOWN",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary=(
                "Port accepted the connection but did not return a Redis "
                "protocol response."
            ),
            details=[
                "TCP connection succeeded.",
                "No response was received after the RESP-formatted PING.",
            ],
            metadata=metadata,
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
            "Port is reachable, but the response does not match the Redis "
            "RESP protocol."
        ),
        details=[
            "TCP connection succeeded.",
            f"Unexpected non-RESP response: {response[:500]}",
        ],
        metadata=metadata,
    )
