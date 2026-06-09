from __future__ import annotations

import shutil
from typing import Dict, List, Tuple

from .common import ValidationResult, run_command, tcp_probe


SMB_SHARE_TYPES = {
    "disk",
    "ipc",
    "printer",
    "device",
}

AUTHENTICATION_DENIED_MARKERS = {
    "nt_status_access_denied",
    "nt_status_logon_failure",
    "nt_status_account_disabled",
    "nt_status_password_expired",
    "session setup failed",
    "access denied",
    "logon failure",
}

PROTOCOL_MISMATCH_MARKERS = {
    "protocol negotiation failed",
    "nt_status_invalid_network_response",
    "connection reset by peer",
    "server not using user level security",
}


def _extract_share_lines(output: str) -> List[str]:
    """
    Parse grepable smbclient -L output.

    Expected rows commonly resemble:
        Disk|Public|Fixture share
        IPC|IPC$|IPC Service
    """

    shares = []

    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()

        if not line or "|" not in line:
            continue

        parts = [
            part.strip()
            for part in line.split("|")
        ]

        if not parts:
            continue

        share_type = parts[0].lower()

        if share_type in SMB_SHARE_TYPES:
            shares.append(line)

    return shares


def _contains_any(
    text: str,
    markers: set[str],
) -> bool:
    lowered = str(text or "").lower()

    return any(
        marker in lowered
        for marker in markers
    )


def _dependency_result(
    host: str,
    port: int,
    finding_id: str,
    tcp: Dict[str, object],
) -> ValidationResult:
    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=False,
        confidence="LOW",
        status="DEPENDENCY_MISSING",
        reachability="CONFIRMED",
        protocol="UNKNOWN",
        exposure="UNKNOWN",
        authentication="UNKNOWN",
        transport="TCP",
        summary=(
            "SMB port is reachable, but smbclient is not installed. "
            "Anonymous enumeration and SMB protocol validation were skipped."
        ),
        details=[
            "TCP connection to the suspected SMB port succeeded.",
            "Required dependency is missing: smbclient",
            "Install with: sudo apt install smbclient",
        ],
        metadata={
            "probe_type": "smbclient_anonymous_list",
            "tcp": tcp,
            "dependency": "smbclient",
        },
    )


def validate(
    host: str,
    port: int = 445,
    finding_id: str = "SMB_EXPOSED",
) -> ValidationResult:
    """
    Safely validate SMB reachability and anonymous share enumeration.

    This invokes smbclient without credentials and requests a service list.
    It does not mount shares, read files, write files, or attempt passwords.
    """

    tcp = tcp_probe(
        host=host,
        port=port,
    )

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
            summary="SMB port is not reachable from this system.",
            details=[
                "TCP connection failed.",
                f"Reason: {tcp.get('error') or 'unknown connection error'}",
            ],
            metadata={
                "probe_type": "smbclient_anonymous_list",
                "tcp": tcp,
            },
        )

    if shutil.which("smbclient") is None:
        return _dependency_result(
            host=host,
            port=port,
            finding_id=finding_id,
            tcp=tcp,
        )

    command = [
        "smbclient",
        "-L",
        host,
        "-N",
        "-g",
        "-p",
        str(port),
    ]

    rc, stdout, stderr = run_command(
        command,
        timeout=12,
    )

    combined = (
        f"{stdout}\n{stderr}"
    ).strip()

    metadata = {
        "probe_type": "smbclient_anonymous_list",
        "tcp": tcp,
        "command": command,
        "return_code": rc,
        "stdout": stdout[:4000],
        "stderr": stderr[:4000],
    }

    details = [
        "TCP connection to the suspected SMB port succeeded.",
        f"smbclient return code: {rc}",
    ]

    if rc == 127:
        return _dependency_result(
            host=host,
            port=port,
            finding_id=finding_id,
            tcp=tcp,
        )

    if rc == 124:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="LOW",
            status="TIMEOUT",
            reachability="CONFIRMED",
            protocol="UNKNOWN",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary=(
                "SMB port is reachable, but smbclient timed out before "
                "validation completed."
            ),
            details=details + [
                "smbclient timed out.",
            ],
            metadata=metadata,
        )

    share_lines = _extract_share_lines(
        stdout,
    )

    if share_lines:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="HIGH",
            status="CONFIRMED",
            reachability="CONFIRMED",
            protocol="CONFIRMED",
            exposure="ANONYMOUS_ENUMERATION",
            authentication="NOT_REQUIRED_FOR_LIST",
            transport="TCP",
            summary=(
                "SMB protocol was confirmed and anonymous service "
                "enumeration returned share information."
            ),
            details=details + [
                "Anonymous SMB service listing returned parseable entries.",
                *[
                    f"Anonymous listing entry: {line}"
                    for line in share_lines
                ],
            ],
            metadata={
                **metadata,
                "shares": share_lines,
            },
        )

    if _contains_any(
        combined,
        AUTHENTICATION_DENIED_MARKERS,
    ):
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
                "SMB protocol appears reachable, but anonymous service "
                "enumeration was denied."
            ),
            details=details + [
                "SMB authentication or authorization rejection observed.",
                combined[:1000],
            ],
            metadata=metadata,
        )

    if _contains_any(
        combined,
        PROTOCOL_MISMATCH_MARKERS,
    ):
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
                "Port is reachable, but SMB protocol negotiation did not "
                "complete successfully."
            ),
            details=details + [
                "SMB protocol mismatch indicator observed.",
                combined[:1000],
            ],
            metadata=metadata,
        )

    if rc == 0:
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="MEDIUM",
            status="PARTIALLY_CONFIRMED",
            reachability="CONFIRMED",
            protocol="LIKELY",
            exposure="UNKNOWN",
            authentication="UNKNOWN",
            transport="TCP",
            summary=(
                "smbclient completed successfully, but no parseable "
                "anonymous share listing was returned."
            ),
            details=details + [
                "smbclient completed without a parseable share listing.",
                combined[:1000] or "No smbclient output was returned.",
            ],
            metadata=metadata,
        )

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
            "SMB port is reachable, but anonymous enumeration returned "
            "an inconclusive result."
        ),
        details=details + [
            combined[:1000] or "No smbclient output was returned.",
        ],
        metadata=metadata,
    )
