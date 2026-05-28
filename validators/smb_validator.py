from .common import ValidationResult, tcp_connect, run_command


def validate(host: str, port: int = 445, finding_id: str = "SMB_EXPOSED") -> ValidationResult:
    details = []

    if not tcp_connect(host, port):
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=False,
            confidence="NONE",
            summary="SMB port is not reachable from this system.",
            details=["TCP connection failed."]
        )

    details.append("TCP connection to SMB port succeeded.")

    rc, stdout, stderr = run_command(["smbclient", "-L", f"//{host}", "-N"], timeout=10)

    if rc == 127:
        details.append("smbclient is not installed; anonymous share validation skipped.")
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="LOW",
            summary="SMB is reachable, but anonymous access could not be tested because smbclient is missing.",
            details=details
        )

    combined = f"{stdout}\n{stderr}".lower()

    if "sharename" in combined or "disk" in combined:
        details.append("Anonymous SMB listing returned share information.")
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="HIGH",
            summary="SMB is reachable and may allow anonymous share enumeration.",
            details=details
        )

    if "access denied" in combined or "logon failure" in combined or "nt_status" in combined:
        details.append("Anonymous SMB listing did not succeed.")
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="MEDIUM",
            summary="SMB is reachable, but anonymous share enumeration was not confirmed.",
            details=details
        )

    details.append("SMB anonymous check returned inconclusive output.")
    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=True,
        confidence="LOW",
        summary="SMB is reachable, but validation was inconclusive.",
        details=details
    )
