from . import redis_validator
from . import docker_validator
from . import http_validator
from . import mongodb_validator
from . import smb_validator
from .common import ValidationResult, tcp_connect


VALIDATOR_MAP = {
    "REDIS_EXPOSED": redis_validator.validate,
    "DOCKER_API_EXPOSED": docker_validator.validate,
    "HTTP_EXPOSED": http_validator.validate,
    "HTTPS_EXPOSED": http_validator.validate,
    "JENKINS_EXPOSED": http_validator.validate,
    "PORTAINER_EXPOSED": http_validator.validate,
    "KIBANA_EXPOSED": http_validator.validate,
    "MONGODB_EXPOSED": mongodb_validator.validate,
    "SMB_EXPOSED": smb_validator.validate
}


def generic_tcp_validator(host: str, port: int, finding_id: str) -> ValidationResult:
    if tcp_connect(host, port):
        return ValidationResult(
            finding_id=finding_id,
            host=host,
            port=port,
            validated=True,
            confidence="LOW",
            summary="Port is reachable. No service-specific validator is available yet.",
            details=["Generic TCP connection succeeded."]
        )

    return ValidationResult(
        finding_id=finding_id,
        host=host,
        port=port,
        validated=False,
        confidence="NONE",
        summary="Port is not reachable from this system.",
        details=["Generic TCP connection failed."]
    )


def validate_finding(host: str, finding: dict) -> dict:
    finding_id = finding.get("id", "UNKNOWN")
    port = int(finding.get("port", 0) or 0)

    validator = VALIDATOR_MAP.get(finding_id)

    if validator:
        result = validator(host=host, port=port, finding_id=finding_id)
    else:
        result = generic_tcp_validator(host=host, port=port, finding_id=finding_id)

    return result.to_dict()


def validate_dataset(netsniper_data: list) -> list:
    results = []

    for host_entry in netsniper_data:
        host = host_entry.get("host", "Unknown")

        for finding in host_entry.get("findings", []):
            results.append(validate_finding(host, finding))

    return results
