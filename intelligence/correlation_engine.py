from collections import Counter, defaultdict

SMART_CORRELATIONS = [
    {
        "id": "WINDOWS_LATERAL_MOVEMENT_SURFACE",
        "name": "Windows lateral movement surface",
        "severity": "HIGH",
        "confidence_base": 72,
        "requires_any": ["SMB_EXPOSED", "NETBIOS_SMB_EXPOSED"],
        "requires_related": ["RDP_EXPOSED", "LDAP_EXPOSED", "LDAPS_EXPOSED", "KERBEROS_EXPOSED", "LDAP_GLOBAL_CATALOG_EXPOSED", "LDAPS_GLOBAL_CATALOG_EXPOSED"],
        "why_it_matters": "SMB combined with remote administration or identity services can support enumeration, credential reuse, and lateral movement across Windows environments.",
        "analyst_questions": [
            "Are these hosts restricted to an administrative VLAN or VPN?",
            "Is SMB signing enforced?",
            "Are local administrator passwords unique across hosts?",
            "Is RDP protected by MFA or gateway access?"
        ],
        "recommended_focus": [
            "Confirm SMB and RDP exposure scope.",
            "Review segmentation between user workstations and administrative systems.",
            "Prioritize hosts that expose both file sharing and remote desktop."
        ]
    },
    {
        "id": "IDENTITY_INFRASTRUCTURE_EXPOSURE",
        "name": "Identity infrastructure exposure",
        "severity": "HIGH",
        "confidence_base": 78,
        "requires_any": ["KERBEROS_EXPOSED", "LDAP_EXPOSED", "LDAPS_EXPOSED"],
        "requires_related": ["SMB_EXPOSED", "LDAP_GLOBAL_CATALOG_EXPOSED", "LDAPS_GLOBAL_CATALOG_EXPOSED"],
        "why_it_matters": "Identity infrastructure is high-value because compromise or excessive exposure may affect authentication, authorization, and access across the environment.",
        "analyst_questions": [
            "Is this host a domain controller?",
            "Are anonymous LDAP binds disabled?",
            "Is access limited to trusted internal subnets?",
            "Are authentication logs monitored for enumeration attempts?"
        ],
        "recommended_focus": [
            "Validate whether the host is an Active Directory component.",
            "Review directory service exposure and access controls.",
            "Check whether identity services are reachable outside expected network zones."
        ]
    },
    {
        "id": "REMOTE_ACCESS_CLUSTER",
        "name": "Remote access exposure cluster",
        "severity": "HIGH",
        "confidence_base": 68,
        "minimum_count": 2,
        "services": ["SSH_EXPOSED", "RDP_EXPOSED", "TELNET_EXPOSED", "VNC_EXPOSED"],
        "why_it_matters": "Multiple remote access services increase the number of authentication surfaces attackers can target and may reveal inconsistent access controls.",
        "analyst_questions": [
            "Which remote access services are actually required?",
            "Are all remote access paths protected by MFA or VPN?",
            "Are failed login attempts monitored?",
            "Are default or shared credentials still in use?"
        ],
        "recommended_focus": [
            "Reduce unnecessary remote access surfaces.",
            "Prioritize plaintext or weakly protected services first.",
            "Standardize administrative access through a controlled path."
        ]
    },
    {
        "id": "DATA_SERVICES_CLUSTER",
        "name": "Exposed data services cluster",
        "severity": "HIGH",
        "confidence_base": 70,
        "minimum_count": 2,
        "services": ["MSSQL_EXPOSED", "MYSQL_EXPOSED", "POSTGRES_EXPOSED", "REDIS_EXPOSED", "MONGODB_EXPOSED", "ELASTICSEARCH_EXPOSED", "ORACLE_EXPOSED"],
        "why_it_matters": "Multiple exposed data services can increase blast radius because application data, logs, credentials, or operational records may be reachable from more places than intended.",
        "analyst_questions": [
            "Are database ports reachable only from application servers?",
            "Is authentication required on every data service?",
            "Are sensitive datasets exposed through search or logging systems?",
            "Is database access monitored?"
        ],
        "recommended_focus": [
            "Confirm database network exposure boundaries.",
            "Prioritize unauthenticated or validation-confirmed data services.",
            "Review whether any data service is reachable from user or guest networks."
        ]
    },
    {
        "id": "CICD_TO_CONTAINER_CONTROL_PATH",
        "name": "CI/CD to container infrastructure pathway",
        "severity": "CRITICAL",
        "confidence_base": 88,
        "requires_any": ["JENKINS_EXPOSED"],
        "requires_related": ["DOCKER_API_EXPOSED", "DOCKER_TLS_EXPOSED", "PORTAINER_EXPOSED", "PORTAINER_HTTPS_EXPOSED", "KUBERNETES_API_EXPOSED", "KUBELET_EXPOSED", "KUBELET_READONLY_EXPOSED"],
        "why_it_matters": "Build systems often hold deployment credentials and automation permissions. If CI/CD exposure overlaps with container control surfaces, compromise could move from code/build access to infrastructure control.",
        "analyst_questions": [
            "Does Jenkins store deployment secrets or cloud credentials?",
            "Can the CI/CD server reach Docker or Kubernetes APIs?",
            "Is container management restricted to administrative systems?",
            "Are build agents isolated from production infrastructure?"
        ],
        "recommended_focus": [
            "Review CI/CD authentication and authorization.",
            "Confirm container APIs require strong authentication.",
            "Check whether build systems can administer runtime infrastructure."
        ]
    },
    {
        "id": "ELK_LOGGING_EXPOSURE",
        "name": "Elastic/Kibana logging exposure",
        "severity": "HIGH",
        "confidence_base": 74,
        "requires_any": ["ELASTICSEARCH_EXPOSED", "ELASTICSEARCH_TRANSPORT_EXPOSED"],
        "requires_related": ["KIBANA_EXPOSED"],
        "why_it_matters": "Logging stacks may contain usernames, internal hostnames, application errors, request data, tokens, or operational details useful for deeper attack planning.",
        "analyst_questions": [
            "Does Kibana require authentication?",
            "Do Elasticsearch indices contain sensitive logs?",
            "Is access limited to monitoring administrators?",
            "Are logs sanitized for secrets or tokens?"
        ],
        "recommended_focus": [
            "Validate authentication on Kibana and Elasticsearch.",
            "Review exposed indices and dashboard permissions.",
            "Restrict log infrastructure to trusted networks."
        ]
    },
    {
        "id": "MONITORING_VISIBILITY_CLUSTER",
        "name": "Monitoring visibility cluster",
        "severity": "MEDIUM",
        "confidence_base": 58,
        "minimum_count": 2,
        "services": ["GRAFANA_EXPOSED", "PROMETHEUS_EXPOSED", "KIBANA_EXPOSED"],
        "why_it_matters": "Monitoring systems can reveal internal service names, targets, uptime, software stacks, and operational patterns even when they do not directly provide system access.",
        "analyst_questions": [
            "Are dashboards authenticated?",
            "Can users view data sources or credentials?",
            "Do metrics reveal internal target names?",
            "Are monitoring tools segmented from general user networks?"
        ],
        "recommended_focus": [
            "Review anonymous dashboard access.",
            "Restrict monitoring tools to operations networks.",
            "Check whether metrics expose sensitive infrastructure metadata."
        ]
    },
    {
        "id": "LEGACY_PLAINTEXT_EXPOSURE",
        "name": "Legacy plaintext protocol exposure",
        "severity": "HIGH",
        "confidence_base": 82,
        "minimum_count": 1,
        "services": ["TELNET_EXPOSED", "FTP_EXPOSED", "POP3_EXPOSED", "IMAP_EXPOSED"],
        "why_it_matters": "Legacy plaintext protocols can expose credentials or sensitive data in transit and often indicate older devices or unmanaged systems.",
        "analyst_questions": [
            "Is this service still required?",
            "Can it be replaced with an encrypted alternative?",
            "Is the service limited to a trusted subnet?",
            "Does the host represent legacy or unmanaged equipment?"
        ],
        "recommended_focus": [
            "Prioritize Telnet and FTP first.",
            "Identify owning team or device class.",
            "Replace plaintext management protocols where feasible."
        ]
    },
    {
        "id": "IOT_CAMERA_MANAGEMENT_SURFACE",
        "name": "IoT/camera management surface",
        "severity": "MEDIUM",
        "confidence_base": 60,
        "requires_any": ["RTSP_EXPOSED"],
        "requires_related": ["HTTP_EXPOSED", "HTTPS_EXPOSED", "TR069_EXPOSED"],
        "why_it_matters": "RTSP plus web or CPE management interfaces may indicate cameras, DVRs, or embedded devices that often have weak patching and default credential risk.",
        "analyst_questions": [
            "Is this host a camera, DVR, or embedded appliance?",
            "Are default credentials disabled?",
            "Is firmware current?",
            "Is the device isolated from user and server networks?"
        ],
        "recommended_focus": [
            "Confirm device ownership and purpose.",
            "Restrict camera and IoT systems to dedicated segments.",
            "Review web management and stream access controls."
        ]
    },
    {
        "id": "PRINTER_INFRASTRUCTURE_SURFACE",
        "name": "Printer infrastructure surface",
        "severity": "LOW",
        "confidence_base": 45,
        "minimum_count": 1,
        "services": ["PRINTER_9100_EXPOSED", "IPP_EXPOSED"],
        "why_it_matters": "Printer services are usually lower severity but can still reveal device information, enable unauthorized printing, or expose outdated embedded systems.",
        "analyst_questions": [
            "Are printers reachable from non-print-server subnets?",
            "Are printer admin panels protected?",
            "Is firmware maintained?",
            "Are unnecessary print protocols disabled?"
        ],
        "recommended_focus": [
            "Restrict printer access to print servers and trusted users.",
            "Disable unused print protocols.",
            "Inventory printer devices and firmware versions."
        ]
    }
]

ROLE_SIGNATURES = [
    {
        "role": "Likely Active Directory Domain Controller",
        "confidence_base": 85,
        "services_any": ["KERBEROS_EXPOSED", "LDAP_EXPOSED", "LDAPS_EXPOSED", "LDAP_GLOBAL_CATALOG_EXPOSED", "LDAPS_GLOBAL_CATALOG_EXPOSED"],
        "services_related": ["SMB_EXPOSED"],
        "why": "Identity and SMB services together are strongly associated with Windows domain infrastructure.",
        "questions": ["Is this host expected to provide domain services?", "Is it reachable outside the server/admin network?"]
    },
    {
        "role": "Likely Windows Administrative Host",
        "confidence_base": 72,
        "services_any": ["SMB_EXPOSED", "NETBIOS_SMB_EXPOSED"],
        "services_related": ["RDP_EXPOSED"],
        "why": "SMB and RDP together often indicate a Windows host that supports remote administration.",
        "questions": ["Is RDP required?", "Are administrative accounts protected by MFA or gateway access?"]
    },
    {
        "role": "Likely Container Infrastructure",
        "confidence_base": 88,
        "services_any": ["DOCKER_API_EXPOSED", "DOCKER_TLS_EXPOSED", "PORTAINER_EXPOSED", "PORTAINER_HTTPS_EXPOSED"],
        "services_related": [],
        "why": "Docker or container management ports indicate infrastructure that may control workloads or host-level resources.",
        "questions": ["Is remote container administration expected?", "Is access restricted and authenticated?"]
    },
    {
        "role": "Likely Kubernetes Infrastructure",
        "confidence_base": 88,
        "services_any": ["KUBERNETES_API_EXPOSED", "KUBELET_EXPOSED", "KUBELET_READONLY_EXPOSED"],
        "services_related": [],
        "why": "Kubernetes API or kubelet services indicate cluster control-plane or node exposure.",
        "questions": ["Is the Kubernetes API limited to admins?", "Are kubelet anonymous endpoints disabled?"]
    },
    {
        "role": "Likely Database Server",
        "confidence_base": 70,
        "services_any": ["MSSQL_EXPOSED", "MYSQL_EXPOSED", "POSTGRES_EXPOSED", "REDIS_EXPOSED", "MONGODB_EXPOSED", "ORACLE_EXPOSED", "ELASTICSEARCH_EXPOSED"],
        "services_related": [],
        "why": "Database or data service ports suggest the host may store application or operational data.",
        "questions": ["Which applications require access?", "Is database access segmented from user networks?"]
    },
    {
        "role": "Likely Monitoring or Logging Host",
        "confidence_base": 68,
        "services_any": ["GRAFANA_EXPOSED", "PROMETHEUS_EXPOSED", "KIBANA_EXPOSED", "ELASTICSEARCH_EXPOSED"],
        "services_related": [],
        "why": "Monitoring and logging services suggest the host may expose infrastructure telemetry or operational data.",
        "questions": ["Are dashboards authenticated?", "Do logs or metrics reveal secrets or internal topology?"]
    },
    {
        "role": "Likely Printer or Print Server",
        "confidence_base": 82,
        "services_any": ["PRINTER_9100_EXPOSED", "IPP_EXPOSED"],
        "services_related": [],
        "why": "Raw print or IPP services are common on network printers and print servers.",
        "questions": ["Is this device isolated to a printer VLAN?", "Are admin interfaces restricted?"]
    },
    {
        "role": "Likely Camera or Embedded Device",
        "confidence_base": 76,
        "services_any": ["RTSP_EXPOSED", "TR069_EXPOSED", "ADB_EXPOSED"],
        "services_related": ["HTTP_EXPOSED", "HTTPS_EXPOSED"],
        "why": "Streaming, CPE management, or debug interfaces suggest embedded or IoT device exposure.",
        "questions": ["Is firmware current?", "Are default credentials removed?", "Is the device segmented?"]
    }
]


def severity_rank(severity):
    return {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0
    }.get(severity, 0)


def flatten_findings(netsniper_data, prioritized_findings=None):
    validation_lookup = {}

    if prioritized_findings:
        for item in prioritized_findings:
            validation_lookup[(item["host"], item["finding_id"], item["port"])] = item

    flattened = []

    for host_entry in netsniper_data:
        host = host_entry.get("host", "Unknown")
        device_type = host_entry.get("device_type", "Unknown")

        for finding in host_entry.get("findings", []):
            finding_id = finding.get("id", "UNKNOWN")
            port = int(finding.get("port", 0) or 0)
            enriched = validation_lookup.get((host, finding_id, port), {})

            flattened.append({
                "host": host,
                "device_type": device_type,
                "finding_id": finding_id,
                "name": finding.get("name", finding_id),
                "service": finding.get("service", "unknown"),
                "port": port,
                "validation_status": enriched.get("validation_status", "NOT VALIDATED"),
                "priority_label": enriched.get("priority_label", "UNKNOWN"),
                "priority_score": enriched.get("priority_score", 0)
            })

    return flattened


def by_host(flattened):
    grouped = defaultdict(list)
    for item in flattened:
        grouped[item["host"]].append(item)
    return grouped


def confidence_from_validation(findings, matched_ids, base):
    """
    Adjust correlation confidence using structured validation evidence.
    """

    statuses = Counter(
        item["validation_status"]
        for item in findings
        if item["finding_id"] in matched_ids
    )

    weights = {
        "CONFIRMED": 8,
        "PROTECTED": 5,
        "PARTIALLY CONFIRMED": 4,
        "REACHABLE": 2,
        "DEPENDENCY MISSING": 0,
        "TIMEOUT": -1,
        "INCONCLUSIVE": -1,
        "PROTOCOL MISMATCH": -8,
        "NOT REACHABLE": -6,
        "UNKNOWN": 0,
        "NOT VALIDATED": 0,
    }

    confidence = base

    for status, count in statuses.items():
        confidence += weights.get(status, 0) * count

    return max(
        0,
        min(100, confidence),
    )

def rule_matches(rule, findings):
    ids = [item["finding_id"] for item in findings]
    id_set = set(ids)

    if "minimum_count" in rule:
        count = sum(1 for item in ids if item in set(rule.get("services", [])))
        if count >= rule["minimum_count"]:
            return sorted(id_set.intersection(set(rule.get("services", []))))
        return []

    any_matches = id_set.intersection(set(rule.get("requires_any", [])))
    related_matches = id_set.intersection(set(rule.get("requires_related", [])))

    if rule.get("requires_related"):
        if any_matches and related_matches:
            return sorted(any_matches.union(related_matches))
        return []

    if any_matches:
        return sorted(any_matches)

    return []


def infer_host_roles(flattened):
    results = []
    grouped = by_host(flattened)

    for host, findings in grouped.items():
        id_set = {item["finding_id"] for item in findings}

        for role in ROLE_SIGNATURES:
            any_matches = id_set.intersection(set(role.get("services_any", [])))
            related_required = set(role.get("services_related", []))
            related_matches = id_set.intersection(related_required)

            if not any_matches:
                continue

            if related_required and not related_matches:
                continue

            matched = sorted(any_matches.union(related_matches))
            confidence = confidence_from_validation(findings, matched, role["confidence_base"])

            results.append({
                "host": host,
                "role": role["role"],
                "confidence": confidence,
                "matched_findings": matched,
                "why": role["why"],
                "analyst_questions": role["questions"]
            })

    return sorted(results, key=lambda item: item["confidence"], reverse=True)


def correlate_attack_surface(netsniper_data, prioritized_findings=None):
    flattened = flatten_findings(netsniper_data, prioritized_findings)
    grouped = by_host(flattened)

    correlations = []

    for host, findings in grouped.items():
        for rule in SMART_CORRELATIONS:
            matched = rule_matches(rule, findings)
            if not matched:
                continue

            confidence = confidence_from_validation(findings, matched, rule["confidence_base"])
            correlations.append({
                "id": rule["id"],
                "name": rule["name"],
                "host": host,
                "severity": rule["severity"],
                "confidence": confidence,
                "matched_findings": matched,
                "why_it_matters": rule["why_it_matters"],
                "analyst_questions": rule["analyst_questions"],
                "recommended_focus": rule["recommended_focus"],
                "validation_context": dict(Counter(
                    item["validation_status"]
                    for item in findings
                    if item["finding_id"] in matched
                ))
            })

    return sorted(
        correlations,
        key=lambda item: (severity_rank(item["severity"]), item["confidence"]),
        reverse=True
    )


def build_environment_profile(netsniper_data, prioritized_findings=None):
    flattened = flatten_findings(netsniper_data, prioritized_findings)

    device_types = Counter()
    service_counts = Counter()
    finding_counts = Counter()
    validation_counts = Counter()
    priority_counts = Counter()
    category_guess = Counter()

    hosts = set()

    for host_entry in netsniper_data:
        host = host_entry.get("host", "Unknown")
        hosts.add(host)
        device_types[host_entry.get("device_type", "Unknown")] += 1

    for finding in flattened:
        service_counts[finding["service"]] += 1
        finding_counts[finding["finding_id"]] += 1
        validation_counts[finding["validation_status"]] += 1
        priority_counts[finding["priority_label"]] += 1

    roles = infer_host_roles(flattened)
    for role in roles:
        category_guess[role["role"]] += 1

    return {
        "host_count": len(hosts),
        "device_types": dict(device_types),
        "service_counts": dict(service_counts),
        "finding_counts": dict(finding_counts),
        "validation_counts": dict(validation_counts),
        "priority_counts": dict(priority_counts),
        "inferred_roles": roles,
        "role_counts": dict(category_guess)
    }


def build_attack_surface_narrative(profile, correlations):
    host_count = profile.get("host_count", 0)
    services = Counter(profile.get("service_counts", {}))
    roles = Counter(profile.get("role_counts", {}))
    validation = Counter(profile.get("validation_counts", {}))

    top_services = ", ".join(name for name, _ in services.most_common(5)) or "no dominant exposed services"
    top_roles = ", ".join(name for name, _ in roles.most_common(3)) or "no strong inferred roles"

    confirmed = validation.get("CONFIRMED", 0)
    partial = validation.get("PARTIALLY CONFIRMED", 0)
    reachable = validation.get("REACHABLE", 0)

    if correlations:
        strongest = correlations[0]
        strongest_text = (
            f"The strongest relationship is '{strongest['name']}' on {strongest['host']} "
            f"with {strongest['confidence']}% confidence."
        )
        why = strongest.get("why_it_matters", "")
    else:
        strongest_text = "No multi-finding attack surface relationships were detected."
        why = "The current dataset may still contain individual exposures that require review."

    return (
        f"The environment contains {host_count} host(s). The most common observed services are {top_services}. "
        f"Inferred roles include {top_roles}. Validation context shows {confirmed} confirmed finding(s), "
        f"{partial} partially confirmed finding(s), and {reachable} reachable finding(s). "
        f"{strongest_text} {why}"
    )


def build_recommended_questions(correlations, roles):
    questions = []

    for item in correlations[:5]:
        for question in item.get("analyst_questions", []):
            questions.append({
                "source": item["name"],
                "host": item.get("host", "environment"),
                "question": question
            })

    for role in roles[:5]:
        for question in role.get("analyst_questions", []):
            questions.append({
                "source": role["role"],
                "host": role.get("host", "environment"),
                "question": question
            })

    seen = set()
    unique = []
    for item in questions:
        key = (item["host"], item["question"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    return unique[:12]


def build_intelligence(netsniper_data, prioritized_findings=None):
    profile = build_environment_profile(netsniper_data, prioritized_findings)
    correlations = correlate_attack_surface(netsniper_data, prioritized_findings)
    narrative = build_attack_surface_narrative(profile, correlations)
    questions = build_recommended_questions(correlations, profile.get("inferred_roles", []))

    return {
        "profile": profile,
        "correlations": correlations,
        "narrative": narrative,
        "recommended_questions": questions,
        "inferred_roles": profile.get("inferred_roles", [])
    }
