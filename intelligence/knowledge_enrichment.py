import json
import random
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
KNOWLEDGE_DIR = BASE_DIR / "knowledge"
EXPOSURE_DB = BASE_DIR / "remediations" / "exposures.json"
SERVICE_DB = KNOWLEDGE_DIR / "services.json"
CORRELATION_DB = KNOWLEDGE_DIR / "correlations.json"
ROLE_DB = KNOWLEDGE_DIR / "role_signatures.json"
LANGUAGE_DB = KNOWLEDGE_DIR / "report_language.json"


def load_json(path):
    with open(path, "r") as file:
        return json.load(file)


def load_knowledge():
    return {
        "exposures": load_json(EXPOSURE_DB),
        "services": load_json(SERVICE_DB),
        "correlations": load_json(CORRELATION_DB),
        "roles": load_json(ROLE_DB),
        "language": load_json(LANGUAGE_DB)
    }


def pick_variant(options, seed=None):
    if not options:
        return ""
    rng = random.Random(seed)
    return rng.choice(options)


def enrich_finding(finding_id, validation_status="NOT VALIDATED", seed=None):
    kb = load_knowledge()
    exposure = kb["exposures"].get(finding_id, {})
    language = kb["language"]

    exec_variants = exposure.get("report_variants", {}).get("executive", [])
    tech_variants = exposure.get("report_variants", {}).get("technical", [])
    validation_variants = language.get("validation_phrases", {}).get(validation_status, [])

    return {
        "finding_id": finding_id,
        "display_name": exposure.get("display_name", finding_id),
        "category": exposure.get("category", "Unknown"),
        "business_context": exposure.get("business_context", ""),
        "executive_sentence": pick_variant(exec_variants, seed=f"{seed}-exec"),
        "technical_sentence": pick_variant(tech_variants, seed=f"{seed}-tech"),
        "validation_sentence": pick_variant(validation_variants, seed=f"{seed}-validation"),
        "risk_themes": exposure.get("threats", []),
        "safe_validation": exposure.get("safe_validation", [])
    }
