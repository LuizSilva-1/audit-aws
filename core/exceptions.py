from __future__ import annotations

from typing import Any, Dict, List

import os
import yaml

from core.models import Finding


def load_exceptions(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def apply_exceptions(findings: List[Finding], rules: Dict[str, Any]) -> List[Finding]:
    allowed_public_buckets = set(rules.get("allowed_public_s3_buckets", []) or [])
    for f in findings:
        if f.resource and "role/aws-service-role/" in f.resource:
            f.severity = "INFO"
            f.confidence = "ALTA"
            f.title = "Role vinculada a serviço AWS (service-linked role) - verificação informativa"
            f.is_exception = True
        if f.control_id == "S3-001" and f.resource in allowed_public_buckets:
            f.severity = "INFO"
            f.confidence = "ALTA"
            f.remediation = f.remediation + " Exceção: bucket permitido em exceptions.allowed_public_s3_buckets."
            f.is_exception = True
    return findings
