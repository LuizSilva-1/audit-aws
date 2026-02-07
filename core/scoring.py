from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List

from core.models import Finding


SEVERITY_PENALTY = {
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 3,
    "INFO": 0,
}

DOMAIN_WEIGHTS = {
    "security": 0.50,
    "iam": 0.30,
    "finops": 0.20,
}


def _penalty_for_severity(sev: str) -> int:
    return SEVERITY_PENALTY.get(sev, SEVERITY_PENALTY["LOW"])


def compute_score(findings: List[Finding]) -> Dict[str, Any]:
    domain_penalties: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(lambda: defaultdict(lambda: {"penalty": 0, "count": 0}))

    for f in findings:
        if f.is_exception:
            continue
        domain = f.domain
        control_id = f.control_id
        sev_penalty = _penalty_for_severity(f.severity)
        cap = sev_penalty * 2
        current = domain_penalties[domain][control_id]
        if current["penalty"] < cap:
            current["penalty"] = min(cap, current["penalty"] + sev_penalty)
        current["count"] += 1

    domain_scores: Dict[str, int] = {}
    penalties_list: Dict[str, List[Dict[str, Any]]] = {}

    for domain in ["security", "iam", "finops"]:
        penalties = domain_penalties.get(domain, {})
        total_penalty = sum(item["penalty"] for item in penalties.values())
        score = max(0, 100 - total_penalty)
        domain_scores[domain] = score
        penalties_list[domain] = [
            {"control_id": cid, "penalty": data["penalty"], "count": data["count"]}
            for cid, data in penalties.items()
        ]

    overall = round(
        domain_scores["security"] * DOMAIN_WEIGHTS["security"]
        + domain_scores["iam"] * DOMAIN_WEIGHTS["iam"]
        + domain_scores["finops"] * DOMAIN_WEIGHTS["finops"]
    )

    return {
        "overall": overall,
        "method": "weighted",
        "weights": DOMAIN_WEIGHTS,
        "domains": domain_scores,
        "penalties": penalties_list,
    }


def top_penalty_controls(score_obj: Dict[str, Any], findings: List[Finding], limit: int = 3) -> List[Dict[str, Any]]:
    title_by_control = {}
    for f in findings:
        if f.control_id not in title_by_control:
            title_by_control[f.control_id] = f.title

    aggregated: List[Dict[str, Any]] = []
    for domain, items in score_obj.get("penalties", {}).items():
        for item in items:
            aggregated.append(
                {
                    "control_id": item["control_id"],
                    "penalty": item["penalty"],
                    "count": item["count"],
                    "title": title_by_control.get(item["control_id"], ""),
                }
            )
    aggregated.sort(key=lambda x: x["penalty"], reverse=True)
    return aggregated[:limit]
