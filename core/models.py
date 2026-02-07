from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    account_id: str
    region: Optional[str]
    domain: str
    control_id: str
    severity: str
    resource: str
    title: str
    finding: str
    remediation: str
    evidence: Dict[str, Any]
    resource_type: Optional[str] = None
    display_name: Optional[str] = None
    risk_category: Optional[str] = None
    confidence: Optional[str] = None
    references: Optional[List[str]] = field(default_factory=list)
    is_exception: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
