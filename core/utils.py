from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

import botocore


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_tz(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def safe_call(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Tuple[Optional[Any], Optional[Exception]]:
    try:
        return func(*args, **kwargs), None
    except botocore.exceptions.ClientError as exc:
        return None, exc
    except Exception as exc:  # defensive
        return None, exc


def is_access_denied(exc: Exception) -> bool:
    if not isinstance(exc, botocore.exceptions.ClientError):
        return False
    code = exc.response.get("Error", {}).get("Code", "")
    return code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}


def counters_from_findings(findings: Iterable[Dict[str, Any]]) -> Tuple[Counter, Counter]:
    severity = Counter()
    domain = Counter()
    for f in findings:
        severity[f["severity"]] += 1
        domain[f["domain"]] += 1
    return severity, domain
