"""Shared connection-test result model for OIDC, health, and credential probes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class CheckStatus(str, Enum):
    OK = "ok"
    WARN = "warn"
    ERROR = "error"


@dataclass
class CheckStep:
    name: str
    status: CheckStatus
    message: str
    detail: dict | None = None  # never put secrets here


@dataclass
class ConnectionTestResult:
    resource_type: str
    resource_id: str | int
    overall_status: CheckStatus
    checks: list[CheckStep] = field(default_factory=list)
    tested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    latency_ms: int | None = None

    def to_api_dict(self) -> dict:
        return {
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "status": self.overall_status.value,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "message": c.message,
                }
                for c in self.checks
            ],
            "tested_at": self.tested_at.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "latency_ms": self.latency_ms,
        }


def overall_from_checks(checks: list[CheckStep]) -> CheckStatus:
    """error > warn > ok — worst status wins."""
    if any(c.status == CheckStatus.ERROR for c in checks):
        return CheckStatus.ERROR
    if any(c.status == CheckStatus.WARN for c in checks):
        return CheckStatus.WARN
    return CheckStatus.OK
