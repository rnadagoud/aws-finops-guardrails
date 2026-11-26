from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class Finding:
    check_id: str
    category: str
    severity: str  # "HIGH" | "MEDIUM" | "LOW"
    resource_id: str
    region: str
    estimated_monthly_savings_usd: float
    summary: str
    remediation_cli: str

    @property
    def estimated_annual_savings_usd(self) -> float:
        return round(self.estimated_monthly_savings_usd * 12.0, 2)


@dataclass
class AuditSummary:
    account_id: str
    regions_scanned: list[str]
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    )
    mode: str = "live"
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_monthly_savings_usd(self) -> float:
        return round(sum(f.estimated_monthly_savings_usd for f in self.findings), 2)

    @property
    def total_annual_savings_usd(self) -> float:
        return round(self.total_monthly_savings_usd * 12.0, 2)

    def sorted_findings(self) -> list[Finding]:
        severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        return sorted(
            self.findings,
            key=lambda f: (
                severity_rank.get(f.severity, 3),
                -f.estimated_monthly_savings_usd,
            ),
        )
