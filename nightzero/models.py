from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4


class IncidentStatus(StrEnum):
    IDLE = "IDLE"
    INGESTING = "INGESTING"
    RCA = "RCA"
    PATCHING = "PATCHING"
    SANDBOX_TESTING = "SANDBOX_TESTING"
    TRIAGED = "TRIAGED"
    STAGING_VERIFIED = "STAGING_VERIFIED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    PR_CREATION_FAILED = "PR_CREATION_FAILED"
    RESOLVED = "RESOLVED"


@dataclass
class IncidentContext:
    incident_id: str
    session_id: str
    issue_number: int
    title: str
    service: str
    severity: str
    source_commit: str
    created_at: str
    status: IncidentStatus = IncidentStatus.TRIAGED
    issue_url: str = ""
    repository: str = ""
    repository_ref: str = ""
    delivery_id: str = ""

    @classmethod
    def from_issue(cls, issue_number: int, title: str, **metadata: str) -> "IncidentContext":
        identifier = uuid4().hex[:12]
        return cls(
            incident_id=f"inc-{identifier}",
            session_id=f"incident-{identifier}",
            issue_number=issue_number,
            title=title,
            service="demo_target",
            severity="HIGH",
            source_commit="8f3c2a1",
            created_at=datetime.now(UTC).isoformat(),
            **metadata,
        )


@dataclass
class Evidence:
    kind: str
    source: str
    detail: str


@dataclass
class RootCauseAnalysis:
    root_cause: str
    confidence: float
    culprit_commit: str
    proposed_patch: str
    evidence: list[Evidence]


@dataclass(frozen=True)
class InvestigationProposal:
    root_cause: str
    confidence: float
    proposed_patch: str
    file_path: str
    replacement: str


@dataclass
class CommandResult:
    command: list[str]
    exit_code: int
    output: str


@dataclass
class RemediationVerificationReport:
    sandbox_id: str
    branch_name: str
    file_path: str
    diff: str
    before: CommandResult
    after: CommandResult
    staging_status: str


@dataclass
class AuditEvent:
    action: str
    timestamp: str
    detail: str


@dataclass
class IncidentRecord:
    context: IncidentContext
    rca: RootCauseAnalysis | None
    verification: RemediationVerificationReport | None
    audit_events: list[AuditEvent] = field(default_factory=list)
    approval: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "IncidentRecord":
        context = value["context"]
        
        rca_val = value.get("rca")
        rca = RootCauseAnalysis(
            **{**rca_val, "evidence": [Evidence(**item) for item in rca_val.get("evidence", [])]}
        ) if rca_val else None

        verification_val = value.get("verification")
        verification = RemediationVerificationReport(
            **{
                **verification_val,
                "before": CommandResult(**verification_val["before"]),
                "after": CommandResult(**verification_val["after"]),
            }
        ) if verification_val else None

        return cls(
            context=IncidentContext(**{**context, "status": IncidentStatus(context["status"])}),
            rca=rca,
            verification=verification,
            audit_events=[AuditEvent(**item) for item in value.get("audit_events", [])],
            approval=value.get("approval"),
        )


def artifact_path(directory: Path, incident_id: str) -> Path:
    return directory / f"{incident_id}.json"