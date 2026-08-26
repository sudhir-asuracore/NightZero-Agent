from __future__ import annotations

import os
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
    DEPLOYED = "DEPLOYED"


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
    occurrence_count: int = 1
    last_seen_at: str = ""
    error_signature: str = ""

    @classmethod
    def from_issue(cls, issue_number: int, title: str, **metadata: str) -> "IncidentContext":
        identifier = uuid4().hex[:12]
        repo = metadata.pop("repository", "") or os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "") or "default/repo"
        return cls(
            incident_id=f"inc-{identifier}",
            session_id=f"incident-{identifier}",
            issue_number=issue_number,
            title=title,
            service=metadata.pop("service", "target-service"),
            severity=metadata.pop("severity", "HIGH"),
            source_commit=metadata.pop("source_commit", "latest"),
            created_at=datetime.now(UTC).isoformat(),
            repository=repo,
            **metadata,
        )


@dataclass
class Evidence:
    kind: str
    source: str
    detail: str


@dataclass
class TimelineEvent:
    timestamp: str
    phase: str  # "PRECURSOR" | "TRIGGER" | "FAILURE" | "DETECTION"
    event: str
    source: str
    details: str = ""


@dataclass
class GitAttribution:
    author: str
    commit_sha: str
    commit_message: str
    pr_number: int | None = None
    pr_title: str = ""
    pr_url: str = ""
    changed_file: str = ""
    merged_at: str = ""


@dataclass
class TestGapAnalysis:
    why_tests_missed: str
    blindspot_summary: str
    recommended_test_name: str
    recommended_test_code: str


@dataclass
class BlastRadius:
    impacted_endpoints: list[str] = field(default_factory=list)
    failure_rate: str = ""
    affected_services: list[str] = field(default_factory=list)


@dataclass
class RootCauseAnalysis:
    root_cause: str
    confidence: float
    culprit_commit: str
    proposed_patch: str
    replacement: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    timeline_trail: list[TimelineEvent] = field(default_factory=list)
    attribution: GitAttribution | None = None
    test_gap_analysis: TestGapAnalysis | None = None
    blast_radius: BlastRadius | None = None


@dataclass(frozen=True)
class InvestigationProposal:
    root_cause: str
    confidence: float
    proposed_patch: str
    file_path: str
    replacement: str
    timeline_trail: list[TimelineEvent] = field(default_factory=list)
    attribution: GitAttribution | None = None
    test_gap_analysis: TestGapAnalysis | None = None
    blast_radius: BlastRadius | None = None


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
    spiffe_id: str = ""
    signature: str = ""
    armor_sanitized: bool = False


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
        rca = None
        if rca_val:
            evidence_list = [Evidence(**item) for item in rca_val.get("evidence", [])]
            timeline_list = [TimelineEvent(**item) for item in rca_val.get("timeline_trail", [])]
            
            attr_val = rca_val.get("attribution")
            attribution = GitAttribution(**attr_val) if attr_val else None
            
            gap_val = rca_val.get("test_gap_analysis")
            test_gap = TestGapAnalysis(**gap_val) if gap_val else None
            
            blast_val = rca_val.get("blast_radius")
            blast_radius = BlastRadius(**blast_val) if blast_val else None

            rca = RootCauseAnalysis(
                root_cause=rca_val.get("root_cause", ""),
                confidence=float(rca_val.get("confidence", 0.0)),
                culprit_commit=rca_val.get("culprit_commit", ""),
                proposed_patch=rca_val.get("proposed_patch", ""),
                replacement=rca_val.get("replacement", ""),
                evidence=evidence_list,
                timeline_trail=timeline_list,
                attribution=attribution,
                test_gap_analysis=test_gap,
                blast_radius=blast_radius,
            )

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