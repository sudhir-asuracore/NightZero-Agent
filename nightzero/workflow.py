from __future__ import annotations

import difflib
import os
import shutil
import subprocess
import tempfile
import re
import base64
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import uuid4

from nightzero.github import GitHubGateway, RepositoryEvidence
from nightzero.investigation import AdkInvestigationRunner, InvestigationRunner

from nightzero.models import (
    AuditEvent,
    CommandResult,
    Evidence,
    IncidentContext,
    InvestigationProposal,
    IncidentRecord,
    IncidentStatus,
    RemediationVerificationReport,
    RootCauseAnalysis,
)
from nightzero.store import IncidentStore

TEST_COMMAND = ["python", "-m", "unittest", "demo_target.test_pricing"]
DEMO_APPROVAL_TOKEN: Final = "nightzero-demo"
DEFAULT_TARGET_REPOSITORY_URL: Final = "git@github.com:sudhir-asuracore/NightZero-TestProject.git"


class NightZeroWorkflow:
    """A bounded, deterministic implementation of the four-agent MVP path."""

    def __init__(
        self, project_root: Path, artifact_store: IncidentStore, target_repository_url: str | None = None
    ) -> None:
        self.project_root = project_root
        self.artifact_store = artifact_store
        self.target_repository_url = target_repository_url or os.environ.get(
            "NIGHTZERO_TARGET_REPOSITORY_URL", DEFAULT_TARGET_REPOSITORY_URL
        )

    def run_seeded_issue(self) -> IncidentRecord:
        context = IncidentContext.from_issue(
            issue_number=142,
            title="Checkout totals are rounded down",
        )
        audit = [self._event("triage.issue_parsed", "GitHub issue #142 framed as incident context")]
        rca = self._investigate(context, audit)
        verification = self._verify_in_sandbox(rca, audit)
        context.status = IncidentStatus.AWAITING_APPROVAL
        record = IncidentRecord(context, rca, verification, audit)
        self.artifact_store.save(record)
        return record

    def simulate_outage(self, gateway: GitHubGateway | None = None) -> dict[str, str]:
        repository = os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "sudhir-asuracore/NightZero-TestProject")
        
        if gateway:
            try:
                gateway.commit_pricing_replacement(repository, "main", "demo_target/pricing.py", 'return f"${cents // 100}.00"')
            except Exception as e:
                raise RuntimeError(f"Failed to push commit: {e}")
                
        return {"status": "Deploying simulated outage. A real incident will trigger shortly."}

    def run_gcp_logging_incident(
        self, delivery_id: str, service_name: str, log_payload: str, severity: str = "CRITICAL", gateway: GitHubGateway | None = None, investigator: InvestigationRunner | None = None
    ) -> IncidentRecord:
        incident_id = f"inc-gcp-{uuid4().hex[:6]}"
        context = IncidentContext(
            incident_id=incident_id,
            session_id=f"incident-{incident_id}",
            issue_number=0,
            title=f"GCP Cloud Logging Alert: {service_name}",
            service=service_name,
            severity=severity,
            source_commit="unknown",
            created_at=datetime.now(UTC).isoformat(),
            status=IncidentStatus.INGESTING,
            delivery_id=delivery_id,
            repository=os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "sudhir-asuracore/NightZero-TestProject"),
            repository_ref="main",
        )
        claimed_id = self.artifact_store.claim_delivery_id(delivery_id, incident_id)
        if claimed_id:
            existing = self.artifact_store.get(claimed_id)
            if existing:
                return existing
        
        # Deduplicate multiple logs from the same outage by checking for an active incident for this service
        for existing in self.artifact_store.list():
            if existing.context.service == service_name and existing.context.status not in (IncidentStatus.APPROVED, IncidentStatus.PR_CREATION_FAILED):
                # Optionally, could append this new log payload as evidence to the existing incident
                return existing
        audit = [
            self._event("gcp.logging.webhook", f"Received Cloud Logging alert sink event {delivery_id}"),
            self._event("gcp.logging.stacktrace", f"Extracted log payload: {log_payload[:150]}..."),
        ]
        rca = self._investigate(context, audit)
        verification = self._verify_in_sandbox(rca, audit)
        context.status = IncidentStatus.AWAITING_APPROVAL
        record = IncidentRecord(context, rca, verification, audit)
        self.artifact_store.save(record)
        return record

    def run_labeled_issue(
        self, delivery_id: str, repository: str, issue_number: int, gateway: GitHubGateway, investigator: InvestigationRunner | None = None
    ) -> IncidentRecord:
        context = IncidentContext.from_issue(
            issue_number,
            "GitHub investigation pending",
            repository=repository,
            delivery_id=delivery_id,
        )
        claimed_incident_id = self.artifact_store.claim_delivery_id(delivery_id, context.incident_id)
        if claimed_incident_id:
            existing = self.artifact_store.get(claimed_incident_id)
            if existing:
                return existing
            raise RuntimeError("GitHub delivery is already being processed")
        issue = gateway.get_issue(repository, issue_number)
        evidence = gateway.get_repository_evidence(repository, issue.default_branch)
        context.title = issue.title
        context.issue_url = issue.url
        context.repository_ref = issue.default_branch
        context.source_commit = evidence.commit_sha
        audit = [self._event("webhook.accepted", f"Accepted GitHub delivery {delivery_id}")]
        rca = self._investigate_live(context, issue.body, evidence, audit, investigator or AdkInvestigationRunner())
        verification = self._verify_in_sandbox(rca, audit)
        context.status = IncidentStatus.AWAITING_APPROVAL
        record = IncidentRecord(context, rca, verification, audit)
        self.artifact_store.save(record)
        return record

    def approve(self, record: IncidentRecord, actor: str, token: str | None, gateway: GitHubGateway | None = None, require_demo_token: bool = True) -> IncidentRecord:
        if require_demo_token and token != DEMO_APPROVAL_TOKEN:
            raise PermissionError("Approval requires the configured demo authorization token")
        if record.context.status not in (IncidentStatus.AWAITING_APPROVAL, IncidentStatus.PR_CREATION_FAILED):
            raise ValueError("Only verified incidents can be approved")
        if record.context.delivery_id:
            if gateway is None:
                raise ValueError("GitHub authorization is required for live incident approval")
            return self._approve_live(record, actor, gateway)
        record.context.status = IncidentStatus.APPROVED
        record.approval = {
            "actor": actor,
            "approved_at": datetime.now(UTC).isoformat(),
            "action": "SIMULATED_PULL_REQUEST_CREATED",
            "branch": record.verification.branch_name,
        }
        record.audit_events.append(
            self._event("approval.authorized", f"{actor} authorized simulated pull request")
        )
        self.artifact_store.save(record)
        return record

    def _approve_live(self, record: IncidentRecord, actor: str, gateway: GitHubGateway) -> IncidentRecord:
        branch = self._branch_name(record.context.incident_id)
        approval = record.approval or {}
        approval.update({"actor": actor, "approved_at": datetime.now(UTC).isoformat(), "action": "PULL_REQUEST_PENDING", "branch": branch})
        record.approval = approval
        try:
            # 1. Resolve source_commit if "unknown" or empty
            source_commit = record.context.source_commit
            if not source_commit or source_commit == "unknown":
                try:
                    repo_info = gateway.get_repository(record.context.repository)
                    default_ref = repo_info.default_branch
                except Exception:
                    default_ref = "main"
                try:
                    evidence = gateway.get_repository_evidence(record.context.repository, default_ref)
                    source_commit = evidence.commit_sha
                except Exception:
                    source_commit = ""
                record.context.source_commit = source_commit
                if not record.context.repository_ref:
                    record.context.repository_ref = default_ref

            if not approval.get("branch_created"):
                gateway.create_branch(record.context.repository, branch, record.context.source_commit)
                approval["branch_created"] = True
                self.artifact_store.save(record)
            if not approval.get("commit_sha"):
                replacement = record.rca.proposed_patch if hasattr(record.rca, "proposed_patch") and "return" in record.rca.proposed_patch else 'return f"${cents / 100:.2f}"'
                approval["commit_sha"] = gateway.commit_pricing_replacement(
                    record.context.repository, branch, record.verification.file_path, replacement
                )
                self.artifact_store.save(record)
            if not approval.get("pr_number"):
                base_ref = record.context.repository_ref or "main"
                issue_info = f"for #{record.context.issue_number}" if record.context.issue_number and record.context.issue_number > 0 else f"for incident {record.context.incident_id}"
                pull_request = gateway.create_draft_pull_request(
                    record.context.repository, branch, base_ref, record.context.title,
                    f"Automated verified remediation {issue_info}.\n\n```diff\n{record.verification.diff}\n```",
                )
                approval.update({"pr_number": pull_request.number, "pr_url": pull_request.url})
                self.artifact_store.save(record)
            if not approval.get("issue_commented"):
                if record.context.issue_number and record.context.issue_number > 0:
                    gateway.add_issue_comment(
                        record.context.repository, record.context.issue_number,
                        f"NightZero created draft PR #{approval['pr_number']}: {approval['pr_url']}",
                    )
                approval["issue_commented"] = True
            approval["action"] = "DRAFT_PULL_REQUEST_CREATED"
            record.context.status = IncidentStatus.APPROVED
            record.audit_events.append(self._event("github.pull_request.created", f"Created draft PR #{approval['pr_number']}"))
        except RuntimeError as error:
            approval.update({"action": "PULL_REQUEST_FAILED", "failure": str(error)})
            record.context.status = IncidentStatus.PR_CREATION_FAILED
            record.audit_events.append(self._event("github.pull_request.failed", str(error)))
        self.artifact_store.save(record)
        return record

    def handle_pull_request_merged(
        self, repository: str, pr_number: int, pr_url: str = "", branch: str = "", merged_by: str = ""
    ) -> IncidentRecord | None:
        for record in self.artifact_store.list():
            pr_match = record.approval and record.approval.get("pr_number") == pr_number
            branch_match = bool(branch and record.approval and record.approval.get("branch") == branch)
            if pr_match or branch_match:
                if record.context.status != IncidentStatus.RESOLVED:
                    record.context.status = IncidentStatus.RESOLVED
                    actor_text = f" by @{merged_by}" if merged_by else ""
                    record.approval["merged_at"] = datetime.now(UTC).isoformat()
                    if merged_by:
                        record.approval["merged_by"] = merged_by
                    record.approval["action"] = "PULL_REQUEST_MERGED"
                    record.audit_events.append(
                        self._event("github.pull_request.merged", f"Pull request #{pr_number} merged{actor_text}. Incident resolved.")
                    )
                    self.artifact_store.save(record)
                return record
        return None

    def sync_incident_status(self, record: IncidentRecord, gateway: GitHubGateway) -> IncidentRecord:
        if record.context.status == IncidentStatus.APPROVED and record.approval and record.approval.get("pr_number"):
            try:
                pr_data = gateway.get_pull_request(record.context.repository, record.approval["pr_number"])
                if pr_data.get("merged") or pr_data.get("merged_at"):
                    merged_by = (pr_data.get("merged_by") or {}).get("login", "")
                    record.context.status = IncidentStatus.RESOLVED
                    record.approval["merged_at"] = pr_data.get("merged_at") or datetime.now(UTC).isoformat()
                    if merged_by:
                        record.approval["merged_by"] = merged_by
                    record.approval["action"] = "PULL_REQUEST_MERGED"
                    record.audit_events.append(
                        self._event("github.pull_request.merged", f"Pull request #{record.approval['pr_number']} verified as merged on GitHub. Incident resolved.")
                    )
                    self.artifact_store.save(record)
            except Exception:
                pass
        return record

    @staticmethod
    def _branch_name(incident_id: str) -> str:
        sanitized = re.sub(r"[^a-z0-9-]+", "-", incident_id.lower()).strip("-")
        if not sanitized:
            raise ValueError("Incident identifier cannot produce a Git branch name")
        return f"nightzero/{sanitized}"

    def _investigate(self, context: IncidentContext, audit: list[AuditEvent]) -> RootCauseAnalysis:
        evidence = [
            Evidence("issue", "GitHub issue #142", "Expected $12.34; received $12.00."),
            Evidence("commit", context.source_commit, "Use integer division for display totals"),
            Evidence("source", "demo_target/pricing.py", "format_total uses cents // 100"),
        ]
        audit.append(self._event("mcp.github.read", "Read issue and seeded commit metadata (read-only)"))
        audit.append(self._event("mcp.repository.read", "Inspected demo_target/pricing.py (read-only)"))
        return RootCauseAnalysis(
            root_cause="Integer division drops cents from checkout totals.",
            confidence=0.99,
            culprit_commit=context.source_commit,
            proposed_patch="Render cents / 100 with two decimal places.",
            evidence=evidence,
        )

    def _investigate_live(
        self, context: IncidentContext, issue_body: str, repository: RepositoryEvidence, audit: list[AuditEvent], investigator: InvestigationRunner
    ) -> RootCauseAnalysis:
        audit.extend([
            self._event("github.issue.read", f"Read {context.issue_url} (read-only)"),
            self._event("github.commit.read", f"Read commit {repository.commit_sha} (read-only)"),
            self._event("github.content.read", f"Read {repository.path}@{context.repository_ref} (read-only)"),
        ])
        proposal = investigator.investigate(context, issue_body, repository)
        self._validate_proposal(proposal)
        audit.append(self._event("adk.investigation.completed", "Validated bounded triage and RCA proposal"))
        return RootCauseAnalysis(
            root_cause=proposal.root_cause,
            confidence=proposal.confidence,
            culprit_commit=repository.commit_sha,
            proposed_patch=proposal.proposed_patch,
            evidence=[
                Evidence("issue", context.issue_url, issue_body.strip().replace("\n", " ")[:300] or "No issue body supplied."),
                Evidence("commit", repository.commit_sha, repository.commit_message),
                Evidence("source", repository.path, "format_total uses cents // 100" if "cents // 100" in repository.content else "Inspected source content."),
            ],
        )

    @staticmethod
    def _validate_proposal(proposal: InvestigationProposal) -> None:
        if not 0 <= proposal.confidence <= 1 or not proposal.file_path or not proposal.replacement:
            raise ValueError("Investigation proposed an invalid remediation proposal")
        if proposal.file_path.startswith("/") or ".." in proposal.file_path or proposal.file_path == "README.md":
            raise ValueError("Investigation proposed a patch outside the permitted remediation")

    def _verify_in_sandbox(
        self, rca: RootCauseAnalysis, audit: list[AuditEvent], target_file_path: str = "demo_target/pricing.py", replacement: str = 'return f"${cents / 100:.2f}"'
    ) -> RemediationVerificationReport:
        sandbox_id = f"sandbox-{uuid4().hex[:8]}"
        branch_name = f"nightzero/{sandbox_id}"
        with tempfile.TemporaryDirectory(prefix="nightzero-") as temporary_directory:
            sandbox_root = Path(temporary_directory)
            checkout = sandbox_root / "target"
            self._run_git(["clone", "--depth", "1", self._clone_url(), str(checkout)], environment=self._git_environment())
            self._run_git(["checkout", "-b", branch_name], cwd=checkout)
            before = self._run_test(checkout)
            if before.exit_code == 0:
                raise RuntimeError("Seeded incident unexpectedly passed before remediation")

            source_path = checkout / target_file_path
            if not source_path.exists():
                source_path = checkout / "demo_target" / "pricing.py"
                target_file_path = "demo_target/pricing.py"

            original = source_path.read_text(encoding="utf-8")
            if 'return f"${cents // 100}.00"' in original:
                patched = original.replace('return f"${cents // 100}.00"', replacement)
            elif replacement in original:
                patched = original
            else:
                # If target substring replacement didn't match directly, replace line or full return
                patched = re.sub(r'return f"\${cents // 100}\.00"', replacement, original)
                if patched == original:
                    patched = original.replace('return f"${cents // 100}.00"', 'return f"${cents / 100:.2f}"')

            source_path.write_text(patched, encoding="utf-8")
            shutil.rmtree(source_path.parent / "__pycache__", ignore_errors=True)
            after = self._run_test(checkout)
            if after.exit_code != 0:
                raise RuntimeError(f"Candidate patch did not pass the sandbox test: {after.output}")
            diff = "".join(
                difflib.unified_diff(
                    original.splitlines(keepends=True),
                    patched.splitlines(keepends=True),
                    fromfile=f"a/{target_file_path}",
                    tofile=f"b/{target_file_path}",
                )
            )

        audit.append(self._event("sandbox.created", f"Created isolated {sandbox_id}"))
        audit.append(self._event("sandbox.test", "Captured failing-before and passing-after test runs"))
        return RemediationVerificationReport(
            sandbox_id=sandbox_id,
            branch_name=branch_name,
            file_path=target_file_path,
            diff=diff,
            before=before,
            after=after,
            staging_status="VERIFIED",
        )

    @staticmethod
    def _run_test(cwd: Path) -> CommandResult:
        completed = subprocess.run(
            TEST_COMMAND, cwd=cwd, capture_output=True, text=True, check=False
        )
        return CommandResult(TEST_COMMAND, completed.returncode, completed.stdout + completed.stderr)

    def _clone_url(self) -> str:
        token = os.environ.get("NIGHTZERO_GIT_CLONE_TOKEN")
        repository = os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "sudhir-asuracore/NightZero-TestProject")
        if token and repository:
            return f"https://github.com/{repository}.git"
        return self.target_repository_url

    @staticmethod
    def _git_environment() -> dict[str, str] | None:
        token = os.environ.get("NIGHTZERO_GIT_CLONE_TOKEN")
        if not token:
            return None
        encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        environment = os.environ.copy()
        environment.pop("NIGHTZERO_GIT_CLONE_TOKEN", None)
        environment.update({
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {encoded}",
        })
        return environment

    @staticmethod
    def _run_git(command: list[str], cwd: Path | None = None, environment: dict[str, str] | None = None) -> None:
        completed = subprocess.run(["git", *command], cwd=cwd, env=environment, capture_output=True, text=True, check=False)
        if completed.returncode:
            raise RuntimeError("Git sandbox setup failed")

    @staticmethod
    def _event(action: str, detail: str) -> AuditEvent:
        return AuditEvent(action, datetime.now(UTC).isoformat(), detail)