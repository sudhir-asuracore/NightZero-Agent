from __future__ import annotations

import difflib
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import uuid4

from nightzero.models import (
    AuditEvent,
    CommandResult,
    Evidence,
    IncidentContext,
    IncidentRecord,
    IncidentStatus,
    RemediationVerificationReport,
    RootCauseAnalysis,
)
from nightzero.store import ArtifactStore

TEST_COMMAND = ["python", "-m", "unittest", "demo_target.test_pricing"]
DEMO_APPROVAL_TOKEN: Final = "nightzero-demo"
DEFAULT_TARGET_REPOSITORY_URL: Final = "git@github.com:sudhir-asuracore/NightZero-TestProject.git"


class NightZeroWorkflow:
    """A bounded, deterministic implementation of the four-agent MVP path."""

    def __init__(
        self, project_root: Path, artifact_store: ArtifactStore, target_repository_url: str | None = None
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

    def approve(self, record: IncidentRecord, actor: str, token: str) -> IncidentRecord:
        if token != DEMO_APPROVAL_TOKEN:
            raise PermissionError("Approval requires the configured demo authorization token")
        if record.context.status != IncidentStatus.AWAITING_APPROVAL:
            raise ValueError("Only verified incidents can be approved")
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

    def _verify_in_sandbox(
        self, rca: RootCauseAnalysis, audit: list[AuditEvent]
    ) -> RemediationVerificationReport:
        sandbox_id = f"sandbox-{uuid4().hex[:8]}"
        branch_name = f"nightzero/{sandbox_id}"
        with tempfile.TemporaryDirectory(prefix="nightzero-") as temporary_directory:
            sandbox_root = Path(temporary_directory)
            checkout = sandbox_root / "target"
            self._run_git(["clone", "--depth", "1", self.target_repository_url, str(checkout)])
            self._run_git(["checkout", "-b", branch_name], cwd=checkout)
            before = self._run_test(checkout)
            if before.exit_code == 0:
                raise RuntimeError("Seeded incident unexpectedly passed before remediation")

            source_path = checkout / "demo_target" / "pricing.py"
            original = source_path.read_text(encoding="utf-8")
            patched = original.replace('return f"${cents // 100}.00"', 'return f"${cents / 100:.2f}"')
            if patched == original:
                raise RuntimeError("Expected seeded patch location was not found")
            source_path.write_text(patched, encoding="utf-8")
            shutil.rmtree(source_path.parent / "__pycache__", ignore_errors=True)
            after = self._run_test(checkout)
            if after.exit_code != 0:
                raise RuntimeError(f"Candidate patch did not pass the sandbox test: {after.output}")
            diff = "".join(
                difflib.unified_diff(
                    original.splitlines(keepends=True),
                    patched.splitlines(keepends=True),
                    fromfile="a/demo_target/pricing.py",
                    tofile="b/demo_target/pricing.py",
                )
            )

        audit.append(self._event("sandbox.created", f"Created isolated {sandbox_id}"))
        audit.append(self._event("sandbox.test", "Captured failing-before and passing-after test runs"))
        return RemediationVerificationReport(
            sandbox_id=sandbox_id,
            branch_name=branch_name,
            file_path="demo_target/pricing.py",
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

    @staticmethod
    def _run_git(command: list[str], cwd: Path | None = None) -> None:
        completed = subprocess.run(["git", *command], cwd=cwd, capture_output=True, text=True, check=False)
        if completed.returncode:
            raise RuntimeError(f"Git sandbox setup failed: {completed.stderr.strip()}")

    @staticmethod
    def _event(action: str, detail: str) -> AuditEvent:
        return AuditEvent(action, datetime.now(UTC).isoformat(), detail)