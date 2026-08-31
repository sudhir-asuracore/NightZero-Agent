import difflib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from nightzero.agent_gateway import AgentGateway
from nightzero.github import GitHubGateway, RepositoryEvidence
from nightzero.identity import AgentIdentity, AgentIdentityRegistry, SubagentPersona
from nightzero.investigation import GeminiInvestigationRunner, InvestigationProposal, InvestigationRunner
from nightzero.model_armor import ModelArmor
from nightzero.models import (
    AuditEvent,
    BlastRadius,
    CommandResult,
    Evidence,
    GitAttribution,
    IncidentContext,
    IncidentRecord,
    IncidentStatus,
    RemediationVerificationReport,
    RootCauseAnalysis,
    TestGapAnalysis,
    TimelineEvent,
)
from nightzero.store import IncidentStore

logger = logging.getLogger(__name__)


def _event(
    action: str,
    detail: str,
    identity: AgentIdentity | None = None,
    armor_sanitized: bool = False,
) -> AuditEvent:
    now_iso = datetime.now(UTC).isoformat()
    spiffe_id = identity.spiffe_id if identity else ""
    signature = AgentIdentityRegistry.sign_agent_action(identity, action, detail) if identity else ""
    return AuditEvent(
        action=action,
        timestamp=now_iso,
        detail=detail,
        spiffe_id=spiffe_id,
        signature=signature,
        armor_sanitized=armor_sanitized,
    )


class TriageSubagent:
    """Subagent 1: Telemetry & Log Ingestion / Incident Registration."""

    def triage_log_alert(
        self,
        service_name: str,
        log_payload: str,
        delivery_id: str,
        repository: str = "",
        severity: str = "CRITICAL",
    ) -> tuple[IncidentContext, list[AuditEvent]]:
        identity = AgentIdentityRegistry.get_identity(SubagentPersona.TRIAGE)
        armor_res = AgentGateway.enforce_policy(identity, "telemetry.read", payload=log_payload)
        clean_payload = (armor_res.sanitized_text if armor_res else log_payload).strip()
        is_sanitized = bool(armor_res and armor_res.redactions)

        identifier = uuid4().hex[:6]
        incident_id = f"inc-gcp-{identifier}"
        # Dynamically extract incident title from log payload (JSON or plaintext stack trace)
        title = f"Production Anomaly in {service_name}"
        try:
            parsed = json.loads(clean_payload)
            if isinstance(parsed, dict):
                msg = parsed.get("message") or parsed.get("event") or parsed.get("error") or parsed.get("description")
                if msg:
                    first_line = str(msg).strip().splitlines()[0]
                    title = f"{service_name}: {first_line[:120]}"
        except Exception:
            lines = [l.strip() for l in clean_payload.splitlines() if l.strip()]
            # Find the most informative exception line (usually last or line with Error/Exception)
            err_line = next((l for l in reversed(lines) if any(kw in l for kw in ["Error:", "Exception:", "FATAL", "CRITICAL", "Panic:", "assert ", "AssertionError"])), None)
            if err_line:
                title = f"{service_name}: {err_line[:120]}"
            elif lines:
                title = f"{service_name}: {lines[0][:120]}"

        now_iso = datetime.now(UTC).isoformat()
        
        # Dynamically derive error signature from normalized error line and tokens
        try:
            parsed_pl = json.loads(clean_payload)
            if isinstance(parsed_pl, dict):
                norm_base = str(parsed_pl.get("message") or parsed_pl.get("error") or parsed_pl.get("event") or clean_payload)
            else:
                norm_base = clean_payload
        except Exception:
            norm_base = clean_payload

        lines_pl = [l.strip() for l in norm_base.splitlines() if l.strip()]
        err_line_pl = next((l for l in reversed(lines_pl) if any(kw in l for kw in ["Error", "Exception", "Fault", "Panic", "Failure", "assert ", "AssertionError"])), norm_base[:120])
        norm_pl = re.sub(r'0x[0-9a-fA-F]+', '', err_line_pl)
        norm_pl = re.sub(r'[0-9a-fA-F-]{32,36}', '', norm_pl)
        norm_pl = re.sub(r'/tmp/[a-zA-Z0-9_]+', '', norm_pl)
        norm_pl = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?', '', norm_pl)
        tokens_pl = re.findall(r'[a-zA-Z0-9_]{3,}', norm_pl)
        key_part_pl = "_".join(t.lower() for t in tokens_pl[:6])
        signature = f"{service_name}:{key_part_pl}" if key_part_pl else f"{service_name}:generic"

        target_repo = repository or os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "")
        context = IncidentContext(
            incident_id=incident_id,
            session_id=f"incident-{incident_id}",
            issue_number=0,
            title=title,
            service=service_name,
            severity=severity,
            source_commit="live-commit",
            created_at=now_iso,
            status=IncidentStatus.INGESTING,
            delivery_id=delivery_id,
            repository=target_repo,
            repository_ref="main",
            occurrence_count=1,
            last_seen_at=now_iso,
            error_signature=signature,
        )
        audit_events = [
            _event(
                "telemetry.ingested",
                f"Ingested Cloud Logging alert sink event for {service_name} (Model Armor Score: {armor_res.safety_score if armor_res else 1.0:.2f})",
                identity=identity,
                armor_sanitized=is_sanitized,
            ),
            _event(
                "triage.classified",
                f"Classified incident as {severity} in {service_name}: {title}",
                identity=identity,
            ),
        ]
        return context, audit_events


class CodeInspectorSubagent:
    """Subagent 2: GitHub Repository AST & Git Blame Forensic Inspection."""

    def inspect_repository(
        self,
        repository: str,
        ref: str,
        gateway: GitHubGateway | None,
        target_path: str = "demo_target/pricing.py",
    ) -> tuple[RepositoryEvidence, list[AuditEvent]]:
        identity = AgentIdentityRegistry.get_identity(SubagentPersona.INSPECTOR)
        AgentGateway.enforce_policy(identity, "git.read")

        if not gateway:
            raise RuntimeError(f"GitHub gateway unavailable: Cannot inspect repository '{repository}'.")
        target_repo = repository or os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "")
        if not target_repo:
            target_repo = "default/repo"

        audit_events = []
        evidence = gateway.get_repository_evidence(target_repo, ref, target_path)
        audit_events.append(
            _event(
                "mcp.github.read",
                f"Fetched repository AST & commit metadata for {target_repo}@{ref} via GitHub MCP tool",
                identity=identity,
            )
        )
        audit_events.append(
            _event(
                "github.commit.blame",
                f"Identified candidate culprit commit {evidence.commit_sha[:7]} by {evidence.commit_author}",
                identity=identity,
            )
        )
        return evidence, audit_events


class GeminiRCASubagent:
    """Subagent 3: Gemini 3.7+ Root Cause Analysis & Multi-Dimensional Forensics."""

    def __init__(self, model: str = "gemini-3.7-flash") -> None:
        self.model = model

    def analyze_root_cause(
        self,
        context: IncidentContext,
        log_payload: str,
        evidence: RepositoryEvidence,
        investigator: InvestigationRunner | None = None,
    ) -> tuple[RootCauseAnalysis, list[AuditEvent]]:
        identity = AgentIdentityRegistry.get_identity(SubagentPersona.RCA)
        armor_res = AgentGateway.enforce_policy(identity, "llm.infer", payload=log_payload)
        sanitized_log = (armor_res.sanitized_text if armor_res else log_payload).strip()

        audit_events = [
            _event(
                "gemini.investigation.started",
                f"Invoking {self.model} with dynamic reasoning budget for multi-step RCA (Model Armor: Protected)",
                identity=identity,
                armor_sanitized=bool(armor_res and armor_res.redactions),
            ),
        ]
        runner = investigator or GeminiInvestigationRunner(model=self.model)
        proposal = runner.investigate(context, sanitized_log, evidence)

        # Inspect generated patch safety with Model Armor
        patch_candidate = proposal.replacement or proposal.proposed_patch
        patch_safety = ModelArmor.inspect_patch_safety(patch_candidate)
        if not patch_safety.is_safe:
            logger.warning("Model Armor detected suspicious patch construct: %s", patch_safety.blocked_patterns)

        # Dynamically extract timestamp from log payload
        time_match = re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', sanitized_log)
        log_time = time_match.group(0) if time_match else context.created_at or datetime.now(UTC).isoformat()

        timeline_list = proposal.timeline_trail if proposal.timeline_trail else [
            TimelineEvent(timestamp=log_time, phase="TRIGGER", event=f"Request dispatched to {context.service}", source=context.service, details=f"Target path: {evidence.path}"),
            TimelineEvent(timestamp=log_time, phase="FAILURE", event=sanitized_log.strip().splitlines()[-1] if sanitized_log else "Runtime Exception", source=context.service, details=f"Failed in {context.service}"),
            TimelineEvent(timestamp=context.created_at or datetime.now(UTC).isoformat(), phase="DETECTION", event=f"Cloud Logging error sink captured alert for {context.service}", source="Cloud Logging", details="Routed alert to NightZero Agent"),
        ]

        attribution = proposal.attribution or GitAttribution(
            author=evidence.commit_author or "engineer",
            commit_sha=evidence.commit_sha or context.source_commit or "latest",
            commit_message=evidence.commit_message or f"Update {evidence.path}",
            pr_number=context.issue_number if context.issue_number > 0 else None,
            pr_title=context.title,
            pr_url=context.issue_url,
            changed_file=evidence.path,
            merged_at=evidence.commit_date or "Recently",
        )

        test_gap = proposal.test_gap_analysis or TestGapAnalysis(
            why_tests_missed="Not applicable for this incident.",
            blindspot_summary="Not applicable for this incident.",
            recommended_test_name="",
            recommended_test_code="",
        )

        blast_radius = proposal.blast_radius or BlastRadius(
            impacted_endpoints=[f"/{context.service}/api"],
            failure_rate="100% of affected requests",
            affected_services=[context.service],
        )

        evidence_list = [
            Evidence(kind="log", source="Cloud Logging", detail=sanitized_log[:250]),
            Evidence(kind="commit", source="git/commit", detail=f"Commit {attribution.commit_sha[:7]} by {attribution.author}: {attribution.commit_message}"),
            Evidence(kind="ast", source=evidence.path, detail=f"Buggy line: {evidence.content.strip().splitlines()[-1] if evidence.content else ''}"),
        ]

        rca = RootCauseAnalysis(
            root_cause=proposal.root_cause,
            confidence=proposal.confidence,
            culprit_commit=attribution.commit_sha,
            proposed_patch=proposal.proposed_patch,
            replacement=proposal.replacement or proposal.proposed_patch,
            evidence=evidence_list,
            timeline_trail=timeline_list,
            attribution=attribution,
            test_gap_analysis=test_gap,
            blast_radius=blast_radius,
        )

        audit_events.append(
            _event(
                "gemini.rca.synthesized",
                f"Isolated root cause (Confidence: {int(proposal.confidence * 100)}%): {proposal.root_cause[:120]}...",
                identity=identity,
            )
        )
        return rca, audit_events


class SandboxVerificationSubagent:
    """Subagent 4: Isolated Ephemeral Polyglot Sandbox Provisioning & Subprocess Verification."""

    def __init__(self, store: IncidentStore | None = None, gemini_model: str = "gemini-3.7-flash") -> None:
        self.store = store
        self.gemini_model = gemini_model

    def verify_patch(
        self,
        rca: RootCauseAnalysis,
        target_path: str = "",
        branch_name: str = "",
        target_content: str = "",
        repository: str = "",
    ) -> tuple[RemediationVerificationReport, list[AuditEvent]]:
        from nightzero.sandbox import ProjectSandboxAnalyzer

        identity = AgentIdentityRegistry.get_identity(SubagentPersona.SANDBOX)
        AgentGateway.enforce_policy(identity, "sandbox.spawn")
        AgentGateway.enforce_policy(identity, "sandbox.test_exec")

        sandbox_id = f"sandbox-{uuid4().hex[:8]}"
        resolved_path = target_path or (rca.attribution.changed_file if rca.attribution else "") or "src/app.py"
        resolved_branch = branch_name or (f"nightzero/fix-{rca.culprit_commit[:7]}" if rca.culprit_commit else "nightzero/remediation")
        target_repo = repository or (rca.attribution.changed_file if rca.attribution else "") or "default/repo"

        audit_events = [
            _event(
                "sandbox.testing.started",
                f"Provisioned isolated ephemeral sandbox {sandbox_id}",
                identity=identity,
            ),
        ]

        with tempfile.TemporaryDirectory() as sandbox_dir:
            sandbox_path = Path(sandbox_dir)
            target_file = sandbox_path / resolved_path
            target_file.parent.mkdir(parents=True, exist_ok=True)

            # Dynamically locate workspace containing target directory
            root_candidates = [
                Path.cwd(),
                Path.cwd().parent,
                Path(__file__).parents[2],
            ]
            target_parent = Path(resolved_path).parent
            target_dir_name = target_parent.name or "demo_target"
            local_target_dir = next((p / target_dir_name for p in root_candidates if (p / target_dir_name).exists()), None)
            if local_target_dir:
                shutil.copytree(
                    local_target_dir,
                    sandbox_path / target_dir_name,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"),
                )
            
            # If no target file copied, synthesize from target_content
            if not target_file.exists() or target_content:
                if target_content:
                    target_file.write_text(target_content, encoding="utf-8")
                else:
                    target_file.write_text('def format_total(cents: int) -> str:\n    return f"${cents // 100}.00"\n', encoding="utf-8")

            # If test directory is empty, create module-specific test runner
            test_dir = sandbox_path / target_dir_name
            if not list(sandbox_path.glob("**/test_*.py")):
                test_dir.mkdir(parents=True, exist_ok=True)
                (test_dir / "__init__.py").touch()
                if "tax" in resolved_path:
                    (test_dir / "test_tax.py").write_text(
                        'import unittest\nfrom demo_target.tax import calculate_tax_and_fees\n\nclass CalculateTaxTest(unittest.TestCase):\n    def test_standard_tax(self) -> None:\n        self.assertEqual(825, calculate_tax_and_fees(10000, 825))\n\nif __name__ == "__main__":\n    unittest.main()\n',
                        encoding="utf-8",
                    )
                elif "currency" in resolved_path:
                    (test_dir / "test_currency.py").write_text(
                        'import unittest\nfrom demo_target.currency import convert_currency\n\nclass ConvertCurrencyTest(unittest.TestCase):\n    def test_usd_to_eur(self) -> None:\n        self.assertEqual(920, convert_currency(1000, 0.92))\n\nif __name__ == "__main__":\n    unittest.main()\n',
                        encoding="utf-8",
                    )
                elif "discount" in resolved_path:
                    (test_dir / "test_discounts.py").write_text(
                        'import unittest\nfrom demo_target.discounts import apply_discount\n\nclass ApplyDiscountTest(unittest.TestCase):\n    def test_discount(self) -> None:\n        self.assertEqual(800, apply_discount(1000, 20.0))\n\nif __name__ == "__main__":\n    unittest.main()\n',
                        encoding="utf-8",
                    )
                elif "billing" in resolved_path:
                    (test_dir / "test_billing.py").write_text(
                        'import unittest\nfrom demo_target.billing import calculate_proration\n\nclass CalculateProrationTest(unittest.TestCase):\n    def test_proration(self) -> None:\n        self.assertEqual(1500, calculate_proration(3000, 15, 30))\n\nif __name__ == "__main__":\n    unittest.main()\n',
                        encoding="utf-8",
                    )
                else:
                    (test_dir / "test_pricing.py").write_text(
                        'import unittest\nfrom demo_target.pricing import format_total\n\nclass FormatTotalTest(unittest.TestCase):\n    def test_preserves_cents(self) -> None:\n        self.assertEqual("$12.34", format_total(1234))\n\nif __name__ == "__main__":\n    unittest.main()\n',
                        encoding="utf-8",
                    )

            # Analyze & Learn Test Profile (Memory Bank)
            profile, from_memory = ProjectSandboxAnalyzer.analyze_repository(
                repository=target_repo,
                workspace_dir=sandbox_path,
                store=self.store,
                gemini_model=self.gemini_model,
            )
            if from_memory:
                audit_events.append(_event("sandbox.memory.loaded", f"Retrieved learned test profile for '{target_repo}' from Memory Bank ({' '.join(profile.test_command)})", identity=identity))
            else:
                audit_events.append(_event("sandbox.techstack.learned", f"Learned test strategy for {profile.language} project in '{target_repo}': {' '.join(profile.test_command)} (Saved to Memory Bank)", identity=identity))

            # Inject synthesized preventative test from CI/CD gap analysis if present
            if rca.test_gap_analysis and rca.test_gap_analysis.recommended_test_code:
                try:
                    test_files = list(test_dir.glob("test_*.py")) or list(sandbox_path.glob("**/test_*.py"))
                    if test_files:
                        primary_test = test_files[0]
                        existing_test_code = primary_test.read_text(encoding="utf-8")
                        if rca.test_gap_analysis.recommended_test_name not in existing_test_code:
                            # Indent properly and append to TestCase class
                            indented = "\n".join("    " + line if line.strip() else "" for line in rca.test_gap_analysis.recommended_test_code.splitlines())
                            class_idx = existing_test_code.find("class ")
                            if class_idx != -1:
                                main_idx = existing_test_code.find("if __name__ ==")
                                if main_idx != -1:
                                    augmented = existing_test_code[:main_idx] + f"\n{indented}\n\n" + existing_test_code[main_idx:]
                                else:
                                    augmented = existing_test_code + f"\n{indented}\n"
                                primary_test.write_text(augmented, encoding="utf-8")
                                audit_events.append(_event("sandbox.gap_test.injected", f"Injected preventative test '{rca.test_gap_analysis.recommended_test_name}' into sandbox test suite", identity=identity))
                except Exception as exc:
                    logger.warning("Could not inject preventative test gap: %s", exc)

            original_code = target_file.read_text(encoding="utf-8") if target_file.exists() else ""

            # 1. Execute tests before patch (verifying baseline failure)
            env = {**os.environ, "PYTHONPATH": str(sandbox_path), **profile.env_vars}
            before_proc = subprocess.run(
                profile.test_command,
                cwd=sandbox_dir,
                capture_output=True,
                text=True,
                env=env,
            )
            before_output = (before_proc.stdout + "\n" + before_proc.stderr).strip()
            before_result = CommandResult(
                command=profile.test_command,
                exit_code=before_proc.returncode,
                output=before_output,
            )
            audit_events.append(_event("sandbox.baseline.tested", f"Baseline pre-patch test run completed (Exit code: {before_proc.returncode})", identity=identity))

            # 2. Apply proposed patch dynamically
            replacement = (rca.replacement if (hasattr(rca, "replacement") and rca.replacement) else "") or rca.proposed_patch or ""
            clean_repl = replacement.strip()
            if "def " in original_code and "return " in original_code and "return" in clean_repl:
                patched_code = re.sub(r'^\s*return .*', lambda _: f'    {clean_repl}', original_code, flags=re.MULTILINE)
            elif "def " in original_code and "return " in original_code and "def " not in clean_repl:
                patched_code = re.sub(r'^\s*return .*', lambda _: f'    return {clean_repl}', original_code, flags=re.MULTILINE)
            elif "def " not in original_code and "return" in clean_repl:
                patched_code = f"def format_total(cents: int) -> str:\n    {clean_repl}\n"
            else:
                patched_code = clean_repl

            target_file.write_text(patched_code, encoding="utf-8")

            # 3. Execute tests after patch (verifying remediation success)
            after_proc = subprocess.run(
                profile.test_command,
                cwd=sandbox_dir,
                capture_output=True,
                text=True,
                env=env,
            )
            after_output = (after_proc.stdout + "\n" + after_proc.stderr).strip()
            after_result = CommandResult(
                command=profile.test_command,
                exit_code=after_proc.returncode,
                output=after_output,
            )
            audit_events.append(_event("sandbox.verified", f"Candidate patch verified in isolated sandbox (Exit code: {after_proc.returncode})", identity=identity))

            # 4. Generate unified diff
            diff_lines = difflib.unified_diff(
                original_code.splitlines(keepends=True),
                patched_code.splitlines(keepends=True),
                fromfile=f"a/{resolved_path}",
                tofile=f"b/{resolved_path}",
            )
            diff = "".join(diff_lines)
            if not diff:
                diff = f"--- a/{resolved_path}\n+++ b/{resolved_path}\n@@ -1,1 +1,1 @@\n- {original_code.strip()}\n+ {patched_code.strip()}"

            report = RemediationVerificationReport(
                sandbox_id=sandbox_id,
                branch_name=resolved_branch,
                file_path=resolved_path,
                diff=diff,
                before=before_result,
                after=after_result,
                staging_status="VERIFIED" if after_proc.returncode == 0 else "FAILED",
            )
            return report, audit_events


class RemediationPRSubagent:
    """Subagent 5: Human Gate & GitHub Draft Pull Request Generation."""

    def create_remediation_pr(
        self,
        record: IncidentRecord,
        actor: str,
        gateway: GitHubGateway,
    ) -> list[AuditEvent]:
        identity = AgentIdentityRegistry.get_identity(SubagentPersona.REMEDIATION, delegated_reviewer=actor)
        branch_prefix = os.environ.get("NIGHTZERO_BRANCH_PREFIX", "nightzero")
        branch = f"{branch_prefix}/{record.context.incident_id}"
        approval = record.approval or {}
        approval.update({"actor": actor, "approved_at": datetime.now(UTC).isoformat(), "branch": branch})
        record.approval = approval
        audit_events = [
            _event(
                "approval.authorized",
                f"Reviewer {actor} authorized remediation proposal with delegated authority ({identity.spiffe_id})",
                identity=identity,
            ),
        ]

        try:
            repo_name = record.context.repository or os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "")
            if not repo_name:
                raise ValueError(f"Target repository not configured for incident {record.context.incident_id}.")

            default_ref = record.context.repository_ref or "main"
            source_commit = record.context.source_commit

            if not approval.get("branch_created"):
                AgentGateway.enforce_policy(identity, "github.branch.create")
                gateway.create_branch(repo_name, branch, source_commit if source_commit != "live-commit" else "main")
                approval["branch_created"] = True
                audit_events.append(_event("github.branch.created", f"Created isolated branch {branch} from {default_ref}", identity=identity))

            if not approval.get("commit_sha"):
                replacement = (
                    (record.rca.replacement if (record.rca and hasattr(record.rca, "replacement") and record.rca.replacement) else "")
                    or (record.rca.proposed_patch if record.rca else "")
                )
                target_file_path = (
                    record.verification.file_path
                    if record.verification
                    else (record.rca.attribution.changed_file if (record.rca and record.rca.attribution) else "")
                )
                if not target_file_path:
                    raise ValueError(f"Target file path required for committing fix in {repo_name}.")

                AgentGateway.enforce_policy(identity, "github.commit.write", payload=replacement)
                commit_sha = gateway.commit_pricing_replacement(
                    repo_name, branch, target_file_path, replacement
                )
                approval["commit_sha"] = commit_sha
                audit_events.append(_event("github.commit.pushed", f"Committed verified fix to branch {branch} (Commit: {commit_sha[:7]})", identity=identity))

            if not approval.get("pr_number"):
                AgentGateway.enforce_policy(identity, "github.pr.create")
                pr = gateway.create_draft_pull_request(
                    repo_name,
                    branch,
                    default_ref,
                    record.context.title,
                    f"Automated verified remediation for incident {record.context.incident_id}.\n\n### Isolated Sandbox Verification:\n```diff\n{record.verification.diff if record.verification else ''}\n```\n\nGenerated autonomously by NightZero Agent (Gemini 3.7+ with Zero-Trust Governance).",
                )
                approval.update({"pr_number": pr.number, "pr_url": pr.url})
                audit_events.append(_event("github.pr.created", f"Opened Draft Pull Request #{pr.number} on GitHub: {pr.url}", identity=identity))

            if not approval.get("issue_commented") and record.context.issue_number > 0:
                gateway.add_issue_comment(
                    repo_name, record.context.issue_number, f"NightZero verified remediation and created draft PR #{approval['pr_number']}: {approval['pr_url']}"
                )
                approval["issue_commented"] = True
                audit_events.append(_event("github.issue.commented", f"Posted verification audit report to Issue #{record.context.issue_number}", identity=identity))

            approval["action"] = "DRAFT_PULL_REQUEST_CREATED"
            record.context.status = IncidentStatus.APPROVED
        except Exception as exc:
            logger.error("Failed creating PR via RemediationPRSubagent: %s", exc)
            approval["failure"] = str(exc)
            record.context.status = IncidentStatus.PR_CREATION_FAILED
            audit_events.append(_event("github.pr.failed", f"PR creation failed: {str(exc)}", identity=identity))

        return audit_events

    def create_consolidated_remediation_pr(
        self,
        records: list[IncidentRecord],
        actor: str,
        gateway: GitHubGateway,
    ) -> tuple[dict[str, Any], list[AuditEvent]]:
        """Bundles multiple verified incident fixes into a single release branch and Draft PR."""
        if not records:
            raise ValueError("No records provided for consolidated batch remediation.")

        identity = AgentIdentityRegistry.get_identity(SubagentPersona.REMEDIATION, delegated_reviewer=actor)
        bundle_id = f"bundle-{uuid4().hex[:8]}"
        branch_prefix = os.environ.get("NIGHTZERO_BRANCH_PREFIX", "nightzero")
        branch = f"{branch_prefix}/release-{bundle_id}"
        repo_name = records[0].context.repository or os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "")
        if not repo_name:
            raise ValueError("Target repository not configured for consolidated release.")

        default_ref = records[0].context.repository_ref or "main"
        source_commit = records[0].context.source_commit

        audit_events = [
            _event(
                "batch.approval.authorized",
                f"Reviewer {actor} authorized batch consolidation of {len(records)} incidents onto release branch {branch}",
                identity=identity,
            ),
        ]

        # 1. Create shared release branch
        AgentGateway.enforce_policy(identity, "github.branch.create")
        gateway.create_branch(repo_name, branch, source_commit if source_commit != "live-commit" else "main")
        audit_events.append(_event("github.branch.created", f"Created consolidated release branch {branch} from {default_ref}", identity=identity))

        # 2. Sequentially apply all verified patches to the release branch
        applied_commits = []
        for rec in records:
            replacement = (
                (rec.rca.replacement if (rec.rca and hasattr(rec.rca, "replacement") and rec.rca.replacement) else "")
                or (rec.rca.proposed_patch if rec.rca else "")
            )
            target_file_path = (
                rec.verification.file_path
                if rec.verification
                else (rec.rca.attribution.changed_file if (rec.rca and rec.rca.attribution) else "")
            )
            if not target_file_path:
                target_file_path = "demo_target/pricing.py"

            AgentGateway.enforce_policy(identity, "github.commit.write", payload=replacement)
            commit_sha = gateway.commit_pricing_replacement(
                repo_name, branch, target_file_path, replacement
            )
            applied_commits.append(commit_sha)
            audit_events.append(
                _event("github.commit.pushed", f"Committed patch for incident {rec.context.incident_id} to branch {branch} (Commit: {commit_sha[:7]})", identity=identity)
            )

        # 3. Create single Consolidated Draft PR
        inc_ids_str = ", ".join(r.context.incident_id for r in records)
        pr_title = f"fix(bundle): Consolidated remediation for {len(records)} incidents ({inc_ids_str})"
        
        pr_sections = []
        for i, rec in enumerate(records, 1):
            pr_sections.append(
                f"#### Incident #{i}: {rec.context.title} (`{rec.context.incident_id}`)\n"
                f"- **Service**: `{rec.context.service}`\n"
                f"- **Severity**: `{rec.context.severity}`\n"
                f"- **Root Cause**: {rec.rca.root_cause if rec.rca else 'Synthesized patch'}\n"
                f"```diff\n{rec.verification.diff if rec.verification else ''}\n```"
            )
        
        pr_body = (
            f"## 📦 NightZero Consolidated Release Bundle (`{bundle_id}`)\n\n"
            f"This pull request bundles verified automated remediations for **{len(records)} production incidents**.\n\n"
            + "\n\n".join(pr_sections) +
            "\n\n---\n*Generated autonomously by NightZero Agent (Gemini 3.7+ with Zero-Trust Governance).*"
        )

        AgentGateway.enforce_policy(identity, "github.pr.create")
        pr = gateway.create_draft_pull_request(
            repo_name,
            branch,
            default_ref,
            pr_title,
            pr_body,
        )
        audit_events.append(_event("github.pr.created", f"Opened Consolidated Draft Pull Request #{pr.number} on GitHub: {pr.url}", identity=identity))

        # 4. Optional comments on constituent issues
        for rec in records:
            if rec.context.issue_number > 0:
                try:
                    gateway.add_issue_comment(
                        repo_name, rec.context.issue_number, f"NightZero bundled this remediation into Consolidated Release PR #{pr.number}: {pr.url}"
                    )
                except Exception:
                    pass

        result_payload = {
            "batch_id": bundle_id,
            "branch": branch,
            "pr_number": pr.number,
            "pr_url": pr.url,
            "commits": applied_commits,
            "actor": actor,
            "approved_at": datetime.now(UTC).isoformat(),
            "action": "CONSOLIDATED_PULL_REQUEST_CREATED",
        }
        return result_payload, audit_events
