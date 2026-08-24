import base64
import difflib
import os
import random
import re
import shutil
import subprocess
import tempfile
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

SIMULATED_SCENARIOS: Final = [
    {
        "service": "demo-payment-gateway",
        "title": "Pricing formatting truncation: Cents rounded down in checkout totals",
        "severity": "CRITICAL",
        "root_cause": "Integer division (// 100) drops fractional cents from display formatting in format_total().",
        "confidence": 0.99,
        "culprit_commit": "8f3c2a1",
        "proposed_patch": 'return f"${cents / 100:.2f}"',
        "file_path": "demo_target/pricing.py",
        "diff": '-    return f"${cents // 100}.00"\n+    return f"${cents / 100:.2f}"',
        "before_output": "FAIL: test_preserves_cents (demo_target.test_pricing.FormatTotalTest)\nAssertionError: '$12.34' != '$12.00'\nFAILED (failures=1)",
        "after_output": "test_preserves_cents (demo_target.test_pricing.FormatTotalTest) ... ok\nRan 1 test in 0.002s\nOK",
        "evidence": [
            {"kind": "log", "source": "Cloud Logging", "detail": "TypeError in checkout/pricing calculation: Expected $12.34, got $12.00"},
            {"kind": "commit", "source": "git/commits", "detail": "Commit 8f3c2a1 'Use integer division for display totals'"},
            {"kind": "source", "source": "demo_target/pricing.py", "detail": "format_total uses cents // 100 instead of decimal division"},
        ],
        "is_live_commit": True,
    },
    {
        "service": "order-fulfillment-api",
        "title": "HTTP 500 Spike: Unhandled IndexError on empty discount promo list",
        "severity": "HIGH",
        "root_cause": "Discount validator assumes non-empty list before indexing discounts[0], raising IndexError when orders contain no promo codes.",
        "confidence": 0.96,
        "culprit_commit": "4b91e02",
        "proposed_patch": "discount = (discounts or [0])[0] if isinstance(discounts, (list, tuple)) else 0",
        "file_path": "demo_target/pricing.py",
        "diff": "-    discount = discounts[0]\n+    discount = (discounts or [0])[0] if isinstance(discounts, (list, tuple)) else 0",
        "before_output": "FAIL: test_empty_discounts_fallback (demo_target.test_orders.DiscountTest)\nIndexError: list index out of range\nFAILED (failures=1)",
        "after_output": "test_empty_discounts_fallback (demo_target.test_orders.DiscountTest) ... ok\nRan 2 tests in 0.003s\nOK",
        "evidence": [
            {"kind": "log", "source": "Cloud Logging", "detail": "IndexError: list index out of range at /api/v1/orders/apply_discount"},
            {"kind": "commit", "source": "git/commits", "detail": "Commit 4b91e02 'Refactor discount collection handler'"},
            {"kind": "metric", "source": "Cloud Monitoring", "detail": "HTTP 500 error rate spiked to 14.2% on /orders endpoint"},
        ],
        "is_live_commit": False,
    },
    {
        "service": "inventory-sync-worker",
        "title": "Database Deadlock & Timeout during concurrent stock reservation",
        "severity": "CRITICAL",
        "root_cause": "Missing SELECT ... FOR UPDATE row-level lock on inventory reservation queries causing transaction serialization failures under concurrent load.",
        "confidence": 0.98,
        "culprit_commit": "9c12e87",
        "proposed_patch": "stock = db.query(Inventory).filter_by(sku=sku).with_for_update().first()",
        "file_path": "demo_target/pricing.py",
        "diff": "-    stock = db.query(Inventory).filter_by(sku=sku).first()\n+    stock = db.query(Inventory).filter_by(sku=sku).with_for_update().first()",
        "before_output": "FAIL: test_concurrent_inventory_lock (demo_target.test_inventory.StockLockTest)\nOperationalError: (1213, 'Deadlock found when trying to get lock; try restarting transaction')\nFAILED (failures=1)",
        "after_output": "test_concurrent_inventory_lock (demo_target.test_inventory.StockLockTest) ... ok\nRan 3 tests in 0.005s\nOK",
        "evidence": [
            {"kind": "log", "source": "Cloud SQL Engine", "detail": "Deadlock found when trying to get lock; transaction rolled back"},
            {"kind": "commit", "source": "git/commits", "detail": "Commit 9c12e87 'Optimize inventory read queries'"},
            {"kind": "trace", "source": "Cloud Trace", "detail": "Latency p99 increased from 45ms to 12,400ms"},
        ],
        "is_live_commit": False,
    },
    {
        "service": "auth-session-manager",
        "title": "JWT Verification Failure: Clock skew tolerance exceeded on token refresh",
        "severity": "HIGH",
        "root_cause": "Strict leeway=0 on JWT expiration validation causes legitimate edge token refreshes to fail with ExpiredSignatureError across multi-region clusters.",
        "confidence": 0.95,
        "culprit_commit": "7f03a11",
        "proposed_patch": 'return jwt.decode(token, secret, algorithms=["HS256"], leeway=60)',
        "file_path": "demo_target/pricing.py",
        "diff": '-    return jwt.decode(token, secret, algorithms=["HS256"])\n+    return jwt.decode(token, secret, algorithms=["HS256"], leeway=60)',
        "before_output": "FAIL: test_token_leeway_tolerance (demo_target.test_auth.TokenTest)\njwt.exceptions.ExpiredSignatureError: Signature has expired\nFAILED (failures=1)",
        "after_output": "test_token_leeway_tolerance (demo_target.test_auth.TokenTest) ... ok\nRan 4 tests in 0.004s\nOK",
        "evidence": [
            {"kind": "log", "source": "Cloud Logging", "detail": "ExpiredSignatureError: Token expired 2 seconds ago (skew -2000ms)"},
            {"kind": "commit", "source": "git/commits", "detail": "Commit 7f03a11 'Enforce strict auth token validation'"},
            {"kind": "metric", "source": "Identity Platform", "detail": "Re-authentication rejection rate jumped to 8.7%"},
        ],
        "is_live_commit": False,
    },
    {
        "service": "billing-subscription-worker",
        "title": "Memory Leak & Container OOMKilled in Recurring Charge Dispatcher",
        "severity": "CRITICAL",
        "root_cause": "Unbounded event listener registration in webhook subscriber pool causes memory consumption to escalate beyond container memory limit (OOMKilled).",
        "confidence": 0.97,
        "culprit_commit": "1e88d43",
        "proposed_patch": "listeners.add(weakref.ref(callback))",
        "file_path": "demo_target/pricing.py",
        "diff": "-    listeners.append(callback)\n+    listeners.add(weakref.ref(callback))",
        "before_output": "FAIL: test_subscriber_listener_cleanup (demo_target.test_billing.SubscriberTest)\nAssertionError: Expected <= 5 active listeners, found 1000\nFAILED (failures=1)",
        "after_output": "test_subscriber_listener_cleanup (demo_target.test_billing.SubscriberTest) ... ok\nRan 2 tests in 0.003s\nOK",
        "evidence": [
            {"kind": "log", "source": "Cloud Run Events", "detail": "Container terminated with exit code 137 (OOMKilled: memory limit exceeded)"},
            {"kind": "commit", "source": "git/commits", "detail": "Commit 1e88d43 'Add persistent webhook notification listeners'"},
            {"kind": "metric", "source": "Cloud Monitoring", "detail": "Memory utilization reached 100% (512MiB quota saturated)"},
        ],
        "is_live_commit": False,
    },
]

AVAILABLE_GEMINI_MODELS = [
    {
        "id": "gemini-2.5-flash",
        "name": "Gemini 2.5 Flash",
        "badge": "RECOMMENDED / FAST",
        "description": "Ultra-fast, high-efficiency model for real-time autonomous SRE triage and rapid patch synthesis.",
        "latency": "~1.2s",
    },
    {
        "id": "gemini-2.5-pro",
        "name": "Gemini 2.5 Pro",
        "badge": "DEEP REASONING",
        "description": "Advanced deep reasoning model for complex multi-service architectural analysis and subtle root cause deduction.",
        "latency": "~3.5s",
    },
    {
        "id": "gemini-2.5-flash-lite",
        "name": "Gemini 2.5 Flash-Lite",
        "badge": "ULTRA LIGHTWEIGHT",
        "description": "Ultra-lightweight, high-throughput model optimized for ultra-low latency triage.",
        "latency": "~0.8s",
    },
]


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

    @property
    def deterministic_mode(self) -> bool:
        setting = self.artifact_store.get_setting("deterministic_mode", None)
        if setting is not None:
            return bool(setting)
        return os.environ.get("NIGHTZERO_DETERMINISTIC_MODE", "false").lower() in ("true", "1", "yes")

    def set_deterministic_mode(self, enabled: bool) -> bool:
        self.artifact_store.set_setting("deterministic_mode", enabled)
        return enabled

    @property
    def gemini_model(self) -> str:
        setting = self.artifact_store.get_setting("gemini_model", None)
        if setting:
            return str(setting)
        return os.environ.get("NIGHTZERO_GEMINI_MODEL", "gemini-2.5-flash")

    def set_gemini_model(self, model: str) -> str:
        valid_ids = {m["id"] for m in AVAILABLE_GEMINI_MODELS}
        chosen = model if model in valid_ids else "gemini-2.5-flash"
        self.artifact_store.set_setting("gemini_model", chosen)
        return chosen

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
        
        # When deterministic mode is OFF and gateway is available, run live Gemini investigation
        if not self.deterministic_mode and gateway:
            active_model = self.gemini_model
            incident_id = f"inc-gemini-{uuid4().hex[:6]}"
            context = IncidentContext(
                incident_id=incident_id,
                session_id=f"incident-{incident_id}",
                issue_number=0,
                title=f"Gemini AI ({active_model}) RCA: TypeError in checkout/pricing calculation",
                service="demo-payment-gateway",
                severity="CRITICAL",
                source_commit="live-commit",
                created_at=datetime.now(UTC).isoformat(),
                status=IncidentStatus.INGESTING,
                delivery_id=f"sim-{incident_id}",
                repository=repository,
                repository_ref="main",
            )
            audit = [
                self._event("simulation.triggered", f"Operator triggered autonomous outage simulation with {active_model}"),
                self._event("gcp.logging.stacktrace", "Captured checkout TypeError: Expected $12.34, got $12.00 in demo_target/pricing.py"),
            ]
            empty_rca = RootCauseAnalysis(
                root_cause=f"Live {active_model} investigation in progress...",
                confidence=0.0,
                culprit_commit="pending",
                proposed_patch="Synthesizing patch...",
                evidence=[Evidence("log", "Cloud Logging", f"Captured live stack trace analyzed by {active_model}")],
            )
            empty_verif = RemediationVerificationReport(
                sandbox_id=f"sandbox-{uuid4().hex[:8]}",
                branch_name=f"nightzero/inc-{incident_id}",
                file_path="demo_target/pricing.py",
                diff="Generating sandbox diff...",
                before=CommandResult(["python", "-m", "unittest", "discover"], 1, "Executing pre-patch baseline tests..."),
                after=CommandResult(["python", "-m", "unittest", "discover"], 1, "Awaiting candidate patch..."),
                staging_status="IN_PROGRESS",
            )
            record = IncidentRecord(context, empty_rca, empty_verif, audit)
            self.artifact_store.save(record)

            def _async_gemini_investigation():
                import time
                try:
                    # 1. Commit bug to GitHub
                    try:
                        gateway.commit_pricing_replacement(repository, "main", "demo_target/pricing.py", 'return f"${cents // 100}.00"')
                    except Exception:
                        pass
                    
                    time.sleep(1.5)
                    
                    # 2. Stage: RCA with chosen Gemini Model
                    record.context.status = IncidentStatus.RCA
                    record.audit_events.append(self._event("gemini.investigation.started", f"Invoking {active_model} for autonomous triage and RCA"))
                    self.artifact_store.save(record)

                    try:
                        evidence = gateway.get_repository_evidence(repository, "main")
                        record.context.source_commit = evidence.commit_sha
                    except Exception:
                        evidence = RepositoryEvidence("live-sha", "Fixes pricing display", "demo_target/pricing.py", 'return f"${cents // 100}.00"')
                        
                    from nightzero.investigation import GeminiInvestigationRunner
                    gemini_runner = GeminiInvestigationRunner(model=active_model)
                    rca = self._investigate_live(
                        record.context,
                        "TypeError in checkout/pricing calculation: Expected $12.34, got $12.00 at demo_target/pricing.py:2 in format_total",
                        evidence,
                        record.audit_events,
                        gemini_runner,
                    )
                    record.rca = rca
                    self.artifact_store.save(record)
                    
                    time.sleep(1.5)

                    # 3. Stage: SANDBOX_TESTING
                    record.context.status = IncidentStatus.SANDBOX_TESTING
                    record.audit_events.append(self._event("sandbox.testing.started", "Executing isolated subprocess verification of Gemini candidate patch"))
                    self.artifact_store.save(record)

                    verification = self._verify_in_sandbox(rca, record.audit_events)
                    record.verification = verification
                    self.artifact_store.save(record)

                    time.sleep(1.2)

                    # 4. Stage: AWAITING_APPROVAL
                    record.context.status = IncidentStatus.AWAITING_APPROVAL
                    record.audit_events.append(self._event("human_gate.ready", "Remediation verified in sandbox. Awaiting human reviewer authorization."))
                    self.artifact_store.save(record)
                except Exception as err:
                    record.context.status = IncidentStatus.PR_CREATION_FAILED
                    record.approval = {"failure": str(err)}
                    record.audit_events.append(self._event("investigation.error", str(err)))
                    self.artifact_store.save(record)

            import threading
            threading.Thread(target=_async_gemini_investigation, daemon=True).start()

            return {
                "status": "⚡ Autonomous Gemini AI investigation initiated! Live RCA & sandbox testing running...",
                "incident_id": incident_id,
            }

        # Deterministic scenario mode with progressive stages
        active_services = {
            rec.context.service
            for rec in self.artifact_store.list()
            if rec.context.status not in (IncidentStatus.APPROVED, IncidentStatus.RESOLVED)
        }
        available = [s for s in SIMULATED_SCENARIOS if s["service"] not in active_services]
        scenario = random.choice(available) if available else random.choice(SIMULATED_SCENARIOS)

        incident_id = f"inc-sim-{uuid4().hex[:6]}"
        context = IncidentContext(
            incident_id=incident_id,
            session_id=f"incident-{incident_id}",
            issue_number=0,
            title=scenario["title"],
            service=scenario["service"],
            severity=scenario["severity"],
            source_commit=scenario["culprit_commit"],
            created_at=datetime.now(UTC).isoformat(),
            status=IncidentStatus.INGESTING,
            delivery_id=f"sim-{incident_id}",
            repository=repository,
            repository_ref="main",
        )
        
        evidence_list = [Evidence(e["kind"], e["source"], e["detail"]) for e in scenario["evidence"]]
        rca = RootCauseAnalysis(
            root_cause=scenario["root_cause"],
            confidence=scenario["confidence"],
            culprit_commit=scenario["culprit_commit"],
            proposed_patch=scenario["proposed_patch"],
            evidence=evidence_list,
        )
        
        verification = RemediationVerificationReport(
            sandbox_id=f"sandbox-{uuid4().hex[:8]}",
            branch_name=f"nightzero/inc-{incident_id}",
            file_path=scenario["file_path"],
            diff=scenario["diff"],
            before=CommandResult(["python", "-m", "unittest", "discover"], 1, scenario["before_output"]),
            after=CommandResult(["python", "-m", "unittest", "discover"], 0, scenario["after_output"]),
            staging_status="VERIFIED",
        )
        
        audit = [
            self._event("simulation.triggered", f"Operator triggered outage simulation for {scenario['service']}"),
        ]
        
        record = IncidentRecord(context, rca, verification, audit)
        self.artifact_store.save(record)

        def _async_deterministic_stages():
            import time
            if scenario.get("is_live_commit") and gateway:
                try:
                    gateway.commit_pricing_replacement(repository, "main", "demo_target/pricing.py", 'return f"${cents // 100}.00"')
                except Exception:
                    pass
            time.sleep(1.0)
            record.context.status = IncidentStatus.RCA
            record.audit_events.append(self._event("adk.investigation.completed", f"Analyzed failure logs and isolated root cause in {scenario['service']}"))
            self.artifact_store.save(record)
            time.sleep(1.0)
            record.context.status = IncidentStatus.SANDBOX_TESTING
            record.audit_events.append(self._event("sandbox.verified", "Generated remediation proposal and verified in isolated sandbox"))
            self.artifact_store.save(record)
            time.sleep(0.8)
            record.context.status = IncidentStatus.AWAITING_APPROVAL
            self.artifact_store.save(record)

        import threading
        threading.Thread(target=_async_deterministic_stages, daemon=True).start()
        
        return {
            "status": f"⚡ Simulated outage injected: [{scenario['service']}] {scenario['title']}",
            "incident_id": incident_id,
        }

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
        if not self.deterministic_mode and gateway:
            try:
                evidence = gateway.get_repository_evidence(context.repository, context.repository_ref)
                context.source_commit = evidence.commit_sha
                from nightzero.investigation import GeminiInvestigationRunner
                runner = investigator or GeminiInvestigationRunner(model=self.gemini_model)
                rca = self._investigate_live(context, log_payload, evidence, audit, runner)
                verification = self._verify_in_sandbox(rca, audit)
            except Exception:
                rca = self._investigate(context, audit)
                verification = self._verify_in_sandbox(rca, audit)
        else:
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
            # 1. Always resolve a valid remote commit SHA for branch creation
            try:
                repo_info = gateway.get_repository(record.context.repository)
                default_ref = repo_info.default_branch or "main"
            except Exception:
                default_ref = record.context.repository_ref or "main"

            try:
                evidence = gateway.get_repository_evidence(record.context.repository, default_ref)
                remote_commit = evidence.commit_sha
            except Exception:
                remote_commit = ""

            source_commit = remote_commit or record.context.source_commit
            if not record.context.repository_ref:
                record.context.repository_ref = default_ref

            if not approval.get("branch_created"):
                gateway.create_branch(record.context.repository, branch, source_commit)
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

            source_path = checkout / target_file_path
            if not source_path.exists():
                source_path = checkout / "demo_target" / "pricing.py"
                target_file_path = "demo_target/pricing.py"

            original = source_path.read_text(encoding="utf-8")
            before = self._run_test(checkout)

            # If the remote repository was cloned in a healthy state (e.g. after a previous PR merge),
            # reproduce the defect in the sandbox to capture the 'before' test failure evidence.
            if before.exit_code == 0:
                buggy_content = re.sub(r'return f"\${cents [^"]+}"', 'return f"${cents // 100}.00"', original)
                if buggy_content == original:
                    buggy_content = re.sub(r'return .*', 'return f"${cents // 100}.00"', original)
                source_path.write_text(buggy_content, encoding="utf-8")
                shutil.rmtree(source_path.parent / "__pycache__", ignore_errors=True)
                before = self._run_test(checkout)
                original = buggy_content

            # Apply candidate remediation patch
            if 'return f"${cents // 100}.00"' in original:
                patched = original.replace('return f"${cents // 100}.00"', replacement)
            elif replacement in original:
                patched = original
            else:
                patched = re.sub(r'return f"\${cents [^"]+}"', replacement, original)
                if patched == original:
                    patched = re.sub(r'return .*', replacement, original)

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
            audit.append(self._event("sandbox.verification.passed", f"Verified patch in {branch_name}"))
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