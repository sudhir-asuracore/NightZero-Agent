from __future__ import annotations

import base64
import difflib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final
from uuid import uuid4

from nightzero.agents import (
    CodeInspectorSubagent,
    GeminiRCASubagent,
    RemediationPRSubagent,
    SandboxVerificationSubagent,
    TriageSubagent,
)
from nightzero.github import GitHubApiGateway, GitHubGateway, RepositoryEvidence
from nightzero.investigation import AdkInvestigationRunner, InvestigationRunner
from nightzero.models import (
    AuditEvent,
    BlastRadius,
    CommandResult,
    Evidence,
    GitAttribution,
    IncidentContext,
    IncidentRecord,
    IncidentStatus,
    InvestigationProposal,
    RemediationVerificationReport,
    RootCauseAnalysis,
    TestGapAnalysis,
    TimelineEvent,
)
from nightzero.store import IncidentStore

logger = logging.getLogger(__name__)

TEST_COMMAND = ["python", "-m", "unittest", "demo_target.test_pricing"]
DEMO_APPROVAL_TOKEN: Final = "nightzero-demo"
DEFAULT_TARGET_REPOSITORY_URL: Final = os.environ.get("NIGHTZERO_TARGET_REPO_URL", "")


def compute_error_signature(service_name: str, log_payload: str) -> str:
    """Dynamically derives a specific error signature from service, exception class, and normalized message."""
    clean = log_payload.strip()
    try:
        parsed = json.loads(clean)
        if isinstance(parsed, dict):
            clean = str(parsed.get("message") or parsed.get("error") or parsed.get("event") or clean)
    except Exception:
        pass

    lines = [l.strip() for l in clean.splitlines() if l.strip()]
    err_line = next((l for l in reversed(lines) if any(kw in l for kw in ["Error", "Exception", "Fault", "Panic", "Failure", "assert ", "AssertionError"])), clean[:120])
    
    # Normalize out timestamps, hex addresses, UUIDs, temp directories
    norm = re.sub(r'0x[0-9a-fA-F]+', '', err_line)
    norm = re.sub(r'[0-9a-fA-F-]{32,36}', '', norm)
    norm = re.sub(r'/tmp/[a-zA-Z0-9_]+', '', norm)
    norm = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?', '', norm)
    
    tokens = re.findall(r'[a-zA-Z0-9_]{3,}', norm)
    key_part = "_".join(t.lower() for t in tokens[:6])
    return f"{service_name}:{key_part}" if key_part else f"{service_name}:generic"


MODULE_MAP: Final = {
    "demo_target/pricing.py": "demo_target/pricing.py",
    "format_total": "demo_target/pricing.py",
    "pricing": "demo_target/pricing.py",
    "checkout": "demo_target/pricing.py",
    "demo_target/discounts.py": "demo_target/discounts.py",
    "apply_discount": "demo_target/discounts.py",
    "discount": "demo_target/discounts.py",
    "demo_target/currency.py": "demo_target/currency.py",
    "convert_currency": "demo_target/currency.py",
    "currency": "demo_target/currency.py",
    "demo_target/billing.py": "demo_target/billing.py",
    "calculate_proration": "demo_target/billing.py",
    "billing": "demo_target/billing.py",
    "prorate": "demo_target/billing.py",
    "demo_target/tax.py": "demo_target/tax.py",
    "calculate_tax": "demo_target/tax.py",
    "tax": "demo_target/tax.py",
}


def extract_error_core(log_payload: str) -> tuple[str, str]:
    """Extracts (module_or_target, normalized_message) from log payload."""
    clean = log_payload.strip()
    file_path = ""
    for kw, fpath in MODULE_MAP.items():
        if kw in clean or kw in clean.lower():
            file_path = fpath
            break
    try:
        parsed = json.loads(clean)
        if isinstance(parsed, dict):
            msg = str(parsed.get("message") or parsed.get("error") or parsed.get("event") or clean)
            return file_path, msg
    except Exception:
        pass
    lines = [l.strip() for l in clean.splitlines() if l.strip()]
    err_line = next((l for l in reversed(lines) if any(kw in l for kw in ["Error", "Exception", "Fault", "Panic", "Failure", "assert", "Discrepancy", "mismatch"])), clean[:120])
    return file_path, err_line


def compute_incident_similarity(
    incoming_service: str,
    incoming_log: str,
    existing_record: IncidentRecord,
) -> float:
    """Calculates semantic and structural similarity between an incoming alert and an existing incident."""
    # 1. Service must match
    if existing_record.context.service != incoming_service:
        return 0.0

    # 2. If the incident is already marked Done / Deployed, do not merge new errors into it
    if existing_record.context.status == IncidentStatus.DEPLOYED:
        return 0.0

    incoming_file, incoming_msg = extract_error_core(incoming_log)
    existing_file, existing_msg = extract_error_core(existing_record.context.title)

    # 3. If both point to the same target file / module:
    if incoming_file and existing_file and incoming_file == existing_file:
        return 0.95

    # 4. Compare normalized core error messages
    norm_inc = re.sub(r'[^a-zA-Z0-9]', '', incoming_msg.lower())
    norm_exist = re.sub(r'[^a-zA-Z0-9]', '', existing_msg.lower())
    if norm_inc and norm_exist:
        ratio = difflib.SequenceMatcher(None, norm_inc, norm_exist).ratio()
        if ratio >= 0.70:
            return ratio

    # 5. If modules are explicitly different:
    if incoming_file and existing_file and incoming_file != existing_file:
        return 0.15

    return difflib.SequenceMatcher(None, norm_inc, norm_exist).ratio()


AVAILABLE_GEMINI_MODELS: Final = [
    {
        "id": "gemini-2.5-flash",
        "name": "Gemini 2.5 Flash",
        "badge": "VERTEX AI / PRODUCTION",
        "description": "Next-gen high-throughput multimodal model on Vertex AI with zero daily quotas.",
        "latency": "~0.8s",
    },
    {
        "id": "gemini-2.5-pro",
        "name": "Gemini 2.5 Pro",
        "badge": "MAX REASONING",
        "description": "Flagship frontier intelligence model for ultra-deep root cause forensics and complex patch synthesis on Vertex AI.",
        "latency": "~2.5s",
    },
    {
        "id": "gemini-3.7-flash",
        "name": "Gemini 3.7 Flash",
        "badge": "PREVIEW / EXPERIMENTAL",
        "description": "Frontier hybrid dynamic thinking model for complex multi-step reasoning.",
        "latency": "~1.2s",
    },
]


class NightZeroWorkflow:
    """Production autonomous SRE orchestration engine powered by Gemini multi-subagents."""

    def __init__(
        self, project_root: Path, artifact_store: IncidentStore, target_repository_url: str | None = None
    ) -> None:
        self.project_root = project_root
        self.artifact_store = artifact_store
        self.target_repository_url = target_repository_url or os.environ.get(
            "NIGHTZERO_TARGET_REPOSITORY_URL", DEFAULT_TARGET_REPOSITORY_URL
        )
        self._incident_lock = threading.Lock()

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

    @property
    def notification_settings(self) -> dict[str, Any]:
        from nightzero.notifications import DEFAULT_NOTIFICATION_SETTINGS
        saved = self.artifact_store.get_setting("notifications", None)
        if isinstance(saved, dict):
            return {**DEFAULT_NOTIFICATION_SETTINGS, **saved}
        return DEFAULT_NOTIFICATION_SETTINGS

    def set_notification_settings(self, settings: dict[str, Any]) -> dict[str, Any]:
        self.artifact_store.set_setting("notifications", settings)
        return settings

    def _notify(self, event_type: str, record: IncidentRecord) -> None:
        try:
            from nightzero.notifications import NotificationDispatcher
            NotificationDispatcher.dispatch_incident_notification(event_type, record, self.notification_settings)
        except Exception as exc:
            logger.warning("Notification dispatch failed: %s", exc)

    def simulate_outage(
        self,
        repository: str | None = None,
        target_path: str = "demo_target/pricing.py",
        gateway: GitHubGateway | None = None,
    ) -> dict[str, str]:
        """Injects a dynamic code regression commit into the target GitHub repo on main."""
        target_repo = repository or os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "")
        if not target_repo:
            return {
                "status": "⚠️ Target repository is not configured. Set NIGHTZERO_GITHUB_REPOSITORY in Cloud Run environment or pass 'repository' in request body.",
                "incident_id": "error",
            }
        gw = gateway or GitHubApiGateway()

        dynamic_scenarios = [
            {
                "name": "Decimal Cents Floor Truncation",
                "file": "demo_target/pricing.py",
                "description": "Floor division drops fractional remainder from formatted checkout totals in format_total",
                "replacement": 'return f"${cents // 100}.00"',
            },
            {
                "name": "Inverted Discount Calculation",
                "file": "demo_target/discounts.py",
                "description": "Inverted discount formula applies opposite percentage in apply_discount",
                "replacement": 'return max(0, cents - int(round(cents * ((100.0 - discount_pct) / 100.0))))',
            },
            {
                "name": "Integer Truncation in FX Conversion",
                "file": "demo_target/currency.py",
                "description": "Integer truncation before multiplication drops currency cents in convert_currency",
                "replacement": 'return int(cents * int(fx_rate))',
            },
            {
                "name": "Proration Division Scaling Discrepancy",
                "file": "demo_target/billing.py",
                "description": "Premature integer division truncates prorated subscription charges in calculate_proration",
                "replacement": 'return (monthly_cents // total_days) * days_used',
            },
            {
                "name": "Basis Points Divisor Error in Tax",
                "file": "demo_target/tax.py",
                "description": "Tax basis points divided by 100 instead of 10000, inflating tax 100x in calculate_tax_and_fees",
                "replacement": 'return int(round(subtotal_cents * (tax_rate_bps / 100.0)))',
            },
            {
                "name": "Missing Currency Prefix",
                "file": "demo_target/pricing.py",
                "description": "Omission of the required '$' currency symbol prefix in customer totals",
                "replacement": 'return f"{cents / 100:.2f}"',
            },
        ]

        count_key = "simulation_rotation_count"
        rotation_idx = int(self.artifact_store.get_setting(count_key, 0))
        scenario = dynamic_scenarios[rotation_idx % len(dynamic_scenarios)]
        self.artifact_store.set_setting(count_key, rotation_idx + 1)
        target_file = scenario["file"]

        try:
            commit_sha = gw.commit_pricing_replacement(
                target_repo, "main", target_file, scenario["replacement"]
            )

            payload_templates = {
                "demo_target/pricing.py": {
                    "event": "pricing_calculation_failed",
                    "message": f"Calculation Discrepancy in checkout/pricing: {scenario['description']} at demo_target/pricing.py:2 in format_total",
                    "service": "demo-payment-gateway",
                    "stacktrace": "Traceback (most recent call last):\n  File 'demo_target/pricing.py', in format_total\nAssertionError: '$12.34' != '$12.00'",
                },
                "demo_target/discounts.py": {
                    "event": "discount_calculation_failed",
                    "message": f"Discount calculation mismatch: {scenario['description']} at demo_target/discounts.py:5 in apply_discount",
                    "service": "demo-payment-gateway",
                    "stacktrace": "Traceback (most recent call last):\n  File 'demo_target/discounts.py', in apply_discount\nAssertionError: Discount calculation mismatch",
                },
                "demo_target/currency.py": {
                    "event": "currency_conversion_failed",
                    "message": f"FX conversion discrepancy: {scenario['description']} at demo_target/currency.py:4 in convert_currency",
                    "service": "demo-payment-gateway",
                    "stacktrace": "Traceback (most recent call last):\n  File 'demo_target/currency.py', in convert_currency\nAssertionError: FX conversion discrepancy",
                },
                "demo_target/billing.py": {
                    "event": "billing_proration_failed",
                    "message": f"Billing proration mismatch: {scenario['description']} at demo_target/billing.py:4 in calculate_proration",
                    "service": "demo-payment-gateway",
                    "stacktrace": "Traceback (most recent call last):\n  File 'demo_target/billing.py', in calculate_proration\nAssertionError: Billing proration mismatch",
                },
                "demo_target/tax.py": {
                    "event": "tax_calculation_failed",
                    "message": f"Tax calculation discrepancy: {scenario['description']} at demo_target/tax.py:4 in calculate_tax_and_fees",
                    "service": "demo-payment-gateway",
                    "stacktrace": "Traceback (most recent call last):\n  File 'demo_target/tax.py', in calculate_tax_and_fees\nAssertionError: Tax calculation discrepancy",
                },
            }

            raw_payload = payload_templates.get(
                target_file,
                {
                    "event": "simulation_outage",
                    "message": f"Service failure: {scenario['description']} in {target_file}",
                    "service": "demo-payment-gateway",
                },
            )
            sim_delivery_id = f"sim-{commit_sha[:8]}-{int(time.time())}"
            incident_rec = self.run_gcp_logging_incident(
                delivery_id=sim_delivery_id,
                service_name="demo-payment-gateway",
                log_payload=json.dumps(raw_payload),
                severity="ERROR",
                gateway=gw,
                async_pipeline=True,
            )

            return {
                "status": f"⚡ Injected '{scenario['name']}' regression ({commit_sha[:7]}) into '{target_file}' on GitHub main! NightZero autonomous investigation & sandbox verification running.",
                "incident_id": incident_rec.context.incident_id,
                "scenario": scenario["name"],
                "target_file": target_file,
            }
        except Exception as exc:
            logger.error("Failed committing regression to GitHub: %s", exc)
            return {
                "status": f"⚠️ Failed to commit regression to GitHub: {str(exc)}",
                "incident_id": "error",
            }

    def run_gcp_logging_incident(
        self,
        delivery_id: str,
        service_name: str,
        log_payload: str,
        severity: str = "CRITICAL",
        gateway: GitHubGateway | None = None,
        investigator: InvestigationRunner | None = None,
        async_pipeline: bool = False,
    ) -> IncidentRecord:
        with self._incident_lock:
            # 1. Deduplicate by exact delivery_id
            for existing in self.artifact_store.list():
                if existing.context.delivery_id == delivery_id:
                    return existing

            # 2. Check similarity with open (unresolved) incidents for the same service
            best_match: IncidentRecord | None = None
            highest_sim = 0.0
            for existing in self.artifact_store.list():
                sim = compute_incident_similarity(service_name, log_payload, existing)
                if sim >= 0.70 and sim > highest_sim:
                    highest_sim = sim
                    best_match = existing

            if best_match:
                # Increment occurrence counter on the existing incident
                best_match.context.occurrence_count = getattr(best_match.context, "occurrence_count", 1) + 1
                best_match.context.last_seen_at = datetime.now(UTC).isoformat()
                
                detail_msg = (
                    f"Repeated production alert ({best_match.context.occurrence_count} occurrences) in {service_name} "
                    f"(Similarity: {int(highest_sim * 100)}%). Deduplicated with open incident {best_match.context.incident_id}."
                )
                now_iso = datetime.now(UTC).isoformat()
                existing_repeated = next((ev for ev in best_match.audit_events if ev.action == "telemetry.repeated"), None)
                if existing_repeated:
                    existing_repeated.detail = detail_msg
                    existing_repeated.timestamp = now_iso
                else:
                    best_match.audit_events.append(self._event("telemetry.repeated", detail_msg))

                self.artifact_store.save(best_match)
                logger.info(
                    "Deduplicated repeating log into incident %s (occurrence #%d, similarity %.2f)",
                    best_match.context.incident_id,
                    best_match.context.occurrence_count,
                    highest_sim,
                )
                return best_match

            # 3. New unique incident: Triage Subagent
            triage_subagent = TriageSubagent()
            context, triage_audit = triage_subagent.triage_log_alert(
                service_name=service_name,
                log_payload=log_payload,
                delivery_id=delivery_id,
                repository=os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", ""),
                severity=severity,
            )
            claimed_id = self.artifact_store.claim_delivery_id(delivery_id, context.incident_id)
            if claimed_id:
                existing = self.artifact_store.get(claimed_id)
                if existing:
                    return existing

            # Immediately persist in-flight record so subsequent webhooks immediately see it
            initial_record = IncidentRecord(context, None, None, list(triage_audit))
            self.artifact_store.save(initial_record)
            self._notify("detected", initial_record)

        audit = list(triage_audit)

        if async_pipeline:
            worker = threading.Thread(
                target=self._execute_investigation_and_verification,
                args=(context, log_payload, audit, gateway, investigator),
                daemon=True,
            )
            worker.start()
            return initial_record

        return self._execute_investigation_and_verification(context, log_payload, audit, gateway, investigator)

    def _execute_investigation_and_verification(
        self,
        context: IncidentContext,
        log_payload: str,
        audit: list[AuditEvent],
        gateway: GitHubGateway | None = None,
        investigator: InvestigationRunner | None = None,
    ) -> IncidentRecord:
        try:
            # 4. Code Inspector Subagent: Dynamically locate failing module
            detected_target, _ = extract_error_core(log_payload)
            detected_target = detected_target or "demo_target/pricing.py"

            gw = gateway or GitHubApiGateway()
            inspector_subagent = CodeInspectorSubagent()
            evidence, inspect_audit = inspector_subagent.inspect_repository(
                repository=context.repository,
                ref=context.repository_ref,
                gateway=gw,
                target_path=detected_target,
            )
            audit.extend(inspect_audit)
            context.source_commit = evidence.commit_sha
            context.status = IncidentStatus.RCA
            self.artifact_store.save(IncidentRecord(context, None, None, list(audit)))

            # 5. Gemini RCA Subagent
            rca_subagent = GeminiRCASubagent(model=self.gemini_model)
            rca, rca_audit = rca_subagent.analyze_root_cause(
                context=context,
                log_payload=log_payload,
                evidence=evidence,
                investigator=investigator,
            )
            audit.extend(rca_audit)
            context.status = IncidentStatus.SANDBOX_TESTING
            self.artifact_store.save(IncidentRecord(context, rca, None, list(audit)))

            # 6. Sandbox Verification Subagent
            sandbox_subagent = SandboxVerificationSubagent(store=self.artifact_store, gemini_model=self.gemini_model)
            verification, sandbox_audit = sandbox_subagent.verify_patch(
                rca=rca,
                target_path=evidence.path,
                branch_name=self._branch_name(context.incident_id),
                target_content=evidence.content,
                repository=context.repository,
            )
            audit.extend(sandbox_audit)

            audit.append(self._event("human_gate.ready", "Remediation verified in isolated sandbox. Paused at Human Authorization Gate."))
            context.status = IncidentStatus.AWAITING_APPROVAL

            # Re-fetch latest record state to preserve any occurrence_count increments that occurred concurrently
            latest = self.artifact_store.get(context.incident_id)
            if latest:
                context.occurrence_count = getattr(latest.context, "occurrence_count", 1)
                context.last_seen_at = getattr(latest.context, "last_seen_at", context.last_seen_at)
                for ev in latest.audit_events:
                    if ev.action == "telemetry.repeated" and ev not in audit:
                        audit.append(ev)

            final_record = IncidentRecord(context, rca, verification, list(audit))
            self.artifact_store.save(final_record)
            self._notify("awaiting_approval", final_record)
            return final_record
        except Exception as exc:
            logger.exception("Error executing investigation pipeline for %s: %s", context.incident_id, exc)
            audit.append(self._event("pipeline.error", f"Investigation pipeline encountered error: {exc}"))
            record = IncidentRecord(context, None, None, list(audit))
            self.artifact_store.save(record)
            return record

    def run_seeded_issue(self, gateway: GitHubGateway | None = None) -> IncidentRecord:
        context = IncidentContext.from_issue(
            issue_number=142,
            title="Checkout totals are rounded down",
        )
        gw = gateway or GitHubApiGateway()
        inspector = CodeInspectorSubagent()
        evidence, inspect_audit = inspector.inspect_repository(context.repository, "main", gateway=gw)
        rca_subagent = GeminiRCASubagent(model=self.gemini_model)
        rca, rca_audit = rca_subagent.analyze_root_cause(context, "TypeError: expected $12.34 got $12.00", evidence)
        sandbox_subagent = SandboxVerificationSubagent(store=self.artifact_store, gemini_model=self.gemini_model)
        verification, sandbox_audit = sandbox_subagent.verify_patch(
            rca=rca,
            target_path=evidence.path,
            branch_name=self._branch_name(context.incident_id),
            target_content=evidence.content,
            repository=context.repository,
        )
        audit = [self._event("triage.issue_parsed", "GitHub issue #142 framed as incident context"), *inspect_audit, *rca_audit, *sandbox_audit]
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

        inv = investigator or AdkInvestigationRunner()
        proposal = inv.investigate(context, issue.body, evidence)
        if proposal.file_path != "demo_target/pricing.py":
            raise ValueError(f"Candidate patch ({proposal.file_path}) is outside the permitted remediation scope")

        rca_subagent = GeminiRCASubagent(model=self.gemini_model)
        rca, rca_audit = rca_subagent.analyze_root_cause(
            context=context,
            log_payload=issue.body,
            evidence=evidence,
            investigator=inv,
        )
        audit.extend(rca_audit)

        sandbox_subagent = SandboxVerificationSubagent()
        verification, sandbox_audit = sandbox_subagent.verify_patch(
            rca=rca,
            target_path=evidence.path or "demo_target/pricing.py",
            branch_name=self._branch_name(context.incident_id),
        )
        audit.extend(sandbox_audit)

        context.status = IncidentStatus.AWAITING_APPROVAL
        record = IncidentRecord(context, rca, verification, audit)
        self.artifact_store.save(record)
        return record

    def _clone_url(self) -> str:
        repo = os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "owner/repository")
        return f"https://github.com/{repo}.git"

    def _git_environment(self) -> dict[str, str]:
        token = os.environ.get("NIGHTZERO_GIT_CLONE_TOKEN", "")
        env = os.environ.copy()
        if token:
            env["GIT_ASKPASS"] = "echo"
        return {"GIT_TERMINAL_PROMPT": "0"}

    def _run_git(self, args: list[str], environment: dict[str, str] | None = None) -> CommandResult:
        res = subprocess.run(["git", *args], capture_output=True, text=True, env=environment or os.environ.copy())
        if res.returncode != 0:
            raise RuntimeError("Git sandbox setup failed")
        return CommandResult(["git", *args], res.returncode, res.stdout)

    def approve(self, record: IncidentRecord, actor: str, token: str | None, gateway: GitHubGateway | None = None, require_demo_token: bool = True) -> IncidentRecord:
        if require_demo_token and token != DEMO_APPROVAL_TOKEN:
            raise PermissionError("Approval requires the configured demo authorization token")
        if record.context.status not in (IncidentStatus.AWAITING_APPROVAL, IncidentStatus.PR_CREATION_FAILED):
            raise ValueError("Only verified incidents can be approved")
        
        if gateway is not None:
            return self._approve_live(record, actor, gateway)
        
        record.context.status = IncidentStatus.APPROVED
        record.approval = {
            "actor": actor,
            "approved_at": datetime.now(UTC).isoformat(),
            "action": "SIMULATED_PULL_REQUEST_CREATED",
            "branch": record.verification.branch_name if record.verification else f"nightzero/{record.context.incident_id}",
        }
        record.audit_events.append(
            self._event("approval.authorized", f"{actor} authorized pull request")
        )
        self.artifact_store.save(record)
        self._notify("approved", record)
        return record

    def batch_approve(
        self,
        incident_ids: list[str],
        actor: str,
        token: str | None,
        gateway: GitHubGateway | None = None,
        require_demo_token: bool = True,
    ) -> dict[str, Any]:
        if require_demo_token and token != DEMO_APPROVAL_TOKEN:
            raise PermissionError("Batch approval requires the configured demo authorization token")
        if not incident_ids:
            raise ValueError("No incident IDs provided for batch approval")

        records: list[IncidentRecord] = []
        for inc_id in incident_ids:
            rec = self.artifact_store.get(inc_id)
            if not rec:
                raise ValueError(f"Incident {inc_id} not found")
            if rec.context.status not in (IncidentStatus.AWAITING_APPROVAL, IncidentStatus.PR_CREATION_FAILED):
                raise ValueError(f"Incident {inc_id} is in status {rec.context.status}, not ready for batch approval")
            records.append(rec)

        if gateway is not None:
            pr_subagent = RemediationPRSubagent()
            result_payload, audit_events = pr_subagent.create_consolidated_remediation_pr(records, actor, gateway)
            for rec in records:
                rec.context.status = IncidentStatus.APPROVED
                rec.approval = {
                    "actor": actor,
                    "approved_at": result_payload["approved_at"],
                    "action": result_payload["action"],
                    "branch": result_payload["branch"],
                    "pr_number": result_payload["pr_number"],
                    "pr_url": result_payload["pr_url"],
                    "batch_id": result_payload["batch_id"],
                }
                rec.audit_events.extend(audit_events)
                self.artifact_store.save(rec)
                self._notify("approved", rec)
            return {
                "batch_id": result_payload["batch_id"],
                "branch": result_payload["branch"],
                "pr_number": result_payload["pr_number"],
                "pr_url": result_payload["pr_url"],
                "incident_ids": [r.context.incident_id for r in records],
                "incidents": [r.to_dict() for r in records],
            }

        # Simulated fallback (e.g. in tests or when no live gateway configured)
        batch_id = f"bundle-{uuid4().hex[:8]}"
        simulated_branch = f"nightzero/release-{batch_id}"
        sim_approval = {
            "actor": actor,
            "approved_at": datetime.now(UTC).isoformat(),
            "action": "SIMULATED_CONSOLIDATED_PULL_REQUEST_CREATED",
            "branch": simulated_branch,
            "pr_number": 999,
            "pr_url": "https://github.com/example/repo/pull/999",
            "batch_id": batch_id,
        }
        for rec in records:
            rec.context.status = IncidentStatus.APPROVED
            rec.approval = dict(sim_approval)
            rec.audit_events.append(
                self._event("batch.approval.authorized", f"{actor} authorized batch consolidation ({batch_id})")
            )
            self.artifact_store.save(rec)
            self._notify("approved", rec)

        return {
            "batch_id": batch_id,
            "branch": simulated_branch,
            "pr_number": 999,
            "pr_url": "https://github.com/example/repo/pull/999",
            "incident_ids": [r.context.incident_id for r in records],
            "incidents": [r.to_dict() for r in records],
        }

    def _approve_live(self, record: IncidentRecord, actor: str, gateway: GitHubGateway) -> IncidentRecord:
        pr_subagent = RemediationPRSubagent()
        pr_audit = pr_subagent.create_remediation_pr(record, actor, gateway)
        record.audit_events.extend(pr_audit)
        self.artifact_store.save(record)
        if record.context.status == IncidentStatus.APPROVED:
            self._notify("approved", record)
        return record

    def handle_pull_request_merged(
        self, repository: str, pr_number: int, pr_url: str = "", branch: str = "", merged_by: str = ""
    ) -> IncidentRecord | None:
        updated_records: list[IncidentRecord] = []
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
                    self._notify("approved", record)
                updated_records.append(record)
        return updated_records[0] if updated_records else None

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
                        self._event("github.pull_request.merged", f"Pull request #{record.approval['pr_number']} verified as merged on GitHub. Incident resolved (deploying to production).")
                    )
                    self.artifact_store.save(record)
            except Exception:
                pass
        return record

    def mark_incident_deployed(self, incident_id: str, actor: str = "operator") -> IncidentRecord:
        record = self.artifact_store.get(incident_id)
        if not record:
            raise ValueError(f"Incident {incident_id} not found")
        record.context.status = IncidentStatus.DEPLOYED
        now_iso = datetime.now(UTC).isoformat()
        if record.approval:
            record.approval["deployed_at"] = now_iso
            record.approval["action"] = "DEPLOYED_TO_PRODUCTION"
            record.approval["completed_by"] = actor
        record.audit_events.append(
            self._event("incident.completed", f"Incident {incident_id} marked as Done / Deployed by {actor}.")
        )
        self.artifact_store.save(record)
        return record

    def batch_mark_done(self, incident_ids: list[str], actor: str = "operator") -> list[IncidentRecord]:
        updated: list[IncidentRecord] = []
        now_iso = datetime.now(UTC).isoformat()
        for iid in incident_ids:
            record = self.artifact_store.get(iid)
            if not record:
                continue
            record.context.status = IncidentStatus.DEPLOYED
            if record.approval:
                record.approval["deployed_at"] = now_iso
                record.approval["action"] = "DEPLOYED_TO_PRODUCTION"
                record.approval["completed_by"] = actor
            record.audit_events.append(
                self._event("incident.completed", f"Incident {iid} marked as Done / Deployed in batch by {actor}.")
            )
            self.artifact_store.save(record)
            updated.append(record)
        return updated

    @staticmethod
    def _branch_name(incident_id: str) -> str:
        sanitized = re.sub(r"[^a-z0-9-]+", "-", incident_id.lower()).strip("-")
        if not sanitized:
            raise ValueError("Incident identifier cannot produce a Git branch name")
        return f"nightzero/{sanitized}"

    def _event(self, action: str, detail: str) -> AuditEvent:
        return AuditEvent(action=action, timestamp=datetime.now(UTC).isoformat(), detail=detail)
