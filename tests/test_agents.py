from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from nightzero.agents import (
    CodeInspectorSubagent,
    GeminiRCASubagent,
    RemediationPRSubagent,
    SandboxVerificationSubagent,
    TriageSubagent,
)
from nightzero.github import RepositoryEvidence
from nightzero.models import IncidentRecord, IncidentStatus


class AgentsTest(unittest.TestCase):
    def test_triage_subagent_creates_context_and_audit(self) -> None:
        subagent = TriageSubagent()
        context, audit = subagent.triage_log_alert(
            service_name="demo-payment-gateway",
            log_payload="TypeError in checkout/pricing calculation: Expected $12.34, got $12.00",
            delivery_id="deliv-123",
        )
        self.assertEqual(context.service, "demo-payment-gateway")
        self.assertEqual(context.status, IncidentStatus.INGESTING)
        self.assertIn("demo-payment-gateway", context.title)
        self.assertIn("TypeError", context.title)
        self.assertEqual(len(audit), 2)
        self.assertEqual(audit[0].action, "telemetry.ingested")

    def test_code_inspector_subagent(self) -> None:
        subagent = CodeInspectorSubagent()
        with self.assertRaises(RuntimeError):
            subagent.inspect_repository("test/repo", "main", gateway=None)

        gateway = MagicMock()
        gateway.get_repository_evidence.return_value = RepositoryEvidence("sha123", "msg", "demo_target/pricing.py", "content", "dev", "2026-08-25")
        evidence, audit = subagent.inspect_repository("test/repo", "main", gateway=gateway)
        self.assertEqual(evidence.commit_sha, "sha123")
        self.assertEqual(audit[0].action, "mcp.github.read")

    def test_gemini_rca_subagent(self) -> None:
        subagent = GeminiRCASubagent(model="gemini-3.7-flash")
        triage = TriageSubagent()
        context, _ = triage.triage_log_alert("demo-payment-gateway", "TypeError in pricing", "deliv-456")
        evidence = RepositoryEvidence("8f3c2a1", "commit msg", "demo_target/pricing.py", 'return f"${cents // 100}.00"')
        rca, audit = subagent.analyze_root_cause(context, "TypeError in pricing", evidence)
        self.assertIsNotNone(rca.root_cause)
        self.assertIsNotNone(rca.attribution)
        self.assertIsNotNone(rca.test_gap_analysis)
        self.assertEqual(audit[0].action, "gemini.investigation.started")
        self.assertEqual(audit[1].action, "gemini.rca.synthesized")

    def test_sandbox_verification_subagent(self) -> None:
        subagent = SandboxVerificationSubagent()
        triage = TriageSubagent()
        context, _ = triage.triage_log_alert("demo-payment-gateway", "TypeError", "deliv-789")
        evidence = RepositoryEvidence("8f3c2a1", "commit msg", "demo_target/pricing.py", 'return f"${cents // 100}.00"')
        rca, _ = GeminiRCASubagent().analyze_root_cause(context, "TypeError", evidence)
        report, audit = subagent.verify_patch(rca)
        self.assertEqual(report.staging_status, "VERIFIED")
        self.assertEqual(report.before.exit_code, 1)
        self.assertEqual(report.after.exit_code, 0)
        self.assertIn("sandbox.verified", [a.action for a in audit])

    def test_remediation_pr_subagent(self) -> None:
        subagent = RemediationPRSubagent()
        triage = TriageSubagent()
        context, _ = triage.triage_log_alert("demo-payment-gateway", "TypeError", "deliv-000", repository="test/repo")
        evidence = RepositoryEvidence("8f3c2a1", "commit msg", "demo_target/pricing.py", 'return f"${cents // 100}.00"')
        rca, _ = GeminiRCASubagent().analyze_root_cause(context, "TypeError", evidence)
        report, _ = SandboxVerificationSubagent().verify_patch(rca)
        record = IncidentRecord(context, rca, report, [])

        gateway = MagicMock()
        gateway.create_draft_pull_request.return_value = MagicMock(number=144, url="https://github.com/test/repo/pull/144")
        gateway.commit_pricing_replacement.return_value = "commit-144"

        audit = subagent.create_remediation_pr(record, "reviewer@asuracore.com", gateway)
        self.assertEqual(record.context.status, IncidentStatus.APPROVED)
        self.assertEqual(record.approval["pr_number"], 144)
        self.assertIn("github.pr.created", [a.action for a in audit])

    def test_sandbox_memory_bank_and_polyglot_discovery(self) -> None:
        import tempfile
        from pathlib import Path
        from nightzero.sandbox import ProjectSandboxAnalyzer, ProjectSandboxMemory, ProjectTestProfile
        from nightzero.store import ArtifactStore

        with tempfile.TemporaryDirectory() as temp_dir:
            ws = Path(temp_dir)
            (ws / "package.json").write_text('{"scripts": {"test": "jest --coverage"}}', encoding="utf-8")
            (ws / "tsconfig.json").write_text('{}', encoding="utf-8")

            with tempfile.TemporaryDirectory() as store_dir:
                store = ArtifactStore(Path(store_dir))
                ProjectSandboxMemory._in_memory_cache.clear()

                # First discovery: inspects manifests & learns TypeScript/jest
                profile1, from_memory1 = ProjectSandboxAnalyzer.analyze_repository("org/ts-service", ws, store)
                self.assertFalse(from_memory1)
                self.assertEqual(profile1.language, "typescript")
                self.assertEqual(profile1.test_command, ["jest", "--coverage"])

                # Second run: retrieves learned profile from Memory Bank!
                profile2, from_memory2 = ProjectSandboxAnalyzer.analyze_repository("org/ts-service", None, store)
                self.assertTrue(from_memory2)
                self.assertEqual(profile2.language, "typescript")
                self.assertEqual(profile2.test_command, ["jest", "--coverage"])


if __name__ == "__main__":
    unittest.main()
