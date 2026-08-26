import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nightzero.github import GitHubGateway, GitHubIssue, GitHubPullRequest, RepositoryEvidence
from nightzero.models import IncidentContext, IncidentRecord, IncidentStatus, InvestigationProposal
from nightzero.store import ArtifactStore
from nightzero.workflow import DEMO_APPROVAL_TOKEN, NightZeroWorkflow


class RecordingGitHubGateway(GitHubGateway):
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fail_comment = False

    def get_issue(self, repository: str, issue_number: int) -> GitHubIssue:
        return GitHubIssue(issue_number, "Checkout totals are rounded down", "https://github.com/example/repo/issues/142", "Expected $12.34; received $12.00.", "main")

    def get_repository_evidence(self, repository: str, ref: str, path: str = "demo_target/pricing.py") -> RepositoryEvidence:
        return RepositoryEvidence("source-sha", "Regression", path, 'return f"${cents // 100}.00"')

    def create_branch(self, repository: str, branch: str, source_commit: str) -> None:
        self.calls.append("branch")

    def commit_pricing_replacement(self, repository: str, branch: str, file_path: str, replacement: str) -> str:
        self.calls.append("commit")
        self.assert_replacement(replacement)
        return "commit-sha"

    def create_draft_pull_request(self, repository: str, branch: str, base: str, title: str, body: str) -> GitHubPullRequest:
        self.calls.append("pull-request")
        return GitHubPullRequest(73, "https://github.com/example/repo/pull/73")

    def add_issue_comment(self, repository: str, issue_number: int, body: str) -> None:
        self.calls.append("comment")
        if self.fail_comment:
            raise RuntimeError("GitHub post failed: comment unavailable")

    @staticmethod
    def assert_replacement(replacement: str) -> None:
        if replacement != 'return f"${cents / 100:.2f}"':
            raise AssertionError("unexpected replacement")


class FixedInvestigator:
    def investigate(self, context, issue_body, evidence) -> InvestigationProposal:
        return InvestigationProposal("Integer division drops cents from checkout totals.", 0.99, "Render cents / 100 with two decimal places.", "demo_target/pricing.py", 'return f"${cents / 100:.2f}"')


class NightZeroWorkflowTest(unittest.TestCase):
    def test_seeded_issue_is_verified_without_changing_target(self) -> None:
        root = Path(__file__).parents[1]
        target = root.parent / "NightZero-TestProject" / "demo_target" / "pricing.py"
        original = target.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as artifacts:
            record = NightZeroWorkflow(
                root, ArtifactStore(Path(artifacts)), str(target.parents[1])
            ).run_seeded_issue(gateway=RecordingGitHubGateway())
            saved = Path(artifacts, f"{record.context.incident_id}.json")

            self.assertEqual("AWAITING_APPROVAL", record.context.status)
            self.assertNotEqual(0, record.verification.before.exit_code)
            self.assertEqual(0, record.verification.after.exit_code)
            self.assertIn("cents / 100", record.verification.diff)
            self.assertTrue(saved.exists())
            self.assertEqual("VERIFIED", json.loads(saved.read_text())["verification"]["staging_status"])
        self.assertEqual(original, target.read_text(encoding="utf-8"))

    def test_only_authorized_reviewer_can_approve_verified_proposal(self) -> None:
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as artifacts:
            workflow = NightZeroWorkflow(
                root, ArtifactStore(Path(artifacts)), str(root.parent / "NightZero-TestProject")
            )
            record = workflow.run_seeded_issue(gateway=RecordingGitHubGateway())
            with self.assertRaises(PermissionError):
                workflow.approve(record, "on-call", "wrong-token")

            workflow.approve(record, "on-call", DEMO_APPROVAL_TOKEN)
            self.assertEqual("APPROVED", record.context.status)
            self.assertEqual("SIMULATED_PULL_REQUEST_CREATED", record.approval["action"])

    def test_live_approval_orders_writes_and_persists_pull_request_details(self) -> None:
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as artifacts:
            store = ArtifactStore(Path(artifacts))
            workflow = NightZeroWorkflow(root, store, str(root.parent / "NightZero-TestProject"))
            gateway = RecordingGitHubGateway()
            record = workflow.run_labeled_issue("delivery-live", "example/repo", 142, gateway, FixedInvestigator())

            approved = workflow.approve(record, "on-call", DEMO_APPROVAL_TOKEN, gateway)

            self.assertEqual(["branch", "commit", "pull-request", "comment"], gateway.calls)
            self.assertEqual(IncidentStatus.APPROVED, approved.context.status)
            self.assertEqual("nightzero/" + approved.context.incident_id, approved.approval["branch"])
            self.assertEqual("commit-sha", approved.approval["commit_sha"])
            self.assertEqual(73, approved.approval["pr_number"])
            self.assertEqual("https://github.com/example/repo/pull/73", store.get(approved.context.incident_id).approval["pr_url"])

    def test_live_approval_recovers_after_comment_failure_without_duplicate_pull_request(self) -> None:
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as artifacts:
            store = ArtifactStore(Path(artifacts))
            workflow = NightZeroWorkflow(root, store, str(root.parent / "NightZero-TestProject"))
            gateway = RecordingGitHubGateway()
            record = workflow.run_labeled_issue("delivery-retry", "example/repo", 142, gateway, FixedInvestigator())
            gateway.fail_comment = True

            failed = workflow.approve(record, "on-call", DEMO_APPROVAL_TOKEN, gateway)

            self.assertEqual(IncidentStatus.PR_CREATION_FAILED, failed.context.status)
            self.assertEqual(73, failed.approval["pr_number"])
            self.assertIn("comment unavailable", failed.approval["failure"])
            gateway.fail_comment = False
            recovered = workflow.approve(store.get(record.context.incident_id), "on-call", DEMO_APPROVAL_TOKEN, gateway)

            self.assertEqual(IncidentStatus.APPROVED, recovered.context.status)
            self.assertEqual(["branch", "commit", "pull-request", "comment", "comment"], gateway.calls)

    def test_clone_credential_is_not_in_sandbox_failure(self) -> None:
        root = Path(__file__).parents[1]
        workflow = NightZeroWorkflow(root, ArtifactStore(Path(tempfile.mkdtemp())), "https://example.invalid/repository.git")
        with patch.dict("os.environ", {"NIGHTZERO_GIT_CLONE_TOKEN": "secret-clone-token", "NIGHTZERO_GITHUB_REPOSITORY": "owner/repository"}):
            self.assertEqual("https://github.com/owner/repository.git", workflow._clone_url())
            environment = workflow._git_environment()
            self.assertNotIn("secret-clone-token", " ".join(environment.values()))
            with patch("subprocess.run") as run:
                run.return_value.returncode = 1
                run.return_value.stderr = "https://secret-clone-token@github.com/owner/repository.git"
                with self.assertRaisesRegex(RuntimeError, r"^Git sandbox setup failed$"):
                    workflow._run_git(["clone", "ignored"], environment=environment)

    def test_gemini_model_setting(self) -> None:
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as artifacts:
            store = ArtifactStore(Path(artifacts))
            workflow = NightZeroWorkflow(root, store, str(root.parent / "NightZero-TestProject"))
            self.assertEqual("gemini-3.7-flash", workflow.gemini_model)
            workflow.set_gemini_model("gemini-3.5-pro")
            self.assertEqual("gemini-3.5-pro", workflow.gemini_model)
            # Test invalid model resets/defaults to gemini-3.7-flash
            workflow.set_gemini_model("invalid-model")
            self.assertEqual("gemini-3.7-flash", workflow.gemini_model)

    def test_recurring_incident_deduplication_increments_counter(self) -> None:
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as artifacts:
            store = ArtifactStore(Path(artifacts))
            workflow = NightZeroWorkflow(root, store, str(root.parent / "NightZero-TestProject"))
            
            # First occurrence
            inc1 = workflow.run_gcp_logging_incident(
                delivery_id="deliv-101",
                service_name="demo-payment-gateway",
                log_payload="AssertionError: '$12.34' != '$12.00' in format_total(1234)",
                gateway=RecordingGitHubGateway(),
            )
            self.assertEqual(1, inc1.context.occurrence_count)
            self.assertEqual(1, len(store.list()))

            # Second occurrence of the same error for demo-payment-gateway
            inc2 = workflow.run_gcp_logging_incident(
                delivery_id="deliv-102",
                service_name="demo-payment-gateway",
                log_payload="AssertionError: '$12.34' != '$12.00' in format_total(1234)",
                gateway=RecordingGitHubGateway(),
            )
            self.assertEqual(inc1.context.incident_id, inc2.context.incident_id)
            self.assertEqual(2, inc2.context.occurrence_count)
            self.assertEqual(1, len(store.list()))
            self.assertIn("telemetry.repeated", [a.action for a in inc2.audit_events])

    def test_inflight_incident_deduplication(self) -> None:
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as artifacts:
            store = ArtifactStore(Path(artifacts))
            workflow = NightZeroWorkflow(root, store, str(root.parent / "NightZero-TestProject"))

            # Simulate an incident currently in INGESTING status
            from nightzero.agents import TriageSubagent
            context, audit = TriageSubagent().triage_log_alert(
                service_name="demo-payment-gateway",
                log_payload="AssertionError: '$12.34' != '$12.00' in format_total(1234)",
                delivery_id="deliv-first-11",
            )
            record = IncidentRecord(context, None, None, audit)
            store.save(record)

            # An incoming webhook arrives while the previous is still in-flight
            dedup = workflow.run_gcp_logging_incident(
                delivery_id="deliv-concurrent-99",
                service_name="demo-payment-gateway",
                log_payload="AssertionError: '$12.34' != '$12.00' in format_total(1234)",
            )
            self.assertEqual(record.context.incident_id, dedup.context.incident_id)
            self.assertEqual(2, dedup.context.occurrence_count)
            self.assertEqual(1, len(store.list()))

    def test_resolved_incident_deduplicates_during_deployment_and_creates_new_after_deployed(self) -> None:
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as artifacts:
            store = ArtifactStore(Path(artifacts))
            workflow = NightZeroWorkflow(root, store, str(root.parent / "NightZero-TestProject"))

            # 1. Incident triaged and approved (PR opened)
            record = workflow.run_gcp_logging_incident(
                delivery_id="deliv-d1",
                service_name="demo-payment-gateway",
                log_payload="AssertionError: '$12.34' != '$12.00' in format_total(1234)",
                gateway=RecordingGitHubGateway(),
            )
            workflow.approve(record, "on-call", DEMO_APPROVAL_TOKEN)
            # PR is merged -> status becomes RESOLVED (deployment in-flight)
            workflow.handle_pull_request_merged(
                repository=record.context.repository,
                pr_number=record.approval.get("pr_number", 1) if record.approval else 1,
                branch=record.approval.get("branch", "") if record.approval else "",
                merged_by="sid",
            )
            resolved_record = store.get(record.context.incident_id)
            self.assertEqual(IncidentStatus.RESOLVED, resolved_record.context.status)

            # 2. An error occurs WHILE deployment is in-flight -> MUST DEDUPLICATE into existing incident
            in_flight_err = workflow.run_gcp_logging_incident(
                delivery_id="deliv-d2",
                service_name="demo-payment-gateway",
                log_payload="AssertionError: '$12.34' != '$12.00' in format_total(1234)",
                gateway=RecordingGitHubGateway(),
            )
            self.assertEqual(record.context.incident_id, in_flight_err.context.incident_id)
            self.assertEqual(2, in_flight_err.context.occurrence_count)
            self.assertEqual(1, len(store.list()))

            # 3. User marks incident as Done / Deployed
            workflow.mark_incident_deployed(record.context.incident_id, actor="operator")
            deployed_record = store.get(record.context.incident_id)
            self.assertEqual(IncidentStatus.DEPLOYED, deployed_record.context.status)

            # 4. An error occurs AFTER deployment is complete -> MUST create a NEW incident (true regression)
            post_deploy_err = workflow.run_gcp_logging_incident(
                delivery_id="deliv-d3",
                service_name="demo-payment-gateway",
                log_payload="AssertionError: '$12.34' != '$12.00' in format_total(1234)",
                gateway=RecordingGitHubGateway(),
            )
            self.assertNotEqual(record.context.incident_id, post_deploy_err.context.incident_id)
            self.assertEqual(2, len(store.list()))

    def test_batch_approval_and_consolidated_pr_creation(self) -> None:
        root = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as artifacts:
            store = ArtifactStore(Path(artifacts))
            workflow = NightZeroWorkflow(root, store, str(root.parent / "NightZero-TestProject"))
            gateway = RecordingGitHubGateway()

            # 1. Create two separate verified incidents
            inc1 = workflow.run_gcp_logging_incident(
                delivery_id="deliv-batch-1",
                service_name="demo-payment-gateway",
                log_payload="AssertionError: '$12.34' != '$12.00' in format_total(1234)",
                gateway=gateway,
            )
            inc2 = workflow.run_gcp_logging_incident(
                delivery_id="deliv-batch-2",
                service_name="checkout-service",
                log_payload="TypeError: unsupported operand type for +: 'int' and 'NoneType'",
                gateway=gateway,
            )
            self.assertEqual(IncidentStatus.AWAITING_APPROVAL, inc1.context.status)
            self.assertEqual(IncidentStatus.AWAITING_APPROVAL, inc2.context.status)

            # 2. Batch approve both incidents into a consolidated PR
            res = workflow.batch_approve(
                incident_ids=[inc1.context.incident_id, inc2.context.incident_id],
                actor="on-call",
                token=DEMO_APPROVAL_TOKEN,
                gateway=gateway,
            )
            self.assertIn("batch_id", res)
            self.assertIn("nightzero/release-bundle-", res["branch"])
            self.assertGreaterEqual(res["pr_number"], 1)

            # Verify both incidents updated to APPROVED with shared branch and PR
            rec1 = store.get(inc1.context.incident_id)
            rec2 = store.get(inc2.context.incident_id)
            self.assertEqual(IncidentStatus.APPROVED, rec1.context.status)
            self.assertEqual(IncidentStatus.APPROVED, rec2.context.status)
            self.assertEqual(res["pr_number"], rec1.approval["pr_number"])
            self.assertEqual(res["pr_number"], rec2.approval["pr_number"])
            self.assertEqual(res["branch"], rec1.approval["branch"])
            self.assertEqual(res["branch"], rec2.approval["branch"])

            # 3. Simulate PR merge on GitHub -> ALL bundled incidents transition to RESOLVED
            workflow.handle_pull_request_merged(
                repository=rec1.context.repository,
                pr_number=res["pr_number"],
                branch=res["branch"],
                merged_by="sid",
            )
            r1_merged = store.get(inc1.context.incident_id)
            r2_merged = store.get(inc2.context.incident_id)
            self.assertEqual(IncidentStatus.RESOLVED, r1_merged.context.status)
            self.assertEqual(IncidentStatus.RESOLVED, r2_merged.context.status)

            # 4. User marks all bundled incidents as Done / Complete in batch
            workflow.batch_mark_done(
                [inc1.context.incident_id, inc2.context.incident_id],
                actor="sid",
            )
            r1_deployed = store.get(inc1.context.incident_id)
            r2_deployed = store.get(inc2.context.incident_id)
            self.assertEqual(IncidentStatus.DEPLOYED, r1_deployed.context.status)
            self.assertEqual(IncidentStatus.DEPLOYED, r2_deployed.context.status)