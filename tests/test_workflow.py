import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nightzero.github import GitHubGateway, GitHubIssue, GitHubPullRequest, RepositoryEvidence
from nightzero.models import IncidentStatus, InvestigationProposal
from nightzero.store import ArtifactStore
from nightzero.workflow import DEMO_APPROVAL_TOKEN, NightZeroWorkflow


class RecordingGitHubGateway(GitHubGateway):
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fail_comment = False

    def get_issue(self, repository: str, issue_number: int) -> GitHubIssue:
        return GitHubIssue(issue_number, "Checkout totals are rounded down", "https://github.com/example/repo/issues/142", "Expected $12.34; received $12.00.", "main")

    def get_repository_evidence(self, repository: str, ref: str) -> RepositoryEvidence:
        return RepositoryEvidence("source-sha", "Regression", "demo_target/pricing.py", 'return f"${cents // 100}.00"')

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
            ).run_seeded_issue()
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
            record = workflow.run_seeded_issue()
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