import hashlib
import hmac
import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from nightzero.api import AgentApiServer
from nightzero.auth import ReviewerIdentity
from nightzero.github import GitHubGateway, GitHubIssue, RepositoryEvidence
from nightzero.models import InvestigationProposal
from nightzero.store import ArtifactStore
from nightzero.workflow import NightZeroWorkflow


class FakeGitHubGateway(GitHubGateway):
    def __init__(self) -> None:
        self.issue_reads = 0

    def get_issue(self, repository: str, issue_number: int) -> GitHubIssue:
        self.issue_reads += 1
        return GitHubIssue(issue_number, "Checkout totals are rounded down", "https://github.com/sudhir-asuracore/NightZero-TestProject/issues/142", "Expected $12.34; received $12.00.", "main")

    def get_repository_evidence(self, repository: str, ref: str) -> RepositoryEvidence:
        return RepositoryEvidence("live-sha", "Fixes pricing display", "demo_target/pricing.py", 'return f"${cents // 100}.00"')


class FakeInvestigator:
    def investigate(self, context, issue_body, evidence) -> InvestigationProposal:
        return InvestigationProposal("Integer division drops cents from checkout totals.", 0.99, "Render cents / 100 with two decimal places.", "demo_target/pricing.py", 'return f"${cents / 100:.2f}"')


class UnsafeInvestigator:
    def investigate(self, context, issue_body, evidence) -> InvestigationProposal:
        return InvestigationProposal("Unsupported", 0.8, "Change another file", "README.md", "unsafe")


class FakeTokenVerifier:
    def __init__(self, email: str = "reviewer@example.com") -> None:
        self.email = email

    def verify(self, token: str) -> ReviewerIdentity:
        if token != "valid-firebase-token":
            raise PermissionError("Invalid Firebase token")
        return ReviewerIdentity(self.email, "firebase-user")


class GitHubWebhookTest(unittest.TestCase):
    def setUp(self) -> None:
        self.artifacts = tempfile.TemporaryDirectory()
        root = Path(__file__).parents[1]
        self.github = FakeGitHubGateway()
        self.verifier = FakeTokenVerifier()
        self.server = AgentApiServer(("127.0.0.1", 0), NightZeroWorkflow(root, ArtifactStore(Path(self.artifacts.name)), str(root.parent / "NightZero-TestProject")), self.github, FakeInvestigator(), self.verifier)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.environment = patch.dict(os.environ, {"NIGHTZERO_WEBHOOK_SECRET": "webhook-secret", "NIGHTZERO_GITHUB_REPOSITORY": "sudhir-asuracore/NightZero-TestProject"})
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.artifacts.cleanup()

    def _post(self, payload: dict, *, signature: bool = True, event: str = "issues") -> tuple[int, dict]:
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "X-GitHub-Event": event, "X-GitHub-Delivery": "delivery-1"}
        if signature:
            headers["X-Hub-Signature-256"] = "sha256=" + hmac.new(b"webhook-secret", body, hashlib.sha256).hexdigest()
        connection = http.client.HTTPConnection(*self.server.server_address)
        connection.request("POST", "/api/v1/webhooks/github", body, headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())

    @staticmethod
    def _payload(**overrides: object) -> dict:
        payload = {"action": "labeled", "label": {"name": "nightzero:investigate"}, "repository": {"full_name": "sudhir-asuracore/NightZero-TestProject"}, "issue": {"number": 142}}
        payload.update(overrides)
        return payload

    def test_rejects_invalid_signature_without_workflow_side_effects(self) -> None:
        status, response = self._post(self._payload(), signature=False)
        self.assertEqual(401, status)
        self.assertEqual("Invalid GitHub webhook", response["error"])
        self.assertEqual(0, self.github.issue_reads)

    def test_ignores_unsupported_label_and_repository(self) -> None:
        status, response = self._post(self._payload(label={"name": "bug"}))
        self.assertEqual(202, status)
        self.assertTrue(response["ignored"])
        status, response = self._post(self._payload(repository={"full_name": "other/project"}))
        self.assertEqual(202, status)
        self.assertTrue(response["ignored"])
        self.assertEqual(0, self.github.issue_reads)

    def test_creates_idempotent_live_incident_with_persisted_evidence(self) -> None:
        status, first = self._post(self._payload())
        self.assertEqual(200, status)
        status, duplicate = self._post(self._payload())
        self.assertEqual(200, status)
        self.assertEqual(first["context"]["incident_id"], duplicate["context"]["incident_id"])
        self.assertEqual(1, self.github.issue_reads)
        self.assertEqual("delivery-1", first["context"]["delivery_id"])
        self.assertEqual("https://github.com/sudhir-asuracore/NightZero-TestProject/issues/142", first["context"]["issue_url"])
        self.assertEqual("live-sha", first["rca"]["culprit_commit"])

    def test_rejects_out_of_scope_model_patch(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside the permitted remediation"):
            self.server.workflow.run_labeled_issue("delivery-unsafe", "sudhir-asuracore/NightZero-TestProject", 142, self.github, UnsafeInvestigator())

    def test_firebase_approval_requires_valid_allowlisted_reviewer(self) -> None:
        record = self.server.workflow.run_seeded_issue()
        environment = patch.dict(os.environ, {"NIGHTZERO_AUTH_MODE": "firebase", "NIGHTZERO_REVIEWER_ALLOWLIST": "reviewer@example.com"})
        environment.start()
        self.addCleanup(environment.stop)
        status, response = self._approve(record.context.incident_id, "Bearer valid-firebase-token")
        self.assertEqual(200, status)
        self.assertEqual("reviewer@example.com", response["approval"]["actor"])

    def test_firebase_approval_rejects_missing_or_unallowlisted_token(self) -> None:
        record = self.server.workflow.run_seeded_issue()
        environment = patch.dict(os.environ, {"NIGHTZERO_AUTH_MODE": "firebase", "NIGHTZERO_REVIEWER_ALLOWLIST": "other@example.com"})
        environment.start()
        self.addCleanup(environment.stop)
        status, response = self._approve(record.context.incident_id)
        self.assertEqual(403, status)
        self.assertIn("bearer token", response["error"])
        status, response = self._approve(record.context.incident_id, "Bearer valid-firebase-token")
        self.assertEqual(403, status)
        self.assertIn("not allowlisted", response["error"])

    def _approve(self, incident_id: str, authorization: str | None = None) -> tuple[int, dict]:
        headers = {"Content-Type": "application/json"}
        if authorization:
            headers["Authorization"] = authorization
        connection = http.client.HTTPConnection(*self.server.server_address)
        connection.request("POST", f"/api/v1/incidents/{incident_id}/approve", b"{}", headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())

    def test_pull_request_merged_resolves_incident(self) -> None:
        record = self.server.workflow.run_seeded_issue()
        record.approval = {"pr_number": 42, "branch": "nightzero/inc-test"}
        record.context.status = "APPROVED"
        self.server.store.save(record)

        payload = {
            "action": "closed",
            "repository": {"full_name": "sudhir-asuracore/NightZero-TestProject"},
            "pull_request": {
                "number": 42,
                "html_url": "https://github.com/sudhir-asuracore/NightZero-TestProject/pull/42",
                "merged": True,
                "head": {"ref": "nightzero/inc-test"},
                "merged_by": {"login": "octocat"},
            },
        }
        body = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": "delivery-pr-merge",
            "X-Hub-Signature-256": "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest(),
        }
        with patch.dict(os.environ, {"NIGHTZERO_WEBHOOK_SECRET": "secret"}):
            connection = http.client.HTTPConnection(*self.server.server_address)
            connection.request("POST", "/api/v1/webhooks/github", body, headers)
            response = connection.getresponse()
            self.assertEqual(200, response.status)
            res_data = json.loads(response.read())
            self.assertTrue(res_data.get("resolved"))

        updated = self.server.store.get(record.context.incident_id)
        self.assertEqual("RESOLVED", updated.context.status)
        self.assertEqual("PULL_REQUEST_MERGED", updated.approval.get("action"))
        self.assertEqual("octocat", updated.approval.get("merged_by"))