import json
import tempfile
import unittest
from pathlib import Path

from nightzero.store import ArtifactStore
from nightzero.workflow import DEMO_APPROVAL_TOKEN, NightZeroWorkflow


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