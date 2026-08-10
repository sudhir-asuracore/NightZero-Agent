import tempfile
import unittest
from pathlib import Path

from nightzero.store import ArtifactStore
from nightzero.workflow import NightZeroWorkflow


class ArtifactStoreTest(unittest.TestCase):
    def test_lists_and_rehydrates_persisted_incidents(self) -> None:
        root = Path(__file__).parents[1]
        target = root.parent / "NightZero-TestProject"
        with tempfile.TemporaryDirectory() as artifacts:
            store = ArtifactStore(Path(artifacts))
            record = NightZeroWorkflow(root, store, str(target)).run_seeded_issue()

            self.assertEqual(record.context.incident_id, store.get(record.context.incident_id).context.incident_id)
            self.assertEqual([record.context.incident_id], [item.context.incident_id for item in store.list()])
            self.assertIsNone(store.get("inc-missing"))