import tempfile
import unittest
from pathlib import Path

from nightzero.store import ArtifactStore
from nightzero.store import FirestoreArtifactStore
from nightzero.workflow import NightZeroWorkflow


class ArtifactStoreTest(unittest.TestCase):
    def test_lists_and_rehydrates_persisted_incidents(self) -> None:
        root = Path(__file__).parents[1]
        target = root.parent / "NightZero-TestProject"
        with tempfile.TemporaryDirectory() as artifacts:
            store = ArtifactStore(Path(artifacts))
            from unittest.mock import MagicMock
            from nightzero.github import RepositoryEvidence
            gateway = MagicMock()
            gateway.get_repository_evidence.return_value = RepositoryEvidence("sha-123", "msg", "demo_target/pricing.py", 'return f"${cents // 100}.00"', "dev", "2026-08-25")
            record = NightZeroWorkflow(root, store, str(target)).run_seeded_issue(gateway=gateway)

            self.assertEqual(record.context.incident_id, store.get(record.context.incident_id).context.incident_id)
            self.assertEqual([record.context.incident_id], [item.context.incident_id for item in store.list()])
            self.assertIsNone(store.get("inc-missing"))
            
            rehydrated = store.get(record.context.incident_id)
            self.assertIsNotNone(rehydrated.rca.timeline_trail)
            self.assertGreater(len(rehydrated.rca.timeline_trail), 0)
            self.assertIsNotNone(rehydrated.rca.attribution)
            self.assertTrue(len(rehydrated.rca.attribution.author) > 0)
            self.assertIsNotNone(rehydrated.rca.test_gap_analysis)
            self.assertTrue(len(rehydrated.rca.test_gap_analysis.why_tests_missed) > 0)
            self.assertIsNotNone(rehydrated.rca.blast_radius)
            self.assertGreater(len(rehydrated.rca.blast_radius.impacted_endpoints), 0)


class _Snapshot:
    def __init__(self, value: dict | None) -> None:
        self.value = value
        self.exists = value is not None

    def to_dict(self) -> dict:
        return self.value


class _Document:
    def __init__(self, values: dict[str, dict], key: str) -> None:
        self.values = values
        self.key = key

    def set(self, value: dict) -> None:
        self.values[self.key] = value

    def get(self, transaction=None) -> _Snapshot:
        return _Snapshot(self.values.get(self.key))


class _Collection:
    def __init__(self) -> None:
        self.values: dict[str, dict] = {}

    def document(self, key: str) -> _Document:
        return _Document(self.values, key)

    def stream(self) -> list[_Snapshot]:
        return [_Snapshot(value) for value in self.values.values()]


class _FirestoreClient:
    def __init__(self) -> None:
        self.collections: dict[str, _Collection] = {}

    def collection(self, name: str) -> _Collection:
        return self.collections.setdefault(name, _Collection())


class FirestoreArtifactStoreTest(unittest.TestCase):
    def test_serializes_and_rehydrates_records(self) -> None:
        root = Path(__file__).parents[1]
        target = root.parent / "NightZero-TestProject"
        with tempfile.TemporaryDirectory() as artifacts:
            from unittest.mock import MagicMock
            from nightzero.github import RepositoryEvidence
            gateway = MagicMock()
            gateway.get_repository_evidence.return_value = RepositoryEvidence("sha-123", "msg", "demo_target/pricing.py", 'return f"${cents // 100}.00"', "dev", "2026-08-25")
            record = NightZeroWorkflow(root, ArtifactStore(Path(artifacts)), str(target)).run_seeded_issue(gateway=gateway)
        store = FirestoreArtifactStore(_FirestoreClient())
        store.save(record)
        self.assertEqual(record.to_dict(), store.get(record.context.incident_id).to_dict())
        self.assertEqual([record.context.incident_id], [item.context.incident_id for item in store.list()])