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
            record = NightZeroWorkflow(root, store, str(target)).run_seeded_issue()

            self.assertEqual(record.context.incident_id, store.get(record.context.incident_id).context.incident_id)
            self.assertEqual([record.context.incident_id], [item.context.incident_id for item in store.list()])
            self.assertIsNone(store.get("inc-missing"))


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
            record = NightZeroWorkflow(root, ArtifactStore(Path(artifacts)), str(target)).run_seeded_issue()
        store = FirestoreArtifactStore(_FirestoreClient())
        store.save(record)
        self.assertEqual(record.to_dict(), store.get(record.context.incident_id).to_dict())
        self.assertEqual([record.context.incident_id], [item.context.incident_id for item in store.list()])