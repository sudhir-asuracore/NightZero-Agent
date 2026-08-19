import json
import hashlib
from pathlib import Path
from typing import Protocol

from nightzero.models import IncidentRecord, artifact_path


class IncidentStore(Protocol):
    def save(self, record: IncidentRecord) -> object: ...
    def get(self, incident_id: str) -> IncidentRecord | None: ...
    def list(self) -> list[IncidentRecord]: ...
    def get_by_delivery_id(self, delivery_id: str) -> IncidentRecord | None: ...
    def claim_delivery_id(self, delivery_id: str, incident_id: str) -> str | None: ...
    def clear_all(self) -> None: ...


class ArtifactStore:
    """Persists inspectable workflow artifacts outside the target repository."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def save(self, record: IncidentRecord) -> Path:
        path = artifact_path(self.directory, record.context.incident_id)
        path.write_text(json.dumps(record.to_dict(), indent=2), encoding="utf-8")
        return path

    def get(self, incident_id: str) -> IncidentRecord | None:
        path = artifact_path(self.directory, incident_id)
        if not path.is_file():
            return None
        return IncidentRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list(self) -> list[IncidentRecord]:
        records = [
            IncidentRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))
            for path in self.directory.glob("inc-*.json")
        ]
        return sorted(records, key=lambda record: record.context.created_at, reverse=True)

    def get_by_delivery_id(self, delivery_id: str) -> IncidentRecord | None:
        return next((record for record in self.list() if record.context.delivery_id == delivery_id), None)

    def claim_delivery_id(self, delivery_id: str, incident_id: str) -> str | None:
        record = self.get_by_delivery_id(delivery_id)
        return record.context.incident_id if record else None

    def clear_all(self) -> None:
        for path in self.directory.glob("inc-*.json"):
            path.unlink()


class FirestoreArtifactStore:
    """Durable incident store with a transactional GitHub delivery claim."""

    def __init__(self, client: object, collection: str = "incidents") -> None:
        self.client = client
        self.records = client.collection(collection)
        self.deliveries = client.collection(f"{collection}_deliveries")

    @classmethod
    def from_default_credentials(cls) -> "FirestoreArtifactStore":
        from google.cloud import firestore

        return cls(firestore.Client())

    def save(self, record: IncidentRecord) -> str:
        self.records.document(record.context.incident_id).set(record.to_dict())
        return record.context.incident_id

    def get(self, incident_id: str) -> IncidentRecord | None:
        snapshot = self.records.document(incident_id).get()
        return IncidentRecord.from_dict(snapshot.to_dict()) if snapshot.exists else None

    def list(self) -> list[IncidentRecord]:
        records = [IncidentRecord.from_dict(snapshot.to_dict()) for snapshot in self.records.stream()]
        return sorted(records, key=lambda record: record.context.created_at, reverse=True)

    def get_by_delivery_id(self, delivery_id: str) -> IncidentRecord | None:
        claim = self.deliveries.document(self._delivery_document_id(delivery_id)).get()
        if not claim.exists:
            return None
        return self.get(claim.to_dict()["incident_id"])

    def claim_delivery_id(self, delivery_id: str, incident_id: str) -> str | None:
        from google.cloud import firestore

        claim_reference = self.deliveries.document(self._delivery_document_id(delivery_id))
        transaction = self.client.transaction()

        @firestore.transactional
        def claim(transaction: object) -> str | None:
            snapshot = claim_reference.get(transaction=transaction)
            if snapshot.exists:
                return snapshot.to_dict()["incident_id"]
            transaction.set(claim_reference, {"incident_id": incident_id})
            return None

        return claim(transaction)

    def clear_all(self) -> None:
        for snapshot in self.records.stream():
            snapshot.reference.delete()
        for snapshot in self.deliveries.stream():
            snapshot.reference.delete()

    @staticmethod
    def _delivery_document_id(delivery_id: str) -> str:
        return hashlib.sha256(delivery_id.encode("utf-8")).hexdigest()