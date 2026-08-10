import json
from pathlib import Path

from nightzero.models import IncidentRecord, artifact_path


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