from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from nightzero.store import ArtifactStore
from nightzero.workflow import NightZeroWorkflow


class AgentApiServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], workflow: NightZeroWorkflow) -> None:
        super().__init__(address, AgentApiHandler)
        self.workflow = workflow
        self.store = workflow.artifact_store


class AgentApiHandler(BaseHTTPRequestHandler):
    server: AgentApiServer

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._respond({}, 204)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.rstrip("/")
        if path == "/health":
            self._respond({"status": "IDLE"})
        elif path == "/api/v1/incidents":
            self._respond([self._summary(record) for record in self.server.store.list()])
        elif path.startswith("/api/v1/incidents/"):
            record = self.server.store.get(path.rsplit("/", 1)[1])
            self._respond(record.to_dict() if record else {"error": "Incident not found"}, 200 if record else 404)
        else:
            self._respond({"error": "Not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        prefix = "/api/v1/incidents/"
        if not self.path.startswith(prefix) or not self.path.endswith("/approve"):
            self._respond({"error": "Not found"}, 404)
            return
        incident_id = self.path[len(prefix):-len("/approve")]
        record = self.server.store.get(incident_id)
        if not record:
            self._respond({"error": "Incident not found"}, 404)
            return
        try:
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            record = self.server.workflow.approve(record, payload.get("actor", ""), payload.get("token", ""))
        except (json.JSONDecodeError, PermissionError, ValueError) as error:
            self._respond({"error": str(error)}, 403)
            return
        self._respond(record.to_dict())

    @staticmethod
    def _summary(record: object) -> dict[str, object]:
        context = record.context
        return {"incident_id": context.incident_id, "title": context.title, "service": context.service,
                "severity": context.severity, "status": context.status, "created_at": context.created_at}

    def _respond(self, value: object, status: int = 200) -> None:
        body = json.dumps(value, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", os.environ.get("NIGHTZERO_CORS_ORIGIN", "http://localhost:5173"))
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        if status != 204:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(project_root: Path, port: int = 8080) -> None:
    server = AgentApiServer(("", port), NightZeroWorkflow(project_root, ArtifactStore(project_root / "artifacts")))
    print(f"NightZero Agent API: http://localhost:{port}")
    server.serve_forever()