from __future__ import annotations

import json
import os
import hmac
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from nightzero.auth import FirebaseTokenVerifier, TokenVerifier
from nightzero.store import ArtifactStore, FirestoreArtifactStore
from nightzero.github import GitHubApiGateway, GitHubGateway
from nightzero.investigation import InvestigationRunner
from nightzero.workflow import NightZeroWorkflow


class AgentApiServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], workflow: NightZeroWorkflow, github: GitHubGateway | None = None, investigator: InvestigationRunner | None = None, token_verifier: TokenVerifier | None = None) -> None:
        super().__init__(address, AgentApiHandler)
        self.workflow = workflow
        self.store = workflow.artifact_store
        self.github = github
        self.investigator = investigator
        self.token_verifier = token_verifier


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
        if self.path == "/api/v1/webhooks/github":
            self._handle_github_webhook()
            return
        if self.path == "/api/v1/webhooks/gcp-logging":
            self._handle_gcp_logging_webhook()
            return
        if self.path == "/api/v1/simulate-incident":
            self._handle_simulate_incident()
            return
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
            actor, token, require_demo_token = self._approval_identity(payload)
            gateway = self.server.github
            if record.context.delivery_id and gateway is None:
                gateway = GitHubApiGateway()
            record = self.server.workflow.approve(record, actor, token, gateway, require_demo_token)
        except (json.JSONDecodeError, PermissionError, ValueError) as error:
            self._respond({"error": str(error)}, 403)
            return
        self._respond(record.to_dict())

    def _approval_identity(self, payload: dict[str, object]) -> tuple[str, str | None, bool]:
        if os.environ.get("NIGHTZERO_AUTH_MODE", "local") != "firebase":
            return str(payload.get("actor", "")), str(payload.get("token", "")), True
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise PermissionError("Firebase approval requires a bearer token")
        verifier = self.server.token_verifier or FirebaseTokenVerifier()
        identity = verifier.verify(authorization.removeprefix("Bearer "))
        allowlist = {email.strip().lower() for email in os.environ.get("NIGHTZERO_REVIEWER_ALLOWLIST", "").split(",") if email.strip()}
        if not allowlist or identity.email not in allowlist:
            raise PermissionError("Firebase reviewer is not allowlisted")
        return identity.email, None, False

    def _handle_github_webhook(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.headers.get("X-GitHub-Event") != "issues" or not self._valid_signature(body):
            self._respond({"error": "Invalid GitHub webhook"}, 401)
            return
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond({"error": "Invalid JSON"}, 400)
            return
        repository = payload.get("repository", {}).get("full_name")
        issue = payload.get("issue", {})
        label = payload.get("label", {}).get("name")
        configured_repository = os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "sudhir-asuracore/NightZero-TestProject")
        if payload.get("action") != "labeled" or label != "nightzero:investigate" or repository != configured_repository:
            self._respond({"ignored": True}, 202)
            return
        delivery_id = self.headers.get("X-GitHub-Delivery")
        if not delivery_id or not isinstance(issue.get("number"), int):
            self._respond({"error": "Missing GitHub delivery or issue"}, 400)
            return
        try:
            gateway = self.server.github or GitHubApiGateway()
            record = self.server.workflow.run_labeled_issue(delivery_id, repository, issue["number"], gateway, self.server.investigator)
        except (RuntimeError, ValueError) as error:
            self._respond({"error": str(error)}, 502)
            return
        self._respond(record.to_dict(), 200)

    def _handle_simulate_incident(self) -> None:
        try:
            gateway = self.server.github or GitHubApiGateway()
            record = self.server.workflow.simulate_outage(gateway)
            self._respond(record.to_dict(), 201)
        except Exception as error:
            self._respond({"error": str(error)}, 500)

    def _handle_gcp_logging_webhook(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            payload = json.loads(body or b"{}")
        except json.JSONDecodeError:
            self._respond({"error": "Invalid JSON"}, 400)
            return
        # Handle GCP Pub/Sub push notification format or direct Cloud Logging sink payload
        message = payload.get("message", {})
        data_str = ""
        if "data" in message:
            import base64
            try:
                data_str = base64.b64decode(message["data"]).decode("utf-8")
                log_entry = json.loads(data_str)
            except Exception:
                log_entry = {"textPayload": data_str}
        else:
            log_entry = payload

        delivery_id = message.get("messageId") or self.headers.get("X-Cloud-Trace-Context") or f"gcp-msg-{os.urandom(4).hex()}"
        service_name = log_entry.get("resource", {}).get("labels", {}).get("service_name") or log_entry.get("service") or "NightZero-TestProject"
        log_payload = log_entry.get("textPayload") or json.dumps(log_entry.get("jsonPayload", log_entry))
        severity = log_entry.get("severity") or "CRITICAL"

        try:
            gateway = self.server.github or GitHubApiGateway()
            record = self.server.workflow.run_gcp_logging_incident(delivery_id, service_name, log_payload, severity, gateway, self.server.investigator)
            self._respond(record.to_dict(), 200)
        except (RuntimeError, ValueError) as error:
            self._respond({"error": str(error)}, 502)

    def _valid_signature(self, body: bytes) -> bool:
        secret = os.environ.get("NIGHTZERO_WEBHOOK_SECRET")
        signature = self.headers.get("X-Hub-Signature-256", "")
        if not secret or not signature.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    @staticmethod
    def _summary(record: object) -> dict[str, object]:
        context = record.context
        return {"incident_id": context.incident_id, "title": context.title, "service": context.service,
                "severity": context.severity, "status": context.status, "created_at": context.created_at,
                "issue_url": context.issue_url, "pr_url": (record.approval or {}).get("pr_url")}

    def _respond(self, value: object, status: int = 200) -> None:
        body = json.dumps(value, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", os.environ.get("NIGHTZERO_CORS_ORIGIN", "http://localhost:5173"))
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        if status != 204:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(project_root: Path, port: int = 8080) -> None:
    store = FirestoreArtifactStore.from_default_credentials() if os.environ.get("NIGHTZERO_STORE_BACKEND") == "firestore" else ArtifactStore(project_root / "artifacts")
    server = AgentApiServer(("", port), NightZeroWorkflow(project_root, store))
    print(f"NightZero Agent API: http://localhost:{port}")
    server.serve_forever()