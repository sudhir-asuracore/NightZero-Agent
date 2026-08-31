from __future__ import annotations

import json
import os
import hmac
import hashlib
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from nightzero.auth import FirebaseTokenVerifier, TokenVerifier
from nightzero.store import ArtifactStore, FirestoreArtifactStore
from nightzero.github import GitHubApiGateway, GitHubGateway
from nightzero.investigation import InvestigationRunner
from nightzero.models import IncidentStatus
from nightzero.workflow import NightZeroWorkflow, DEMO_APPROVAL_TOKEN

logger = logging.getLogger("nightzero.api")


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
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/")
            if path == "/health":
                self._respond({"status": "IDLE"})
            elif path == "/api/v1/incidents":
                query = urllib.parse.parse_qs(parsed.query)
                try:
                    limit = int(query.get("limit", ["50"])[0])
                    offset = int(query.get("offset", ["0"])[0])
                except ValueError:
                    limit, offset = 50, 0
                
                all_records = self.server.store.list()
                total = len(all_records)
                gateway = self.server.github or GitHubApiGateway()
                synced_records = []
                for record in all_records[offset:offset+limit]:
                    if record.context.status == IncidentStatus.APPROVED and record.approval and record.approval.get("pr_number"):
                        try:
                            record = self.server.workflow.sync_incident_status(record, gateway)
                        except Exception:
                            pass
                    synced_records.append(record)
                paginated = [self._summary(record) for record in synced_records]
                
                self._respond({"incidents": paginated, "total": total})
            elif path == "/api/v1/settings":
                from nightzero.workflow import AVAILABLE_GEMINI_MODELS
                self._respond({
                    "gemini_model": self.server.workflow.gemini_model,
                    "available_models": AVAILABLE_GEMINI_MODELS,
                })
            elif path == "/api/v1/settings/notifications":
                self._respond(self.server.workflow.notification_settings)
            elif path == "/api/v1/governance":
                from nightzero.agent_gateway import AgentGateway
                self._respond(AgentGateway.get_governance_overview())
            elif path.startswith("/api/v1/incidents/"):
                incident_id = path.rsplit("/", 1)[1]
                record = self.server.store.get(incident_id)
                if record:
                    gateway = self.server.github or GitHubApiGateway()
                    record = self.server.workflow.sync_incident_status(record, gateway)
                self._respond(record.to_dict() if record else {"error": "Incident not found"}, 200 if record else 404)
            else:
                self._respond({"error": "Not found"}, 404)
        except Exception as error:
            import traceback
            traceback.print_exc()
            self._respond({"error": str(error)}, 500)

    def do_DELETE(self) -> None:  # noqa: N802
        try:
            if self.path == "/api/v1/incidents":
                self.server.store.clear_all()
                self._respond({"status": "cleared"})
            else:
                self._respond({"error": "Not found"}, 404)
        except Exception as error:
            import traceback
            traceback.print_exc()
            self._respond({"error": str(error)}, 500)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/api/v1/settings":
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")) or 0)
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {}
            if "gemini_model" in payload:
                model = str(payload.get("gemini_model", "gemini-3.7-flash"))
                self.server.workflow.set_gemini_model(model)
            from nightzero.workflow import AVAILABLE_GEMINI_MODELS
            self._respond({
                "gemini_model": self.server.workflow.gemini_model,
                "available_models": AVAILABLE_GEMINI_MODELS,
            })
            return
        if self.path == "/api/v1/settings/notifications":
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")) or 0)
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {}
            updated = self.server.workflow.set_notification_settings(payload)
            self._respond(updated)
            return
        if self.path == "/api/v1/notifications/test":
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")) or 0)
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                payload = {}
            channel = payload.get("channel", "")
            config = payload.get("config", {})
            from nightzero.notifications import NotificationDispatcher
            success, message = NotificationDispatcher.test_channel(channel, config)
            self._respond({"success": success, "message": message}, 200 if success else 400)
            return
        if self.path == "/api/v1/webhooks/github":
            self._handle_github_webhook()
            return
        if self.path == "/api/v1/webhooks/gcp-logging":
            self._handle_gcp_logging_webhook()
            return
        if self.path == "/api/v1/simulate-incident":
            self._handle_simulate_incident()
            return
        if self.path == "/api/v1/incidents/batch-complete":
            try:
                payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                actor = str(payload.get("actor", "operator"))
                incident_ids = payload.get("incident_ids", [])
                if not incident_ids:
                    self._respond({"error": "No incident IDs provided"}, 400)
                    return
                updated = self.server.workflow.batch_mark_done(incident_ids, actor)
                self._respond({"status": "completed", "incident_ids": [u.context.incident_id for u in updated], "count": len(updated)})
            except Exception as exc:
                self._respond({"error": str(exc)}, 500)
            return
        if self.path == "/api/v1/incidents/batch-approve":
            try:
                payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                actor, token, require_demo_token = self._approval_identity(payload)
                incident_ids = payload.get("incident_ids", [])
                if not incident_ids:
                    self._respond({"error": "No incident IDs provided"}, 400)
                    return
                gateway = self.server.github
                if gateway is None and any(self.server.store.get(iid) and self.server.store.get(iid).context.delivery_id for iid in incident_ids):
                    gateway = GitHubApiGateway()
                result = self.server.workflow.batch_approve(
                    incident_ids=incident_ids,
                    actor=actor,
                    token=token,
                    gateway=gateway,
                    require_demo_token=require_demo_token,
                )
                self._respond(result, 200)
            except (json.JSONDecodeError, PermissionError, ValueError) as error:
                self._respond({"error": str(error)}, 403)
            except Exception as error:
                logger.exception("Batch approval failed: %s", error)
                self._respond({"error": str(error)}, 500)
            return
        if self.path == "/api/v1/incidents/prune-duplicates":
            try:
                records = self.server.store.list()
                seen: dict[tuple[str, str], IncidentRecord] = {}
                deleted: list[str] = []
                for rec in records:
                    if rec.context.status == IncidentStatus.DEPLOYED:
                        continue
                    # Normalize title / module
                    key = (rec.context.service, rec.context.title.split(" at ")[0].strip())
                    if key in seen:
                        primary = seen[key]
                        primary.context.occurrence_count = getattr(primary.context, "occurrence_count", 1) + getattr(rec.context, "occurrence_count", 1)
                        self.server.store.delete(rec.context.incident_id)
                        self.server.store.save(primary)
                        deleted.append(rec.context.incident_id)
                    else:
                        seen[key] = rec
                self._respond({"status": "cleaned", "deleted_count": len(deleted), "remaining": len(seen)})
            except Exception as exc:
                self._respond({"error": str(exc)}, 500)
            return
        prefix = "/api/v1/incidents/"
        if self.path.startswith(prefix) and (self.path.endswith("/deployed") or self.path.endswith("/complete")):
            suffix = "/deployed" if self.path.endswith("/deployed") else "/complete"
            incident_id = self.path[len(prefix):-len(suffix)]
            try:
                payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                actor = str(payload.get("actor", "operator"))
            except Exception:
                actor = "operator"
            try:
                record = self.server.workflow.mark_incident_deployed(incident_id, actor=actor)
                self._respond(record.to_dict())
            except Exception as exc:
                self._respond({"error": str(exc)}, 404)
            return
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
        auth_mode = os.environ.get("NIGHTZERO_AUTH_MODE", "local")
        authorization = self.headers.get("Authorization", "")
        token_in_payload = str(payload.get("token", "") or payload.get("demo_token", "")).strip()
        bearer = authorization.removeprefix("Bearer ").strip() if authorization.startswith("Bearer ") else ""

        # If explicit demo token is provided in payload or bearer, allow demo authorization
        if token_in_payload == DEMO_APPROVAL_TOKEN or bearer == DEMO_APPROVAL_TOKEN:
            actor = str(payload.get("actor", "") or "reviewer")
            return actor, DEMO_APPROVAL_TOKEN, True

        # If Firebase auth is configured and a non-demo bearer token was provided
        if auth_mode == "firebase" or (authorization.startswith("Bearer ") and bearer and bearer != DEMO_APPROVAL_TOKEN):
            if not authorization.startswith("Bearer "):
                if token_in_payload == DEMO_APPROVAL_TOKEN:
                    actor = str(payload.get("actor", "") or "reviewer")
                    return actor, DEMO_APPROVAL_TOKEN, True
                raise PermissionError("Firebase approval requires a bearer token in Authorization header")
            raw_token = bearer
            verifier = self.server.token_verifier or FirebaseTokenVerifier()
            try:
                identity = verifier.verify(raw_token)
                allowlist = {email.strip().lower() for email in os.environ.get("NIGHTZERO_REVIEWER_ALLOWLIST", "").split(",") if email.strip()}
                if allowlist and identity.email.lower() not in allowlist:
                    raise PermissionError(f"Firebase reviewer '{identity.email}' is not allowlisted")
                return identity.email, None, False
            except Exception as exc:
                if token_in_payload == DEMO_APPROVAL_TOKEN:
                    actor = str(payload.get("actor", "") or "reviewer")
                    return actor, DEMO_APPROVAL_TOKEN, True
                if "Token expired" in str(exc) or "expired" in str(exc).lower():
                    raise PermissionError("Firebase authentication token expired. Please refresh the page or sign in again.") from exc
                raise

        actor = str(payload.get("actor", "") or "reviewer")
        token = token_in_payload or bearer
        return actor, token, True

    def _handle_github_webhook(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        event = self.headers.get("X-GitHub-Event")
        if event not in ("issues", "pull_request") or not self._valid_signature(body):
            self._respond({"error": "Invalid GitHub webhook"}, 401)
            return
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond({"error": "Invalid JSON"}, 400)
            return
        label = payload.get("label", {}).get("name")
        issue = payload.get("issue", {})
        pull_request = payload.get("pull_request", {})
        repository = payload.get("repository", {}).get("full_name")
        configured_repository = os.environ.get("NIGHTZERO_GITHUB_REPOSITORY")
        if not repository:
            self._respond({"error": "Missing repository"}, 400)
            return
        if event == "pull_request":
            action = payload.get("action")
            pr = payload.get("pull_request", {})
            merged = pr.get("merged", False)
            if action == "closed" and merged:
                repository = payload.get("repository", {}).get("full_name", "")
                pr_number = pr.get("number")
                pr_url = pr.get("html_url", "")
                branch = pr.get("head", {}).get("ref", "")
                merged_by = (pr.get("merged_by") or {}).get("login", "")
                record = self.server.workflow.handle_pull_request_merged(
                    repository=repository,
                    pr_number=pr_number,
                    pr_url=pr_url,
                    branch=branch,
                    merged_by=merged_by,
                )
                self._respond({"resolved": True, "incident_id": record.context.incident_id if record else None}, 200)
                return
            self._respond({"ignored": True}, 202)
            return
        if payload.get("action") != "labeled" or label != "nightzero:investigate" or (configured_repository and repository != configured_repository):
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
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")) or 0)
            payload = {}
            if body:
                try:
                    payload = json.loads(body)
                except Exception:
                    pass
            repo = payload.get("repository") or os.environ.get("NIGHTZERO_GITHUB_REPOSITORY", "")
            target_path = payload.get("target_path", "demo_target/pricing.py")
            gateway = self.server.github or GitHubApiGateway()
            result = self.server.workflow.simulate_outage(repository=repo, target_path=target_path, gateway=gateway)
            self._respond(result, 201)
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
        service_name = log_entry.get("resource", {}).get("labels", {}).get("service_name") or log_entry.get("service") or "production-service"
        log_payload = log_entry.get("textPayload") or json.dumps(log_entry.get("jsonPayload", log_entry))
        severity = log_entry.get("severity") or "CRITICAL"

        try:
            gateway = self.server.github or GitHubApiGateway()
            record = self.server.workflow.run_gcp_logging_incident(
                delivery_id, service_name, log_payload, severity, gateway, self.server.investigator, async_pipeline=True
            )
            self._respond(record.to_dict(), 200)
        except (RuntimeError, ValueError) as error:
            import traceback
            traceback.print_exc()
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
        return {
            "incident_id": context.incident_id,
            "title": context.title,
            "service": context.service,
            "severity": context.severity,
            "status": context.status,
            "created_at": context.created_at,
            "issue_url": context.issue_url,
            "pr_url": (record.approval or {}).get("pr_url"),
            "occurrence_count": getattr(context, "occurrence_count", 1),
            "last_seen_at": getattr(context, "last_seen_at", context.created_at),
        }

    def _respond(self, value: object, status: int = 200) -> None:
        self.send_response(status)
        if status != 204:
            body = json.dumps(value, default=str).encode()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
        origin = self.headers.get("Origin") or ""
        configured = os.environ.get("NIGHTZERO_CORS_ORIGIN", "").strip()
        allowed = [o.strip() for o in configured.split(",") if o.strip()]
        if not configured or "*" in allowed or not origin or origin in allowed or origin.endswith(".web.app") or origin.endswith(".firebaseapp.com") or "localhost" in origin or "127.0.0.1" in origin:
            cors_origin = origin if origin else "*"
        else:
            cors_origin = allowed[0] if allowed else "*"
        self.send_header("Access-Control-Allow-Origin", cors_origin)
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, Accept")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Max-Age", "86400")
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