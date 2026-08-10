# NightZero Agent

NightZero Agent turns a reproducible GitHub issue into an evidence-backed, sandbox-verified fix for human approval. It clones `NightZero-TestProject` into an isolated checkout, and this MVP deliberately creates a **simulated** pull-request authorization; it never deploys to production.

## Run locally

```bash
python -m unittest discover -s tests -v
NIGHTZERO_TARGET_REPOSITORY_URL=git@github.com:sudhir-asuracore/NightZero-TestProject.git python -m nightzero
```

The Agent API runs at `http://localhost:8080`: `GET /health`, `GET /api/v1/incidents`, `GET /api/v1/incidents/{id}`, and `POST /api/v1/incidents/{id}/approve`. Set `NIGHTZERO_CORS_ORIGIN` to the Control Panel URL and `PORT` when needed. Approval requires the demo token `nightzero-demo`; inspect persisted evidence in `artifacts/`.

## Demo narrative

1. A GitHub issue reports that `$12.34` renders as `$12.00`.
2. NightZero links the evidence to commit `8f3c2a1`, captures the failing test, and patches a temporary sandbox only.
3. The incident card shows the diff and passing verification before an authenticated simulated PR approval.

## Cloud Run reproduction

The container is Cloud Run compatible; deploy it to a dedicated demo project rather than a production project:

```bash
gcloud run deploy nightzero-demo --source . --region us-central1 --allow-unauthenticated
```

The local `artifacts/` directory is intentionally ephemeral in this demo container. A production deployment should replace it with a restricted persistence service and use an identity-aware approval endpoint.