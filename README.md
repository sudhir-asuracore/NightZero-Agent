# NightZero Agent

NightZero Agent turns a reproducible GitHub issue into an evidence-backed, sandbox-verified fix for human approval. It clones `NightZero-TestProject` into an isolated checkout. This MVP deliberately creates a **simulated** pull-request authorization and never deploys to production.

## Workspace

Keep the three private repositories adjacent in one working directory:

```text
NightZero/
├── NightZero-Agent/
├── NightZero-ControlPanel/
└── NightZero-TestProject/
```

The Agent owns the remediation workflow, sandbox checkout, artifacts, and any future GitHub branch/PR writes. The Control Panel is an API client only; it does not receive GitHub credentials.

## Run locally

Use Python 3.11+ and an SSH identity that has read access to `NightZero-TestProject`:

```bash
cp .env.example .env
# Edit .env with the Agent-only credentials, then load it into this shell.
set -a && source .env && set +a
python -m unittest discover -s tests -v
python -m nightzero
```

The Agent API listens on `http://localhost:8080` by default:

- `GET /health`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{incident_id}`
- `POST /api/v1/incidents/{incident_id}/approve`

Set `PORT` to change the listener and `NIGHTZERO_CORS_ORIGIN` to the exact Control Panel origin. Approval requires the demo-only token `nightzero-demo`; inspect persisted evidence in the ignored `artifacts/` directory.

## Local GitHub webhook tunnel

GitHub needs a public HTTPS destination and cannot call `localhost` directly. With the Agent running, install [`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) and run:

```bash
./scripts/start-github-webhook-tunnel.sh
```

The script verifies `http://127.0.0.1:${PORT:-8080}/health`, then starts a temporary Cloudflare Quick Tunnel. Copy the printed HTTPS URL and configure GitHub's webhook payload URL as `<printed-url>/api/v1/webhooks/github`. The URL changes whenever the tunnel restarts; stop it with `Ctrl+C` after testing.

## Credential boundary

Copy `.env.example` to the ignored `.env` file and supply the values locally. For live remediation, create a fine-grained GitHub token scoped only to `NightZero-TestProject` with `Contents`, `Issues`, and `Pull requests` read/write access; configure the same `NIGHTZERO_WEBHOOK_SECRET` in GitHub's Issues webhook; and set `GOOGLE_API_KEY` for Gemini/ADK. Do not put GitHub tokens, webhook secrets, SSH private keys, or approval secrets in the Control Panel environment or source tree.

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