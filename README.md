# NightZero Agent 🌌
### Multi-Subagent Autonomous SRE Engine powered by Google Cloud Vertex AI & ADK

[![Live Service](https://img.shields.io/badge/Google%20Cloud%20Run-nightzero--agent-4285F4?style=for-the-badge&logo=googlecloud)](https://nightzero-agent-164161200079.us-central1.run.app)
[![Vertex AI Gemini](https://img.shields.io/badge/AI%20Engine-Vertex%20AI%20Gemini%202.5-8E75FF?style=for-the-badge&logo=googlegemini)](https://cloud.google.com/vertex-ai)
[![Enterprise Security](https://img.shields.io/badge/Security-Model%20Armor%20%2B%20SPIFFE-10B981?style=for-the-badge)](https://nightzero.web.app)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](LICENSE)

---

## 📌 Overview

**NightZero Agent** is the core backend autonomous engine of the NightZero platform. It continuously ingests production telemetry alerts from Google Cloud Logging error sinks, orchestrates multi-subagent root-cause forensics via **Gemini 2.5 Flash/Pro**, sanitizes payloads via **Model Armor**, enforces **SPIFFE/X.509** identity, verifies candidate patches in ephemeral polyglot sandboxes, and gates GitHub Pull Request remediation behind cryptographic human approval.

---

## 🏛️ Multi-Subagent Architecture

```mermaid
flowchart TD
    Telemetry["GCP Cloud Logging Sink\n(POST /api/v1/webhooks/gcp-logging)"] --> Triage["1. Triage Subagent (ADK)"]
    Triage --> Armor{"Model Armor Defense\n(Prompt Injection & Redaction)"}
    Armor --> Gateway["Agent Gateway Policy Interceptor"]
    Gateway --> Inspector["2. Code Inspector Subagent (GitHub MCP)"]
    Inspector --> RCA["3. Gemini RCA Subagent (Vertex AI 2.5)"]
    RCA --> Sandbox["4. Sandbox Verification Subagent\n(Isolated Test Runner)"]
    Sandbox --> Store[("Cloud Firestore\n(Incident Store & Memory Bank)")]
    Sandbox --> Approval{"Human Approval Gate\n(POST /api/v1/incidents/:id/approve)"}
    Approval --> Remediation["5. Remediation PR Subagent\n(USER_DELEGATED Authority)"]
    Remediation --> GitHubPR["GitHub Draft Pull Request"]
```

---

## ⚡ Key Capabilities

1. **Native Vertex AI Integration**: Uses `google-genai` SDK with Vertex AI backend (`project=nightzero`, `location=us-central1`). Supports `gemini-2.5-flash` (~0.8s latency), `gemini-2.5-pro` (max reasoning), and `gemini-2.5-flash-lite`.
2. **Model Armor AI Firewall**: Inline prompt injection defense, credential/PII redaction, and code patch AST safety analysis.
3. **SPIFFE Cryptographic Identity**: Attested personas (`spiffe://nightzero.io/agent/*`) with HMAC-SHA256 Agent Identity Tokens (`ait-sha256-...`).
4. **Self-Learning Polyglot Sandbox**: Auto-discovers language test runners (Python, TS/JS, Go, Rust, Java) and caches profiles in Firestore Memory Bank.
5. **Human-in-the-Loop Gate**: Strictly enforces `USER_DELEGATED` authority before creating GitHub branches or pull requests.

---

## 🛠️ Local Development & Quickstart

```bash
# 1. Setup Virtual Environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 2. Configure Environment
cp .env.example .env

# 3. Run Test Suite
python3 -m unittest discover -s tests -v

# 4. Start the Agent Service
python3 -m nightzero
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health status and readiness check |
| `GET` | `/api/v1/incidents` | List all triaged and remediated incidents |
| `GET` | `/api/v1/incidents/{id}` | Fetch full incident details, AST diff, and timeline |
| `POST` | `/api/v1/incidents/{id}/approve` | Cryptographically authorize patch and open GitHub Draft PR |
| `GET` | `/api/v1/settings` | Get active model and available Vertex AI catalog |
| `POST` | `/api/v1/settings` | Update active model (`gemini-2.5-flash`, `gemini-2.5-pro`) |
| `GET` | `/api/v1/governance` | Fetch Agent Gateway RBAC and Model Armor telemetry |
| `POST` | `/api/v1/simulate-incident` | Ingest chaos outage regression for live demo verification |
| `POST` | `/api/v1/webhooks/gcp-logging` | Cloud Logging error sink ingestion webhook |
| `POST` | `/api/v1/webhooks/github` | GitHub issue and pull request event webhook |

---

## 📜 License
Licensed under the [Apache License 2.0](LICENSE).
