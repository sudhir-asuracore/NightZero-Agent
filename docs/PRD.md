# Product Requirements Document (PRD): NightZero
## Autonomous Cloud & DevOps Incident Remediation System

---

## 0. Hackathon
**DevPost:** https://allthingsagentichackathon.devpost.com/

"**NightZero:** Shift your SRE load from midnight emergency response to zero-effort morning approvals."
## 1. Executive Summary & Overview

**NightZero** is an autonomous, multi-agent cloud incident investigation and remediation platform. Modern DevOps and SRE teams suffer from severe alert fatigue, long Mean Time to Resolution (MTTR), and context switching when responding to cloud infrastructure alerts.

Existing monitoring tools (e.g., Datadog, GCP Cloud Monitoring, PagerDuty) excel at detecting anomalies and firing alerts, but leave triage, root-cause analysis (RCA), hotfixing, and staging verification to human on-call engineers. **NightZero** bridges this gap by transforming passive alert pipelines into active, autonomous remediation loops built on **Google's Agent Development Kit (ADK)**, **Gemini 3.5**, and the **Model Context Protocol (MCP)**.

### Core Value Proposition
- **Automated MTTR Reduction:** Decreases incident triage and initial patch validation time from hours to under 3 minutes.
- **Context-Aware RCA:** Correlates real-time stack traces, recent git commits, cluster metrics, and external documentation via Google Search Grounding.
- **Zero-Risk Staging Verification:** Automatically spins up ephemeral, sandboxed GCP staging environments (Cloud Run / GKE namespaces) to test generated code or infrastructure fixes before touching production.
- **Human-in-the-Loop Control:** Ensures no production changes occur without human authorization via interactive Slack / Webhook approval gateways.

---

## 2. Objectives & Success Metrics

### Primary Objectives
1. Provide end-to-end autonomous incident handling from alert ingestion to verified staging patch generation.
2. Maintain strict safety boundaries with sandboxed execution environments and mandatory human approval gates.
3. Leverage Google Cloud Native technologies (Gemini 3.5 Pro/Flash, ADK, GCP Cloud Logging, Pub/Sub, Cloud Run) and open standards (MCP).

### Success Metrics & KPIs
| Metric | Target Baseline | NightZero Target |
| :--- | :--- | :--- |
| **Mean Time to Detection & Triage (MTTD)** | 10 - 20 minutes | < 10 seconds |
| **Mean Time to Root Cause Identification** | 30 - 60 minutes | < 45 seconds |
| **Staging Validation Cycle Time** | Manual / Hours | < 90 seconds |
| **End-to-End Resolution Pipeline** | 2 - 4 hours | < 3 minutes (up to Approval) |
| **RCA Accuracy & Relevance** | N/A | > 90% verified by staging tests |

---

## 3. Target Persona & User Stories

### Target Personas
- **Site Reliability Engineers (SREs):** Need fast, automated context gathering and verified patches during high-severity production outages.
- **DevOps Engineers / Infrastructure Lead:** Want automated Terraform / Kubernetes manifests fixes without sacrificing blast radius control.
- **Software Engineers (On-Call):** Seek relief from midnight alerts for recurring or well-defined failure modes (e.g., memory leaks, missing env vars, connection pool exhaustion).

### User Stories
- **US-1 (Ingestion):** As an SRE, when a GCP alert fires via Pub/Sub, I want an agent to immediately frame the incident context so that I don't have to manually search through log streams.
- **US-2 (Root Cause):** As an engineer, I want the system to automatically correlate error logs with recent GitHub commits so that I can immediately identify the offending code change.
- **US-3 (Autonomous Patching):** As a developer, I want an agent to generate a fix and test it in a sandbox environment so that I know the fix works before deploying.
- **US-4 (Interactive Approval):** As an on-call engineer, I want to receive a concise Slack post-mortem with code diffs and a 1-click approval button so that I can safely deploy the fix to production.

---

## 4. System Architecture & Multi-Agent Design

### Multi-Agent Interaction Topology

              ┌────────────────────────────────────────┐
              │   GCP Cloud Observability / Pub/Sub    │
              └───────────────────┬────────────────────┘
                                  │ Alert Payload
                                  ▼
              ┌────────────────────────────────────────┐
              │     Agent 1: Triage & Scope Agent      │
              │   (ADK State Session Initialization)   │
              └───────────────────┬────────────────────┘
                                  │ Context Frame (JSON)
                                  ▼



┌─────────────────────────────────────────────────────────────────────────────┐
│                 Agent 2: Root Cause Analysis & Strategy Agent               │
│                                                                             │
│  MCP Tools:                                                                 │
│  ├── GCP Cloud Logging MCP (Fetch stack traces & logs)                      │
│  ├── GitHub MCP (Fetch recent commit diffs & PRs)                           │
│  └── Google Search Grounding MCP (Query zero-days & lib docs)               │
└─────────────────────────────────────┬───────────────────────────────────────┘
│ RCA & Remediation Plan
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 Agent 3: Remediation & Staging Agent                        │
│                                                                             │
│  Actions:                                                                   │
│  ├── Generate Code / K8s / Terraform Hotfix Patch                           │
│  ├── Provision Ephemeral GCP Cloud Run / GKE Sandbox Environment            │
│  └── Execute Synthetic Load & Health Tests                                  │
└─────────────────────────────────────┬───────────────────────────────────────┘
│ Verified Patch & Test Results
▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 Agent 4: Human-in-the-Loop Approval Gateway                   │
│                                                                             │
│  Output: Slack / Web Dashboard Notification with 1-Click Approve Button     │
│  Action on Approval: Execute Canary Push to Production Pipeline             │
└─────────────────────────────────────────────────────────────────────────────┘



---

## 5. Agent Responsibilities & Capabilities

### Agent 1: Triage & Scope Agent
- **Role:** Parses incoming alert webhooks/Pub/Sub messages.
- **Input:** JSON alert payload from GCP Cloud Monitoring / PubSub.
- **Tasks:**
  1. Extract service name, cluster ID, GCP region, timestamp, error code, and trace IDs.
  2. Instantiate a unique ADK Session ID (`incident-{uuid}`).
  3. Set initial priority and scope in the session memory state.
- **Output:** Structured `IncidentContext` object.

### Agent 2: Root Cause Analysis (RCA) & Strategy Agent
- **Role:** Investigates error history, correlates code changes, and forms diagnostic hypotheses.
- **Input:** `IncidentContext` object from Agent 1.
- **Tools via MCP:**
  - `gcp_logging_query`: Executes query against Cloud Logging.
  - `github_get_recent_commits`: Queries recent merges within the target repository.
  - `google_search_grounding`: Searches external technical documentation or known CVE databases.
- **Tasks:**
  1. Construct hypothesis tree (e.g., "Hypothesis A: Database pool exhaustion caused by unclosed connections in PR #142").
  2. Execute MCP queries to validate or refute hypothesis.
  3. Output explicit Root Cause Analysis document with supporting evidence and proposed fix strategy.

### Agent 3: Remediation & Staging Agent
- **Role:** Generates code/config fixes and validates them in an isolated environment.
- **Input:** RCA output and fix strategy from Agent 2.
- **Tasks:**
  1. Generate code diffs (e.g., Python, Go, Node.js) or manifest changes (K8s YAML, Terraform).
  2. Provision isolated, ephemeral GCP Cloud Run service or GKE sandbox namespace.
  3. Apply patch to staging instance.
  4. Trigger synthetic testing suite (health checks, HTTP load queries).
  5. Collect test metrics (HTTP latency, status codes, memory stability).
- **Output:** `RemediationVerificationReport` containing diff, test logs, and staging status.

### Agent 4: Human-in-the-Loop (HITL) Gateway
- **Role:** Formats incident report for human review and handles user authorization.
- **Input:** `RemediationVerificationReport` from Agent 3.
- **Tasks:**
  1. Build rich Slack Block Kit layout or Web dashboard post-mortem card.
  2. Display RCA summary, proposed diff, staging test results, and confidence score.
  3. Expose interactive buttons: `Approve & Deploy Canary`, `Reject`, or `Request Manual Override`.
  4. On approval, trigger production CI/CD deployment webhook.

---

## 6. Technical Stack & Tooling Integration

| Component | Technology / Library | Description |
| :--- | :--- | :--- |
| **Agent Framework** | **Google Agent Development Kit (ADK)** | Multi-agent coordination, tool execution loops, and persistent session state. |
| **LLM Core** | **Gemini 3.5 Pro / Flash** | Reasoning, code analysis, structured JSON generation, and tool selection. |
| **Protocol Integration** | **Model Context Protocol (MCP)** | Standardization layer connecting agents to infrastructure & services. |
| **Cloud Infrastructure** | **Google Cloud Platform (GCP)** | Cloud Logging, Pub/Sub, Cloud Run, Artifact Registry, GKE. |
| **Grounding Engine** | **Google Search Grounding API** | Web search integration for novel library bugs and error codes. |
| **Human Interface** | **Slack API / Webhooks / FastHTML Dashboard** | Rich interactive user interface for human-in-the-loop validation. |
| **Programming Language** | **Python 3.11+ / Go** | Core backend service language. |

---

## 7. Data Schemas & State Management

### ADK Incident Session State Schema (`incident_state.json`)
json
{
  "incident_id": "inc-20260810-88392",
  "timestamp": "2026-08-10T12:11:17Z",
  "status": "STAGING_VERIFIED",
  "severity": "CRITICAL",
  "context": {
    "service": "payment-gateway",
    "environment": "production",
    "cluster": "gke-us-central1-main",
    "error_type": "FATAL_DB_CONNECTION_LEAK",
    "trace_id": "projects/my-gcp-project/traces/a1b2c3d4e5f6"
  },
  "rca": {
    "hypothesis_verified": true,
    "root_cause": "PR #142 introduced unclosed PostgreSQL pool connections under concurrent load.",
    "culprit_commit": "a8f921e",
    "author": "dev-user@company.com",
    "confidence_score": 0.96
  },
  "remediation": {
    "patch_type": "CODE_FIX",
    "file_path": "services/db/pool.go",
    "diff": "--- a/pool.go\\n+++ b/pool.go\\n@@ -42,3 +42,4 @@\\n conn, err := pool.Acquire(ctx)\\n+defer conn.Release()",
    "staging_endpoint": "[https://staging-payment-gateway-xyz-uc.a.run.app](https://staging-payment-gateway-xyz-uc.a.run.app)",
    "staging_test_results": {
      "synthetic_requests_sent": 1000,
      "success_rate": 1.0,
      "p95_latency_ms": 42
    }
  }
}



---

## 8. Security, Blast Radius & Compliance Controls

1. **Staging Isolation:** Remediation patches are **NEVER** applied directly to production. Patch testing occurs in ephemeral GCP Cloud Run instances with isolated database mocks or read-only replicas.
2. **Least Privilege Principles:** MCP tools run with limited IAM roles:
* Logging MCP: Read-only access (`roles/logging.viewer`).
* GitHub MCP: Restricted repository access with PR/commit reading and branch creation capabilities only.
* Deploy MCP: Restricted to staging namespace/project only.


3. **Mandatory Human Approval:** Production releases require explicit cryptographic or authenticated webhook confirmation from authorized on-call SREs.
4. **Audit Trail:** Every agent tool invocation, reasoning step, code diff generation, and execution log is logged permanently to GCP Cloud Logging for post-incident auditing.

---

## 9. Implementation Roadmap

### Phase 1: Environment & Tooling Setup (Day 1)

* Set up GCP Project, Cloud Pub/Sub topics, and Cloud Logging sinks.
* Initialize Python project with Google ADK (`google-agent-development-kit`).
* Build MCP server stubs for GCP Cloud Logging and GitHub REST API.

### Phase 2: Agent Development & Reasoning Pipeline (Day 2)

* Implement **Triage Agent** for alert parsing and state initialization.
* Implement **Root Cause Agent** with iterative tool-use loops (Logging -> GitHub -> Search).
* Implement **Remediation Agent** to generate code patches and trigger Cloud Run deployments.

### Phase 3: Human-in-the-Loop Gateway & UI (Day 3)

* Build Slack Webhook integration for interactive RCA cards with approval buttons.
* Create lightweight web dashboard displaying live agent execution progress.

### Phase 4: E2E Integration & Demo Preparation (Day 4)

* Simulate realistic outage (e.g., Go/Python memory leak or missing K8s ConfigMap).
* Execute end-to-end flow from alert trigger to automated staging fix and Slack approval.
* Record 3-minute Devpost demo video.

---

## 10. Hackathon Demo Scenario & Script (3 Minutes)

* **0:00 - 0:30 (The Incident):** Trigger simulated production incident (HTTP 500 error spike due to DB connection leak). Pub/Sub alert fires into NightZero.
* **0:30 - 1:15 (Investigation):** Show Triage and Root Cause Agents in action. Agent calls Cloud Logging MCP, retrieves stack trace, queries GitHub MCP for PR #142, and highlights the missing `db.Close()`.
* **1:15 - 2:00 (Autonomous Staging):** Remediation Agent writes code patch, provisions ephemeral Cloud Run service, executes 1,000 synthetic load requests, and verifies 100% success rate.
* **2:00 - 3:00 (Human-in-the-Loop):** Show Slack channel receiving interactive notification card. Presenter clicks **"Approve & Deploy to Production"**, triggering zero-downtime canary push.

---

## 11. Multi-Tenant & Lightweight Deployment Modes

To support solo founders, early-stage startups running micro-budget SaaS infrastructure, and open-source maintainers managing dozens of repositories, **NightZero** provides two lightweight, low-overhead operational profiles alongside the core enterprise deployment.

### Profile A: Single-Operator SaaS Mode (Serverless & Zero-Idle-Cost)

Designed for single-developer or small-team SaaS platforms that require 24/7 incident coverage without the financial burden or maintenance overhead of dedicated monitoring clusters.

```
                    ┌─────────────────────────────────────────┐
                    │ Multi-SaaS Webhooks / GCP PubSub Topics │
                    │   (SaaS Project A, SaaS Project B, etc.)│
                    └────────────────────┬────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │    Ephemeral Cloud Run Agent Container  │
                    │         (Scales to 0 when idle)         │
                    └────────────────────┬────────────────────┘
                                         │
                        ┌────────────────┴────────────────┐
                        ▼                                 ▼
         ┌──────────────────────────────┐ ┌──────────────────────────────┐
         │ Gemini 3.5 Flash (Triage/RCA)│ │  Gemini 3.5 Pro (Deep Code)  │
         └──────────────┬───────────────┘ └──────────────┬───────────────┘
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │    Interactive Slack / Discord / Web    │
                    │           Async 1-Click Approval        │
                    └─────────────────────────────────────────┘

```

#### Key Capabilities & Architecture

1. **Scale-to-Zero Event Driver:**
* Deployed as a single GCP Cloud Run service running Python/ADK.
* Remains completely scaled down ($0/month idle compute) until woken by a Pub/Sub alert, error webhook (e.g., Sentry), or health-check failure.


2. **Dynamic Tiered Model Routing:**
* **Triage & Simple Diagnostics:** Routes initial log extraction and classification through **Gemini 3.5 Flash** for sub-second execution speed and near-zero token cost.
* **Complex Code Analysis & Patching:** Escalates to **Gemini 3.5 Pro** only when code modification, multi-file diff parsing, or deep root-cause reasoning is required.


3. **Multi-Tenant SaaS Management:**
* A single deployed NightZero instance can manage multiple independent SaaS projects.
* Contexts are separated via routing tags in the alert payload (`project_id`, `repo_url`, `staging_environment_target`).

---

### Profile B: Multi-Repo Open-Source Maintainer Mode (CI/CD & CLI Native)

Tailored for maintainers managing open-source libraries, browser extensions, desktop apps, or CLI utilities across multiple repositories where traditional cloud monitoring infrastructure is absent.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       TRIGGER SOURCES & RUNTIMES                            │
│                                                                             │
│  [ GitHub Issue / Crash Report ] ──► GitHub Action Workflow (Headless Agent)│
│  [ Upstream Dependency Deprecation] ──► Local / Daemon CLI Operator        │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NightZero OPEN-SOURCE LOOP                       │
│                                                                             │
│  1. Parse Stack Trace / Issue Body via Gemini 3.5                           │
│  2. Fetch Cross-Repo Commit History via GitHub MCP                          │
│  3. Web Search Upstream API Breaking Changes via Google Search Grounding     │
│  4. Run Unit/Integration Suite in Ephemeral Container                       │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          OUTPUT & DELIVERABLE                               │
│                                                                             │
│  - Pull Request opened on Target Repo with verified passing tests           │
│  - Detailed Post-Mortem & Reproduction steps posted as GitHub Issue Comment │
└─────────────────────────────────────────────────────────────────────────────┘

```

#### Key Capabilities & Architecture

1. **GitHub Actions Native Integration:**
* Runs directly as an automated step inside GitHub Workflows on `issue_comment`, `workflow_dispatch`, or scheduled cron triggers.
* No hosted cloud servers required; operates using project repository secrets (`GEMINI_API_KEY`, `GITHUB_TOKEN`).


2. **Cross-Repo Dependency Drift & Breaking Change Remediation:**
* Monitors upstream package deprecations or runtime updates (e.g., Node/Go runtime updates, browser API updates).
* Queries **Google Search Grounding** to identify official migration guides or upstream patch commits, applies code fixes, runs test suites locally in CI, and opens ready-to-merge Pull Requests.


3. **Automated Crash Report Triage:**
* When users submit error logs or stack traces in issue templates, the agent parses the stack trace, identifies the offending module/commit, and labels the issue while attaching a suggested patch.

---

### Profile Comparison & Cost Matrix

| Feature / Metric | Enterprise SRE Mode | Single-Operator SaaS Mode | Open-Source Maintainer Mode |
| --- | --- | --- | --- |
| **Primary Deployment** | GKE / Dedicated Cloud Run | Scale-to-Zero Cloud Run | GitHub Actions / Local CLI |
| **Idle Infrastructure Cost** | ~$30 - $100 / month | **$0.00 / month** | **$0.00 / month** |
| **Cost per Incident** | ~$0.05 - $0.20 | ~$0.01 - $0.05 | ~$0.005 - $0.02 (API tokens only) |
| **Notification Channel** | PagerDuty, Slack, Webhooks | Slack, Discord, Telegram | GitHub Issue / PR Comments |
| **Primary Focus** | Production Outage Recovery | Zero-On-Call Async Hotfixing | Multi-Repo Drift & Bug Triage |


---
---

### PRD Overview & Structure
#### What's Included:

1. **Executive Summary & Value Proposition:** Highlighting the shift from passive monitoring to autonomous, zero-risk staging remediation.
2. **Objectives & Success Metrics:** Quantifiable targets for MTTD, MTTR, staging cycle time, and RCA accuracy.
3. **Target Personas & User Stories:** SRE, DevOps, and on-call engineer workflows.
4. **Multi-Agent System Architecture:** Clear topology covering the 4 core agents (Triage, Root Cause Analysis, Remediation & Staging, Human-in-the-Loop Gateway).
5. **Detailed Agent Specifications:** Ingestion payloads, MCP tool integrations, hypothesis trees, and staging sandbox execution.
6. **Technical Stack:** Google ADK, Gemini 3.5 Pro/Flash, MCP protocol bindings, GCP Cloud Logging/PubSub/Cloud Run, and Search Grounding.
7. **JSON Schemas & State Management:** Precise ADK Session Memory state structure (`incident_state.json`).
8. **Security & Blast Radius Controls:** Staging isolation, read-only MCP bounds, and mandatory human approval gates.
9. **Implementation Roadmap:** Step-by-step 4-phase execution plan for hackathon completion.
10. **3-Minute Demo Script:** Precise video script timing to impress Devpost judges.




## Extended Why:

The shift from **synchronous emergency response** ("wake up at 3 AM to debug") to **asynchronous approval** ("review a staged, passing fix over morning coffee") is arguably even more transformative for lean teams and solo maintainers than for large enterprise SRE orgs.

---
### Why It’s a Game-Changer for Lean SaaS & Startups

1. **Zero-Headcount 24/7 On-Call Coverage**
* **The Reality:** A 1- to 3-person team running a live SaaS cannot maintain a traditional 24/7 SRE rotation without severe burnout.
* **The Sentinel Advantage:** The agent acts as an autonomous night-shift engineer. If a database pool exhausts or a third-party API rate-limit breaks a microservice at midnight, the system doesn't just ping your phone with raw logs—it isolates the regression, deploys a staging patch, and leaves a verified 1-click fix waiting in Slack.


2. **Dramatically Lower Blast Radius for Fast Merges**
* **The Reality:** Startups ship fast, often lacking extensive manual QA cycles or dedicated staging environments for every micro-service.
* **The Sentinel Advantage:** Because the agent automatically provisions ephemeral sandboxes (e.g., Cloud Run / container instances) to run synthetic load tests before notifying you, it proves the fix works in isolation before you ever hit "Approve."


3. **Cost-Effective Scalability**
* **The Reality:** Hiring external managed SRE services or paying high-tier incident orchestration platforms can devour early-stage runway.
* **The Sentinel Advantage:** Running an agentic loop over lightweight serverless infrastructure and Gemini API calls costs pennies per incident, delivering enterprise-level incident handling on a bootstrap budget.


---
### Why It Solves Open-Source Maintainer Burnout

1. **Context-Switching Across Multiple Repositories**
* Open-source maintainers frequently manage multiple packages, extensions, or modules simultaneously. Remembering the exact internal architecture or dependency graph of a tool written months ago takes heavy cognitive effort.
* When CI fails or a user reports a breaking crash, the agent uses MCP tool bindings to correlate stack traces with recent git commits across repositories instantly, giving the maintainer an immediate mental map of what broke.


2. **Automated Upstream Dependency Drift Fixes**
* Open-source projects constantly break due to underlying upstream dependency updates, API deprecations, or browser/OS environment updates.
* The agent uses **Google Search Grounding** to query recent release notes or GitHub issues across the ecosystem, identifies the breaking change, updates the manifest/dependencies, and submits a clean Pull Request with passing sandbox tests attached.


3. **Noise Reduction in Issue Trackers**
* Maintainers are often flooded with vague issue reports ("it doesn't work"). By hooking the agent into error tracking (e.g., Sentry, GCP Logging), it verifies whether an alert represents a reproducible code defect or user setup error before the maintainer spends hours manually investigating.