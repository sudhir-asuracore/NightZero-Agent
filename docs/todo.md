# NightZero Roadmap

## Status legend

- `✅ Complete` means every task in that phase or milestone is delivered.
- `⬜ Planned` means the work remains future scope.
- Checked work below describes the local, simulated hackathon MVP only. It is not
  evidence of production GitHub, ADK, MCP, Google Cloud, or deployment capability.

## Phase 1 — Constrained Hackathon MVP `✅ Complete`

### Milestone 1.1 — Seeded incident and bounded investigation `✅ Complete`

- [x] Define the reproducible GitHub issue #142 checkout-total regression in
  `docs/MVP_SCENARIO.md`.
- [x] Include the intentionally broken `demo_target/pricing.py` implementation
  and its deterministic failing unit test.
- [x] Create a typed `IncidentContext`, RCA, evidence, verification report, and
  audit-event model in `nightzero/models.py`.
- [x] Record the seeded issue, culprit commit, source evidence, root cause, and
  proposed patch through `NightZeroWorkflow`.

### Milestone 1.2 — Isolated remediation verification `✅ Complete`

- [x] Copy `demo_target/` into a temporary sandbox before any candidate patch is
  applied.
- [x] Capture the failing-before and passing-after results for
  `python -m unittest demo_target.test_pricing`.
- [x] Generate and persist the one-file unified diff for
  `demo_target/pricing.py` without modifying the target checkout.
- [x] Persist inspectable incident artifacts and audit events through
  `nightzero/store.py`.

### Milestone 1.3 — Human review and reproducible demo `✅ Complete`

- [x] Render the incident, evidence, diff, sandbox verification, and approval
  state in the lightweight `nightzero/web.py` reviewer card.
- [x] Require the demo authorization token before recording a simulated PR
  approval; do not write a remote branch or deploy production.
- [x] Test sandbox fail-before/pass-after behavior, target non-mutation,
  artifact persistence, and approval authorization in `tests/test_workflow.py`.
- [x] Document local execution, Cloud Run reproduction, MVP boundaries, and the
  three-minute demo narrative in `README.md`, `docs/MVP_SCENARIO.md`, and
  `docs/DEMO.md`.

## Phase 2 — Real open-source remediation loop `⬜ Planned`

### Milestone 2.1 — GitHub and ADK integration `⬜ Planned`

- [ ] Trigger workflows from GitHub Actions, webhooks, issue comments, or
  scheduled maintainer jobs.
- [ ] Execute Gemini-backed ADK agents rather than only declaring agents in
  `nightzero/adk_agents.py`.
- [ ] Add authenticated, least-privilege GitHub reads for issues, commits,
  pull requests, and repository content.
- [ ] Create real isolated branches, pull requests, and incident comments with
  GitHub API write permissions scoped to approved repositories.

### Milestone 2.2 — Evidence tooling and agent orchestration `⬜ Planned`

- [ ] Implement MCP adapters for GitHub, repository inspection, and Google
  Search Grounding with captured tool-call evidence.
- [ ] Use ADK session state to orchestrate triage, RCA, remediation, and review
  instead of the deterministic local workflow.
- [ ] Ground dependency-drift and crash-report remediation in official upstream
  documentation and repository history.
- [ ] Run each candidate fix in an ephemeral CI container with its repository's
  actual test suite.

## Phase 3 — Google Cloud incident remediation `⬜ Planned`

### Milestone 3.1 — Alert ingestion and correlated investigation `⬜ Planned`

- [ ] Ingest authenticated GCP Cloud Monitoring alerts from Pub/Sub and frame a
  typed incident context.
- [ ] Query Cloud Logging with read-only credentials to correlate trace IDs,
  error history, and service metadata.
- [ ] Associate cloud evidence with recent source changes through controlled MCP
  tool permissions.

### Milestone 3.2 — Ephemeral staging and controlled delivery `⬜ Planned`

- [ ] Provision isolated Cloud Run services or GKE namespaces for remediation
  validation.
- [ ] Run synthetic health and load tests, collecting status, latency, and
  stability metrics in the verification report.
- [ ] Integrate a controlled canary deployment request only after staging
  isolation, authorized identity, and least-privilege deploy credentials are in
  place.

## Phase 4 — Security and operational hardening `⬜ Planned`

### Milestone 4.1 — Authorization and durable evidence `⬜ Planned`

- [ ] Replace the demo token with identity-aware approval for authorized
  on-call reviewers.
- [ ] Store secrets in a managed secret service and enforce scoped IAM for
  logging, GitHub, staging, and deployment actions.
- [ ] Persist immutable audit artifacts and execution logs in protected durable
  storage with retention controls.

### Milestone 4.2 — Reliable production operations `⬜ Planned`

- [ ] Add observability for agent decisions, tool calls, sandbox lifecycle, and
  approval outcomes.
- [ ] Implement retries, idempotency keys, failure recovery, and concurrency
  controls for incident processing.
- [ ] Establish metrics from measured runs rather than unvalidated PRD targets
  for triage, RCA, verification, and approval timing.

## Phase 5 — Optional deployment profiles `⬜ Planned`

### Milestone 5.1 — Single-operator SaaS mode `⬜ Planned`

- [ ] Route tenant-tagged alert payloads to a scale-to-zero Cloud Run service.
- [ ] Isolate tenant context, credentials, repositories, and staging targets.
- [ ] Add configurable notification channels for asynchronous approval.

### Milestone 5.2 — Cross-repository maintainer mode `⬜ Planned`

- [ ] Provide a CLI and GitHub Actions profile for maintainer-triggered,
  cross-repository remediation.
- [ ] Support upstream dependency-deprecation detection and verified migration
  pull requests.
- [ ] Post reproducible RCA and test evidence back to the originating issue or
  pull request.