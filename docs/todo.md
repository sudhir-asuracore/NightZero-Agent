# NightZero Roadmap

## Status legend

- `✅ Complete` means every task in that phase or milestone is delivered.
- `🔄 In progress` means implementation is delivered but its live proof or final
  documentation is still pending.
- `⬜ Planned` means the work remains future scope.
- Checked Phase 1 work describes the local, simulated hackathon MVP only. It is
  not evidence of production GitHub, ADK, MCP, Google Cloud, or deployment
  capability.

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

- [x] Serve incident, evidence, diff, sandbox verification, and approval state
  through the Agent REST API and render it in the standalone
  `NightZero-ControlPanel`.
- [x] Require the demo authorization token before recording a simulated PR
  approval; do not write a remote branch or deploy production.
- [x] Test sandbox fail-before/pass-after behavior, target non-mutation,
  artifact persistence, and approval authorization in `tests/test_workflow.py`.
- [x] Document local execution, Cloud Run reproduction, MVP boundaries, and the
  three-minute demo narrative in `README.md`, `docs/MVP_SCENARIO.md`, and
  `docs/DEMO.md`.

## Phase 2 — Real open-source remediation loop `🔄 In progress`

### Milestone 2.1 — Authenticated GitHub issue-label intake and evidence `✅ Complete`

- [x] Accept signed GitHub `issues` webhook deliveries only for the allowlisted
  repository, `labeled` action, and `nightzero:investigate` label.
- [x] Reject invalid signatures and unsupported deliveries without workflow side
  effects, and reuse the original incident for duplicate delivery IDs.
- [x] Read the source issue, repository content, and commit history through an
  Agent-owned, least-privilege GitHub gateway.
- [x] Persist the delivery ID, source issue metadata, repository reference, and
  GitHub tool-call evidence without serializing credentials.

### Milestone 2.2 — Bounded ADK investigation and sandbox verification `✅ Complete`

- [x] Invoke the declared Gemini/ADK triage and RCA agents through a bounded
  orchestration layer with typed evidence and structured outputs.
- [x] Reject invalid model patch proposals before any repository write.
- [x] Validate permitted candidate patches in an isolated clone using the target
  repository's real fail-before/pass-after unit-test command.
- [x] Capture model and verification evidence in persisted incident artifacts.

### Milestone 2.3 — Approved draft remediation PR `✅ Complete`

- [x] Keep a verified candidate local until Control Panel approval authorizes a
  fresh sanitized `nightzero/<incident-id>` branch.
- [x] Commit and push the verified change, create exactly one draft pull request,
  and comment concise RCA and verification evidence on the source issue.
- [x] Persist remote branch, commit, pull-request number/URL, progress, and
  recoverable GitHub-write failure state.
- [x] Display source-issue links, real PR metadata, terminal PR status, and
  write failures in `NightZero-ControlPanel`.

### Milestone 2.4 — Live proof and secure operator documentation `🔄 In progress`

- [x] Add mocked Agent and Control Panel coverage for webhook validation,
  filtering, idempotency, evidence persistence, approval, PR lifecycle, and
  GitHub-write failure states.
- [x] Provide ignored Agent and Control Panel `.env` templates and document
  scoped GitHub, webhook-secret, Gemini, CORS, and sandbox configuration.
- [x] Provide a local Cloudflare tunnel helper and document temporary webhook
  endpoint registration.
- [ ] Run the opt-in live proof with a dedicated labeled issue, inspect its
  evidence, approve once, and confirm the remote branch, draft PR, and issue
  comment.
- [ ] Document the live-proof cleanup and rollback procedure after it has been
  exercised with scoped credentials.

### Milestone 2.5 — Hosted hackathon deployment `🔄 In progress`

- [x] Create the private `NightZero-Infrastructure` repository with Terraform
  for the Google APIs, Artifact Registry, Firestore, Secret Manager containers,
  Firebase project/Hosting site, least-privilege Agent identity, and Cloud Run
  topology.
- [x] Add a bootstrap-safe deployment wrapper and Firebase Hosting configuration
  that keep secrets outside Terraform state and the Control Panel build.
- [x] Provision the `nightzero` Google Cloud foundation: required APIs,
  Artifact Registry, Firestore, Secret Manager containers, Agent runtime IAM,
  Firebase project linkage, and the default Hosting site.
- [x] Add Firestore persistence, Firebase reviewer-token verification, and
  runtime-only HTTPS clone credentials to the Agent.
- [ ] Build and publish the Agent image, deploy Cloud Run, publish the Control
  Panel to Firebase Hosting, update the GitHub webhook URL, and run the hosted
  smoke test before the hackathon demo.

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