# NightZero Handover

Updated: 2026-08-11

## Purpose

NightZero turns an opt-in GitHub issue into a bounded investigation, a
sandbox-verified candidate fix, and—only after reviewer approval—a draft pull
request. The hackathon deployment uses Cloud Run for the Agent, Firebase
Hosting and Authentication for the Control Panel, Firestore for incident
artifacts, Secret Manager for Agent-only credentials, and Artifact Registry
for the Agent image.

## Workspace and repositories

The shared `NightZero/` workspace contains three private GitHub repositories
and the deployment repository:

| Directory | Responsibility |
| --- | --- |
| `NightZero-Agent/` | Python Agent API, signed GitHub webhook, workflow, persistence, and sandbox verification. |
| `NightZero-ControlPanel/` | React/Vite reviewer UI; it only calls the Agent API and uses Firebase Authentication. |
| `NightZero-TestProject/` | Private monitored target repository used for the controlled issue-to-PR demonstration. |
| `NightZero-Infrastructure/` | Terraform and the ordered Cloud Run/Firebase deployment wrapper. |

## Completed work

- Phase 1 local, seeded demonstration is complete: deterministic incident,
  persisted evidence, isolated fail-before/pass-after sandbox validation, and
  reviewer approval.
- Phase 2 implementation is complete for signed `issues` label intake,
  delivery idempotency, GitHub evidence reads, bounded ADK investigation,
  validated candidate patches, and approval-authorized draft PR creation.
- The Control Panel displays Agent health, incident lifecycle, evidence,
  verification output, source issue/PR metadata, and approval state.
- Cloud deployment foundations are provisioned in Google Cloud project
  `nightzero`: required APIs, Artifact Registry, Firestore, four Secret
  Manager secret containers, Agent runtime service account/IAM, Firebase
  linkage, and the default `nightzero.web.app` Hosting site.
- The Agent has cloud-safe implementations for Firestore persistence, Firebase
  ID-token approval verification with an email allowlist, and redacted
  HTTPS-token sandbox cloning. Local filesystem/demo behavior remains
  available for tests.
- Firebase Email/Password authentication is enabled and the shared judge
  account `nightzero-judges@asuracore.com` was created. The Control Panel Web
  App is configured for project `nightzero`.

For detailed milestone status, see [todo.md](todo.md). The current execution
plan is `../../.junie/plans/nightzero-hackathon-mvp.md` from the workspace root;
Step 4, packaging and deployment, is in progress.

## Remaining work

### Immediate deployment work

1. From `NightZero-Infrastructure`, export the non-secret deployment inputs:

   ```bash
   export PROJECT_ID=nightzero
   export FIREBASE_HOSTING_SITE_ID=nightzero
   export NIGHTZERO_REVIEWER_ALLOWLIST=nightzero-judges@asuracore.com
   export VITE_FIREBASE_API_KEY='<Firebase Web App API key>'
   export VITE_FIREBASE_AUTH_DOMAIN=nightzero.firebaseapp.com
   export VITE_FIREBASE_APP_ID='<Firebase Web App ID>'
   ```

   Obtain the required public Firebase values from Firebase Console or the local
   ignored configuration; do not copy any server-side secret into this file.

2. Confirm that each Secret Manager container has a current version:
   `nightzero-github-token`, `nightzero-webhook-secret`,
   `nightzero-gemini-api-key`, and `nightzero-git-clone-token`. The two GitHub
   token secrets may use the same repository-scoped fine-grained PAT. It must
   be restricted to `sudhir-asuracore/NightZero-TestProject` with only the
   documented Contents, Issues, and Pull requests access.

3. Run the ordered deployment wrapper:

   ```bash
   cd NightZero-Infrastructure
   ./scripts/deploy.sh
   ```

   It builds and pushes the Agent image with Cloud Build, applies the Cloud
   Run service using that immutable image, builds the Control Panel with the
   emitted Agent URL, and deploys Firebase Hosting. Earlier deployment attempts
   identified and corrected Cloud Build source-read and Artifact Registry
   writer IAM; rebuild/publish is the next operation to validate.

4. Save the printed Cloud Run URL. Set the Agent's exact Firebase Hosting
   origin through Terraform/deployment configuration, then update the GitHub
   `Issues` webhook payload URL to:

   ```text
   <cloud-run-agent-url>/api/v1/webhooks/github
   ```

   Keep the configured GitHub webhook secret identical to
   `nightzero-webhook-secret` in Secret Manager.

### Hosted smoke test

After deployment, perform this proof before presenting:

1. Sign in to `https://nightzero.web.app` as the shared judge account and
   confirm health, incident list, and incident detail requests work.
2. Create a dedicated issue in `NightZero-TestProject` and add the
   `nightzero:investigate` label.
3. Confirm GitHub reaches the signed Cloud Run webhook and the Agent persists
   an incident in Firestore.
4. Inspect the RCA, diff, and sandbox test evidence in the panel; check that
   the test fails before and passes after only in the temporary checkout.
5. Approve once in the Control Panel. Confirm the Agent creates one branch,
   draft PR, and source-issue comment.
6. Restart/revise the Cloud Run instance as appropriate and verify the
   incident is still visible, demonstrating Firestore durability.
7. Review Cloud Run request/application logs to ensure no webhook body,
   authorization header, Firebase token, GitHub token, or authenticated clone
   URL appears.

### Documentation and cleanup still needed

- Exercise and document the live-proof cleanup/rollback procedure after the
  hosted proof succeeds.
- Update the Agent README's older local-simulation wording so it matches the
  current real GitHub/hosted capabilities.
- If the Cloud Run URL changes, update the GitHub webhook before testing.
- After the hackathon, disable the GitHub webhook, revoke/rotate the GitHub
  PAT and webhook secret, remove Secret Manager versions, reset or remove the
  shared judge account, and use Firebase release history/previous Agent image
  tags for rollback. Only run `terraform destroy` if `nightzero` is confirmed
  to be a dedicated disposable demo project.

## Security boundaries

- Never commit `.env`, Terraform state, PATs, Gemini keys, webhook secrets,
  Firebase ID tokens, or clone credentials.
- The Control Panel receives only public Firebase web configuration and the
  public Agent API URL. It must never receive GitHub or Gemini credentials.
- The webhook is publicly reachable solely for GitHub delivery; HMAC
  verification happens in the Agent before it starts work.
- Cloud approval requires a verified Firebase ID token and an email present in
  `NIGHTZERO_REVIEWER_ALLOWLIST`; local demo-token approval is not the hosted
  authorization path.
- A GitHub token was previously shared in chat during setup. Treat it as
  compromised: revoke it and create a replacement before the live proof, then
  add the replacement only as fresh Secret Manager versions.

## Validation already completed

- Agent tests passed with `13` tests after the Firestore, Firebase approval,
  and clone-credential work.
- Control Panel production build and lint passed.
- Terraform formatting/validation passed.
- Google Cloud foundation provisioning completed; no deployed Cloud Run image
  or Firebase Hosting release has yet been verified.

## Useful references

- `docs/todo.md` — delivered and remaining milestone checklist.
- `README.md` — local Agent setup, credential boundary, and tunnel helper.
- `../../NightZero-Infrastructure/README.md` — infrastructure prerequisites,
  bootstrap, deployment, rollback, and cleanup commands.
- `../../NightZero-Infrastructure/scripts/deploy.sh` — authoritative ordered
  deployment automation and required environment variable names.