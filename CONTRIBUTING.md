# Contributing to NightZero 🌌

Thank you for your interest in contributing to **NightZero**!

NightZero is an autonomous SRE multi-agent platform designed to detect, triage, investigate, sandbox-verify, and remediate production incidents with zero downtime and strict enterprise governance.

---

## 🏛️ Ecosystem Structure

- [**`NightZero`**](https://github.com/sudhir-asuracore/NightZero): Main landing portal, architectural documentation, and system specifications.
- [**`NightZero-Agent`**](https://github.com/sudhir-asuracore/NightZero-Agent): Core Python multi-agent SRE runtime, Google ADK agents, Model Armor firewall, SPIFFE identity, and REST API.
- [**`NightZero-ControlPanel`**](https://github.com/sudhir-asuracore/NightZero-ControlPanel): Real-time React/Vite/Tailwind dashboard with forensic explorer, incident timelines, and human approval gating.
- [**`NightZero-Infrastructure`**](https://github.com/sudhir-asuracore/NightZero-Infrastructure): Terraform & shell automation for Cloud Run, Cloud Logging sinks, Firestore, and GCP IAM.
- [**`NightZero-TestProject`**](https://github.com/sudhir-asuracore/NightZero-TestProject): Microservice target application (`demo-payment-gateway`) used for chaos injection and remediation testing.

---

## 🛠️ Development Workflow

1. **Fork and Clone** the relevant repository.
2. **Create a Feature Branch**: `git checkout -b feat/my-improvement`.
3. **Run Test Suites**:
   - Python: `python3 -m unittest discover -s tests -v`
   - React UI: `npm test` and `npm run build`
4. **Commit using Conventional Commits**: `feat:`, `fix:`, `docs:`, `chore:`.
5. **Open a Pull Request** against `main`.

---

## 🛡️ Code & Safety Standards

- **Model Armor Compliance**: Ensure any LLM-facing code goes through Model Armor prompt defense and secret redaction.
- **Agent Identity & RBAC**: Personas must declare explicit SPIFFE IDs and abide by the least-privilege tool access matrix in `AgentGateway`.
- **Zero Production Branch Direct Writes**: Autonomous remediations must always execute in ephemeral sandboxes and generate draft PRs gated by human authorization.
