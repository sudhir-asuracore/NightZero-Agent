# Security & Governance Policy 🛡️

The NightZero project takes enterprise security and AI safety with paramount importance.

---

## 🔒 Enterprise Security Architecture

NightZero incorporates multi-layered defense-in-depth:
1. **Model Armor (AI Firewall)**:
   - Real-time prompt injection, jailbreak, and delimiter hijacking detection.
   - Inline redaction of API keys, GitHub PATs, JWT tokens, and sensitive PII.
   - Code patch AST safety analyzer blocking dangerous dynamic execution (`os.system`, `subprocess(shell=True)`, `eval`, `exec`).
2. **Zero-Trust SPIFFE Cryptographic Identity**:
   - Each subagent executes with an attested SPIFFE ID (`spiffe://nightzero.io/agent/*`).
   - Actions generate cryptographically signed Agent Identity Tokens (AIT).
   - Dual-authority model: Read/Sandbox actions execute under `OWN_AUTHORITY`, while Git PR creation strictly requires `USER_DELEGATED` authority with verified human signature.
3. **Agent Gateway**:
   - Central policy interceptor enforcing Role-Based Access Control (RBAC) across LLM tools.

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability or bypass in Model Armor or Agent Gateway:
- **Do NOT open a public GitHub issue.**
- Please email the maintainers directly at `security@asuracore.com` or `sidigrid@gmail.com`.
- We will acknowledge receipt within 24 hours and coordinate a responsible disclosure timeline.
