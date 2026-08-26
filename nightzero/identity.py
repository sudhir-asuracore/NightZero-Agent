"""Agent Identity: Zero-Trust SPIFFE Identity, Attestation Tokens, and Dual Authority Governance.

Part of NightZero Enterprise Security & Governance (Gemini Enterprise Agent Platform).
"""

from __future__ import annotations

import hmac
import hashlib
import json
import base64
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuthorityModel(str, Enum):
    OWN_AUTHORITY = "OWN_AUTHORITY"          # Autonomous execution for read/triage/sandbox
    USER_DELEGATED = "USER_DELEGATED"        # Delegated approval from allowlisted human reviewer


class SubagentPersona(str, Enum):
    TRIAGE = "triage"
    INSPECTOR = "inspector"
    RCA = "rca"
    SANDBOX = "sandbox"
    REMEDIATION = "remediation"
    HUMAN_REVIEWER = "human_reviewer"


@dataclass(frozen=True)
class AgentIdentity:
    spiffe_id: str
    persona: SubagentPersona
    authority_model: AuthorityModel
    granted_scopes: list[str]
    actor_id: str = "nightzero-system"
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)

    @property
    def domain(self) -> str:
        return self.spiffe_id.replace("spiffe://", "").split("/")[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "spiffe_id": self.spiffe_id,
            "persona": self.persona.value,
            "authority_model": self.authority_model.value,
            "granted_scopes": self.granted_scopes,
            "actor_id": self.actor_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentIdentity:
        return cls(
            spiffe_id=data["spiffe_id"],
            persona=SubagentPersona(data["persona"]),
            authority_model=AuthorityModel(data["authority_model"]),
            granted_scopes=data.get("granted_scopes", []),
            actor_id=data.get("actor_id", "nightzero-system"),
            issued_at=data.get("issued_at", time.time()),
            expires_at=data.get("expires_at", time.time() + 3600),
        )


class AgentIdentityRegistry:
    """Issues, verifies, and cryptographically signs Zero-Trust Agent Identities."""

    DOMAIN = "nightzero.io"
    SECRET_KEY = os.environ.get("NIGHTZERO_IDENTITY_SECRET", "nightzero-enterprise-agent-signing-secret-key-2026")

    # Standard RBAC Scope Matrix per Subagent Persona
    PERSONA_SCOPES = {
        SubagentPersona.TRIAGE: [
            "telemetry.read",
            "telemetry.deduplicate",
            "context.create",
        ],
        SubagentPersona.INSPECTOR: [
            "git.read",
            "ast.inspect",
            "commit.blame",
        ],
        SubagentPersona.RCA: [
            "llm.infer",
            "rca.synthesize",
            "gap_analysis.generate",
        ],
        SubagentPersona.SANDBOX: [
            "sandbox.spawn",
            "sandbox.test_exec",
            "manifest.analyze",
            "memory_bank.read",
            "memory_bank.write",
        ],
        SubagentPersona.REMEDIATION: [
            "github.branch.create",
            "github.commit.write",
            "github.pr.create",
            "github.comment.write",
        ],
        SubagentPersona.HUMAN_REVIEWER: [
            "proposal.authorize",
            "settings.manage",
            "chaos.trigger",
        ],
    }

    @classmethod
    def get_identity(
        cls,
        persona: SubagentPersona,
        actor: str = "nightzero-system",
        delegated_reviewer: str | None = None,
    ) -> AgentIdentity:
        """Issues an AgentIdentity for the given subagent persona."""
        spiffe_id = f"spiffe://{cls.DOMAIN}/agent/{persona.value}"
        scopes = cls.PERSONA_SCOPES.get(persona, [])
        authority = AuthorityModel.USER_DELEGATED if delegated_reviewer else AuthorityModel.OWN_AUTHORITY
        actor_id = delegated_reviewer or actor

        return AgentIdentity(
            spiffe_id=spiffe_id,
            persona=persona,
            authority_model=authority,
            granted_scopes=scopes,
            actor_id=actor_id,
            issued_at=time.time(),
            expires_at=time.time() + 3600,
        )

    @classmethod
    def sign_agent_action(cls, identity: AgentIdentity, action: str, detail: str) -> str:
        """Generates a cryptographic HMAC-SHA256 signature for an agent execution step."""
        payload = f"{identity.spiffe_id}|{identity.authority_model.value}|{identity.actor_id}|{action}|{detail}"
        signature = hmac.new(
            cls.SECRET_KEY.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"ait-sha256-{signature[:16]}"

    @classmethod
    def verify_agent_signature(cls, identity: AgentIdentity, action: str, detail: str, signature: str) -> bool:
        """Verifies if an action signature matches the claimed AgentIdentity."""
        expected = cls.sign_agent_action(identity, action, detail)
        return hmac.compare_digest(expected, signature)
