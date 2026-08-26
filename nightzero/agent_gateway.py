"""Agent Gateway: Unified Routing, RBAC Policy Enforcement, and Audit Provenance.

Part of NightZero Enterprise Security & Governance (Gemini Enterprise Agent Platform).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from nightzero.identity import AgentIdentity, AgentIdentityRegistry, AuthorityModel, SubagentPersona
from nightzero.model_armor import ModelArmor, ArmorInspectionResult

logger = logging.getLogger("nightzero.agent_gateway")


class SecurityPolicyViolationError(PermissionError):
    """Raised when an Agent attempts an unauthorized action or violates gateway policy."""
    pass


@dataclass(frozen=True)
class GatewayPolicyRule:
    action_scope: str
    allowed_personas: list[SubagentPersona]
    requires_delegation: bool = False
    requires_model_armor: bool = False


class AgentGateway:
    """Central Governance & Routing Gateway enforcing Zero-Trust RBAC and Model Armor."""

    # Gateway Policy Registry
    POLICIES: dict[str, GatewayPolicyRule] = {
        "telemetry.read": GatewayPolicyRule(
            action_scope="telemetry.read",
            allowed_personas=[SubagentPersona.TRIAGE],
            requires_model_armor=True,
        ),
        "git.read": GatewayPolicyRule(
            action_scope="git.read",
            allowed_personas=[SubagentPersona.INSPECTOR, SubagentPersona.SANDBOX],
        ),
        "llm.infer": GatewayPolicyRule(
            action_scope="llm.infer",
            allowed_personas=[SubagentPersona.RCA, SubagentPersona.SANDBOX],
            requires_model_armor=True,
        ),
        "sandbox.spawn": GatewayPolicyRule(
            action_scope="sandbox.spawn",
            allowed_personas=[SubagentPersona.SANDBOX],
        ),
        "sandbox.test_exec": GatewayPolicyRule(
            action_scope="sandbox.test_exec",
            allowed_personas=[SubagentPersona.SANDBOX],
        ),
        "github.branch.create": GatewayPolicyRule(
            action_scope="github.branch.create",
            allowed_personas=[SubagentPersona.REMEDIATION],
            requires_delegation=True,
        ),
        "github.commit.write": GatewayPolicyRule(
            action_scope="github.commit.write",
            allowed_personas=[SubagentPersona.REMEDIATION],
            requires_delegation=True,
            requires_model_armor=True,
        ),
        "github.pr.create": GatewayPolicyRule(
            action_scope="github.pr.create",
            allowed_personas=[SubagentPersona.REMEDIATION],
            requires_delegation=True,
        ),
    }

    @classmethod
    def enforce_policy(
        cls,
        identity: AgentIdentity,
        action_scope: str,
        payload: str | None = None,
    ) -> ArmorInspectionResult | None:
        """Enforces RBAC permissions, authority delegation, and Model Armor inspection before action execution."""
        policy = cls.POLICIES.get(action_scope)

        # 1. Unknown action scope: allow if identity has explicit scope
        if not policy:
            if action_scope not in identity.granted_scopes:
                logger.error("Agent Gateway: Unregistered action %s rejected for %s", action_scope, identity.spiffe_id)
                raise SecurityPolicyViolationError(
                    f"Agent Gateway Policy Violation: Action '{action_scope}' is not permitted for identity '{identity.spiffe_id}'."
                )
            return None

        # 2. Check Persona RBAC
        if identity.persona not in policy.allowed_personas:
            msg = (
                f"Agent Gateway Policy Violation: Persona '{identity.persona.value}' ({identity.spiffe_id}) "
                f"is unauthorized for action scope '{action_scope}'. Allowed: {[p.value for p in policy.allowed_personas]}."
            )
            logger.error(msg)
            raise SecurityPolicyViolationError(msg)

        # 3. Check Authority Delegation Requirement (e.g. GitHub writes require human review authorization)
        if policy.requires_delegation and identity.authority_model != AuthorityModel.USER_DELEGATED:
            msg = (
                f"Agent Gateway Policy Violation: Action '{action_scope}' requires USER_DELEGATED authority. "
                f"Agent '{identity.spiffe_id}' is executing with OWN_AUTHORITY without a verified human reviewer signature."
            )
            logger.error(msg)
            raise SecurityPolicyViolationError(msg)

        # 4. Apply Model Armor Guardrail if required
        armor_result: ArmorInspectionResult | None = None
        if policy.requires_model_armor and payload is not None:
            armor_result = ModelArmor.sanitize_input(payload)
            if not armor_result.is_safe:
                msg = f"Agent Gateway Model Armor Blocked Action: Threat detected in payload: {armor_result.threat_details}"
                logger.error(msg)
                raise SecurityPolicyViolationError(msg)

        logger.info(
            "Agent Gateway authorized: identity=%s, action=%s, authority=%s",
            identity.spiffe_id,
            action_scope,
            identity.authority_model.value,
        )
        return armor_result

    @classmethod
    def get_governance_overview(cls) -> dict[str, Any]:
        """Returns the full Enterprise Security & Governance state for ControlPanel."""
        return {
            "model_armor": {
                "status": "ACTIVE",
                "features": [
                    "Inline Prompt Injection & Delimiter Defense",
                    "Secret & PII Redaction (API Keys, PATs, JWTs, Passwords)",
                    "Patch Safety Scanner (RCE & Dangerous Code Blocklist)",
                ],
                "active_heuristics_count": len(ModelArmor.PROMPT_INJECTION_PATTERNS) + len(ModelArmor.SECRET_PATTERNS),
            },
            "agent_identity": {
                "domain": AgentIdentityRegistry.DOMAIN,
                "signing_algorithm": "HMAC-SHA256 (AIT Tokens)",
                "registered_personas": [
                    {"persona": p.value, "spiffe_id": f"spiffe://{AgentIdentityRegistry.DOMAIN}/agent/{p.value}", "scopes": AgentIdentityRegistry.PERSONA_SCOPES.get(p, [])}
                    for p in SubagentPersona
                ],
            },
            "agent_gateway": {
                "status": "ENFORCING",
                "policies": [
                    {
                        "action_scope": rule.action_scope,
                        "allowed_personas": [p.value for p in rule.allowed_personas],
                        "requires_delegation": rule.requires_delegation,
                        "requires_model_armor": rule.requires_model_armor,
                    }
                    for rule in cls.POLICIES.values()
                ],
            },
        }
