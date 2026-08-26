"""Model Armor: Inline AI Firewall, Prompt Injection Defense, and PII/Secret Redaction Engine.

Part of NightZero Enterprise Security & Governance (Gemini Enterprise Agent Platform).
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("nightzero.model_armor")


@dataclass(frozen=True)
class RedactionMatch:
    kind: str
    redacted_token: str
    count: int


@dataclass(frozen=True)
class ArmorInspectionResult:
    is_safe: bool
    sanitized_text: str
    prompt_injection_detected: bool
    threat_details: list[str] = field(default_factory=list)
    redactions: list[RedactionMatch] = field(default_factory=list)
    safety_score: float = 1.0  # 1.0 = completely clean, 0.0 = high risk threat


@dataclass(frozen=True)
class ArmorPatchInspectionResult:
    is_safe: bool
    blocked_patterns: list[str] = field(default_factory=list)
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL


class ModelArmor:
    """Inline AI Firewall providing real-time prompt injection defense and credential redaction."""

    # High-confidence prompt injection / jailbreak heuristics
    PROMPT_INJECTION_PATTERNS = [
        r"(?i)\b(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules))\b",
        r"(?i)\b(disregard\s+(the\s+)?system\s+prompt)\b",
        r"(?i)\b(you\s+are\s+now\s+(in\s+)?developer\s+mode)\b",
        r"(?i)\b(system\s+override\s*:\s*execute)\b",
        r"(?i)\b(bypass\s+(all\s+)?safety\s+guidelines)\b",
        r"(?i)\b(reveal\s+(your\s+)?(initial|system)\s+(instructions|prompt))\b",
        r"(?i)\b(print\s+(the\s+)?hidden\s+system\s+context)\b",
        r"(?i)\b(sudo\s+mode\s+enabled)\b",
        r"(?i)\b(DAN\s+mode\s+activated)\b",
    ]

    # Secret & PII redaction regexes
    SECRET_PATTERNS = [
        ("GOOGLE_API_KEY", r"AIza[0-9A-Za-z-_]{35}"),
        ("GITHUB_TOKEN", r"gh[pousr]_[0-9A-Za-z]{36,255}"),
        ("GENERIC_BEARER_TOKEN", r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{24,}"),
        ("PRIVATE_KEY", r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[\s\S]+?-----END[ A-Z0-9_-]+PRIVATE KEY-----"),
        ("AWS_SECRET_KEY", r"(?i)aws_secret_access_key\s*[:=]\s*[0-9a-zA-Z/+]{40}"),
        ("DATABASE_URL", r"(?i)(postgres|mysql|mongodb|redis)://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_\-\.]+"),
        ("PASSWORD_FIELD", r"(?i)(password|passwd|secret|token)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
        ("EMAIL_ADDRESS", r"\b[A-Za-z0-9._%+-]+@(?!github\.com|asuracore\.com|google\.com)[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    ]

    # Dangerous code patterns in generated patches
    DANGEROUS_CODE_PATTERNS = [
        (r"(?i)\bos\s*\.\s*system\s*\(", "Arbitrary system shell command execution via os.system"),
        (r"(?i)\bsubprocess\s*\.\s*(Popen|run|call)\s*\([^)]*shell\s*=\s*True", "Subprocess invocation with shell=True"),
        (r"(?i)\bexec\s*\(", "Dynamic code execution via exec()"),
        (r"(?i)\beval\s*\(", "Dynamic code execution via eval()"),
        (r"(?i)\b__import__\s*\(", "Obfuscated dynamic module import"),
        (r"(?i)\bshutil\s*\.\s*rmtree\s*\(\s*['\"]\/", "Destructive recursive filesystem deletion on root"),
        (r"(?i)\bsocket\s*\.\s*connect\s*\(", "Direct outbound socket network connection in patch"),
    ]

    @classmethod
    def sanitize_input(cls, text: str, strict: bool = False) -> ArmorInspectionResult:
        """Inspects incoming telemetry, stack traces, or issue text for prompt injection and redacts PII/secrets."""
        if not text:
            return ArmorInspectionResult(is_safe=True, sanitized_text="", prompt_injection_detected=False)

        threat_details: list[str] = []
        prompt_injection_detected = False

        # 1. Prompt Injection Inspection
        for pattern in cls.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, text):
                prompt_injection_detected = True
                threat_details.append(f"Prompt injection pattern detected: '{pattern}'")

        # 2. Secret & PII Redaction
        sanitized = text
        redactions: list[RedactionMatch] = []

        for name, pattern in cls.SECRET_PATTERNS:
            matches = list(re.finditer(pattern, sanitized))
            if matches:
                count = len(matches)
                redacted_label = f"[REDACTED_{name}]"
                sanitized = re.sub(pattern, redacted_label, sanitized)
                redactions.append(RedactionMatch(kind=name, redacted_token=redacted_label, count=count))

        # Calculate safety score
        safety_score = 1.0
        if prompt_injection_detected:
            safety_score -= 0.6
        if redactions:
            safety_score -= min(0.3, len(redactions) * 0.1)

        is_safe = not (prompt_injection_detected and strict)

        if threat_details or redactions:
            logger.info(
                "Model Armor inspection: prompt_injection=%s, redactions=%d, safety_score=%.2f",
                prompt_injection_detected,
                len(redactions),
                safety_score,
            )

        return ArmorInspectionResult(
            is_safe=is_safe,
            sanitized_text=sanitized,
            prompt_injection_detected=prompt_injection_detected,
            threat_details=threat_details,
            redactions=redactions,
            safety_score=max(0.0, safety_score),
        )

    @classmethod
    def inspect_patch_safety(cls, patch_code: str) -> ArmorPatchInspectionResult:
        """Inspects proposed remediation code patches to ensure no malicious constructs or backdoors are introduced."""
        if not patch_code:
            return ArmorPatchInspectionResult(is_safe=True)

        blocked: list[str] = []
        for pattern, desc in cls.DANGEROUS_CODE_PATTERNS:
            if re.search(pattern, patch_code):
                blocked.append(desc)

        if blocked:
            logger.warning("Model Armor blocked dangerous patch constructs: %s", blocked)
            return ArmorPatchInspectionResult(
                is_safe=False,
                blocked_patterns=blocked,
                risk_level="CRITICAL" if len(blocked) > 1 else "HIGH",
            )

        return ArmorPatchInspectionResult(is_safe=True, risk_level="LOW")
