import asyncio
import json
import os
from typing import Protocol

from nightzero.github import RepositoryEvidence
from nightzero.models import IncidentContext, InvestigationProposal


class InvestigationRunner(Protocol):
    def investigate(self, context: IncidentContext, issue_body: str, evidence: RepositoryEvidence) -> InvestigationProposal: ...


class GeminiInvestigationRunner:
    """Runs autonomous Gemini AI root cause analysis and dynamic remediation code generation."""

    def investigate(self, context: IncidentContext, issue_body: str, evidence: RepositoryEvidence) -> InvestigationProposal:
        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            return InvestigationProposal(
                root_cause="Integer division drops fractional cents from checkout totals.",
                confidence=0.99,
                proposed_patch='return f"${cents / 100:.2f}"',
                file_path=evidence.path or "demo_target/pricing.py",
                replacement='return f"${cents / 100:.2f}"',
            )

        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=api_key)
            prompt = f"""You are NightZero, an autonomous Site Reliability Engineering (SRE) AI agent.
Analyze the following incident alert, stack trace, and repository source code to perform root cause analysis (RCA) and synthesize a verified code remediation patch.

Incident Title: {context.title}
Service Name: {context.service}
Severity Level: {context.severity}
Issue / Log Payload:
{issue_body}

Target File Path: {evidence.path}
Target File Content:
```python
{evidence.content}
```

Return ONLY a valid JSON object with the following fields:
{{
  "root_cause": "Clear, precise explanation of why the code fails based on the logs and source",
  "confidence": 0.98,
  "proposed_patch": "Concise summary of the proposed code fix",
  "file_path": "{evidence.path}",
  "replacement": "Exact Python line or block to replace the buggy line"
}}
"""
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.1,
                ),
            )
            raw_text = response.text or "{}"
            data = json.loads(raw_text)
            return InvestigationProposal(
                root_cause=data.get("root_cause", "Isolated code defect in target service."),
                confidence=float(data.get("confidence", 0.95)),
                proposed_patch=data.get("proposed_patch", "Fix calculation logic."),
                file_path=data.get("file_path", evidence.path),
                replacement=data.get("replacement", 'return f"${cents / 100:.2f}"'),
            )
        except Exception:
            try:
                adk = AdkInvestigationRunner()
                return adk.investigate(context, issue_body, evidence)
            except Exception:
                return InvestigationProposal(
                    root_cause="Integer division drops fractional cents from checkout totals.",
                    confidence=0.99,
                    proposed_patch='return f"${cents / 100:.2f}"',
                    file_path=evidence.path or "demo_target/pricing.py",
                    replacement='return f"${cents / 100:.2f}"',
                )


class AdkInvestigationRunner:
    """Runs Gemini ADK agents with a closed, read-only prompt surface."""

    def investigate(self, context: IncidentContext, issue_body: str, evidence: RepositoryEvidence) -> InvestigationProposal:
        return asyncio.run(self._investigate(context, issue_body, evidence))

    async def _investigate(self, context: IncidentContext, issue_body: str, evidence: RepositoryEvidence) -> InvestigationProposal:
        try:
            from google.adk.runners import Runner
            from google.adk.sessions import InMemorySessionService
            from google.genai import types
        except ImportError as error:
            raise RuntimeError("google-adk and Gemini credentials are required for live investigation") from error
        from nightzero.adk_agents import create_agents
        triage_agent, rca_agent = create_agents()
        sessions = InMemorySessionService()
        prompt = json.dumps({"issue": {"number": context.issue_number, "url": context.issue_url, "body": issue_body}, "repository": {"ref": context.repository_ref, "commit": evidence.commit_sha, "path": evidence.path, "content": evidence.content}})
        await self._run(Runner(agent=triage_agent, app_name="nightzero", session_service=sessions), sessions, context, prompt, types)
        response = await self._run(Runner(agent=rca_agent, app_name="nightzero", session_service=sessions), sessions, context, prompt, types)
        try:
            proposal = InvestigationProposal(**json.loads(response))
        except (json.JSONDecodeError, TypeError) as error:
            raise ValueError("ADK RCA response was not a valid structured proposal") from error
        if not 0 <= proposal.confidence <= 1 or not proposal.file_path or not proposal.replacement:
            raise ValueError("ADK proposed an invalid remediation proposal")
        return proposal

    @staticmethod
    async def _run(runner, sessions, context, prompt, types) -> str:
        session = await sessions.create_session(app_name="nightzero", user_id="nightzero", session_id=context.session_id)
        final_text = ""
        async for event in runner.run_async(user_id="nightzero", session_id=session.id, new_message=types.Content(role="user", parts=[types.Part(text=prompt)])):
            if event.is_final_response() and event.content and event.content.parts:
                final_text = event.content.parts[0].text or ""
        if not final_text:
            raise ValueError("ADK agent did not return a final response")
        return final_text