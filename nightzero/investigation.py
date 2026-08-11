from __future__ import annotations

import asyncio
import json
from typing import Protocol

from nightzero.github import RepositoryEvidence
from nightzero.models import IncidentContext, InvestigationProposal


class InvestigationRunner(Protocol):
    def investigate(self, context: IncidentContext, issue_body: str, evidence: RepositoryEvidence) -> InvestigationProposal: ...


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