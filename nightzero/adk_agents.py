"""Google ADK agent declarations for a deployed Gemini-backed workflow."""

from google.adk.agents import Agent


triage_agent = Agent(
    name="nightzero_triage",
    model="gemini-2.5-flash",
    instruction="Frame a GitHub issue as a typed NightZero incident context.",
)

rca_agent = Agent(
    name="nightzero_rca",
    model="gemini-2.5-flash",
    instruction="Use read-only evidence to identify a supported root cause.",
)