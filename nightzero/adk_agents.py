"""Google ADK agent declarations, loaded only in a configured Agent runtime."""


def create_agents():
    try:
        from google.adk.agents import Agent
    except ImportError as error:
        raise RuntimeError("google-adk must be installed in the Agent runtime") from error
    triage_agent = Agent(name="nightzero_triage", model="gemini-2.5-flash", instruction="Summarize only supplied read-only error logs and GitHub evidence.")
    rca_agent = Agent(name="nightzero_rca", model="gemini-2.5-flash", instruction="Return JSON only with root_cause, confidence, proposed_patch, file_path, and replacement. Analyze evidence carefully and specify the target file_path and exact code replacement.")
    return triage_agent, rca_agent