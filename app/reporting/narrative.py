import os
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from dotenv import load_dotenv

load_dotenv()


def cluster_logs(raw_lines: list) -> list:
    config = TemplateMinerConfig()
    miner = TemplateMiner(config=config)
    for line in raw_lines:
        miner.add_log_message(str(line))
    clusters = sorted(miner.drain.clusters, key=lambda c: c.size, reverse=True)
    return [{"template": c.get_template(), "count": c.size} for c in clusters]


def generate_llm_narrative(incident_context: dict, clustered_logs: list) -> str:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return (
            "AI Narrative disabled: No GEMINI_API_KEY found in environment. "
            "Add GEMINI_API_KEY=your_key to your .env file and restart the server."
        )

    prompt = f"""You are an expert cybersecurity analyst writing for a non-technical executive audience.

An incident has been detected:
- User account: {incident_context.get('user')}
- Risk Level: {incident_context.get('risk_level')}
- Risk Score: {incident_context.get('score')}
- Security rules triggered: {incident_context.get('rules')}

The system logs for this incident have been grouped into patterns:
"""
    for c in clustered_logs:
        prompt += f"  - {c['count']} occurrence(s) of: {c['template']}\n"

    prompt += """
Write a clear, concise two-paragraph executive summary:
1. First paragraph: What happened — describe the suspicious activity in plain English. No technical jargon.
2. Second paragraph: Why it matters and what the business risk is.

Do NOT mention rule IDs, ML scores, or raw log strings. Write as if briefing a CEO."""

    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )
        return response.text.strip()
    except Exception as e:
        return f"Failed to generate narrative via Gemini: {str(e)}"
