import os
import time
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from dotenv import load_dotenv

load_dotenv()

# Models in priority order — confirmed active & available for this API key
CANDIDATE_MODELS = ["gemini-flash-latest", "gemini-3.5-flash-lite", "gemini-3.8-flash", "gemini-3.7-flash", "gemini-3.6-flash"]


def cluster_logs(raw_lines: list) -> list:
    config = TemplateMinerConfig()
    miner = TemplateMiner(config=config)
    for line in raw_lines:
        miner.add_log_message(str(line))
    clusters = sorted(miner.drain.clusters, key=lambda c: c.size, reverse=True)
    return [{"template": c.get_template(), "count": c.size} for c in clusters]


def _is_retryable(err: Exception) -> bool:
    """Return True for transient errors (503 overload, 429 rate-limit) that warrant a retry."""
    msg = str(err)
    return "503" in msg or "UNAVAILABLE" in msg or "429" in msg or "RESOURCE_EXHAUSTED" in msg


def _call_with_retry(client, model_name: str, prompt: str, max_retries: int = 3) -> str | None:
    """
    Attempt generate_content with exponential back-off on transient errors.
    Returns the text on success, or raises the last exception on exhaustion.
    """
    delay = 2  # initial wait in seconds
    last_err = None
    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(model=model_name, contents=prompt)
            if response and response.text:
                return response.text.strip()
            return None
        except Exception as ex:
            last_err = ex
            if _is_retryable(ex) and attempt < max_retries - 1:
                time.sleep(delay)
                delay *= 2  # back-off: 2s → 4s → 8s
                continue
            raise last_err
    raise last_err


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

    last_err = None
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        for model_name in CANDIDATE_MODELS:
            try:
                text = _call_with_retry(client, model_name, prompt)
                if text:
                    return text
            except Exception as ex:
                last_err = ex
                # 404 = model not found for this key → try next model immediately
                # other errors (503 exhausted retries) → also try next model
                continue
        return f"AI narrative temporarily unavailable. Please try again in a moment. (Last error: {str(last_err)})"
    except Exception as e:
        return f"Failed to generate narrative via Gemini: {str(e)}"
