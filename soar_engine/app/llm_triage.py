import logging
from google import genai
from google.genai import types
from app.config import settings
from app.schemas import TriageReport

logger = logging.getLogger("socforge-soar")

def analyze_alert_with_llm(alert_data: dict) -> TriageReport:
    """Pass enriched alert payload to Gemini for structured JSON triage."""
    if not settings.GEMINI_API_KEY:
        logger.warning("Gemini API key missing. Returning fallback triage report.")
        return TriageReport(
            severity="UNKNOWN",
            risk_score=0,
            summary="AI triage skipped: GEMINI_API_KEY not found in environment.",
            recommended_action=["Check soar_engine/.env configuration."]
        )

    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)

        prompt = f"""
        You are the SOCForge Autonomous AI Triage Engine.
        Analyze the following security telemetry and threat intelligence payload:

        Payload:
        {alert_data}

        Perform automated triage:
        1. Assess threat level and assign a severity (CRITICAL, HIGH, MEDIUM, LOW) and risk score (0-100).
        2. Correlate activity with the MITRE ATT&CK framework (Tactic & Technique ID).
        3. Provide 2-3 specific incident response actions.
        """

        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=TriageReport,
                temperature=0.2,
            ),
        )

        return TriageReport.model_validate_json(response.text)

    except Exception as e:
        logger.error(f"Gemini LLM Triage Error: {str(e)}")
        return TriageReport(
            severity="ERROR",
            risk_score=0,
            summary=f"LLM Triage failed: {str(e)}",
            recommended_action=["Inspect SOCForge middleware error logs."]
        )
