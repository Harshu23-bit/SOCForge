from pydantic import BaseModel, Field
from typing import List, Optional

class TriageReport(BaseModel):
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, or LOW")
    risk_score: int = Field(description="Numeric risk score from 0 to 100")
    summary: str = Field(description="Concise 1-2 sentence executive summary of the incident")
    mitre_tactic: Optional[str] = Field(default="N/A", description="Associated MITRE ATT&CK Tactic e.g. Execution")
    mitre_technique_id: Optional[str] = Field(default="N/A", description="Associated MITRE ATT&CK Technique ID e.g. T1059")
    recommended_action: List[str] = Field(description="List of actionable mitigation or containment steps")
