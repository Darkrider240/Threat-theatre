from typing import Annotated, Literal
from pydantic import BaseModel, Field

class MitreTTP(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float

class AttackerProfile(BaseModel):
    suspected_group: str
    confidence_score: float
    ttps: list[MitreTTP]

class BlastRadius(BaseModel):
    compromised_asset: str
    predicted_next_target: str
    lateral_path: Annotated[list[str], Field(min_length=3, max_length=3)]
    assets_at_risk: Annotated[list[str], Field(min_length=2, max_length=2)]

class RecommendedAction(BaseModel):
    priority: int
    action: str
    urgency: Literal["Immediate", "Within 1 hour", "Within 24 hours"]

class PredictiveBrief(BaseModel):
    event_id: str
    asset_type: str
    generated_at: str
    attacker_profile: AttackerProfile
    blast_radius: BlastRadius
    recommended_actions: Annotated[list[RecommendedAction], Field(min_length=3, max_length=3)]
    summary: str
