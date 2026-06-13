from models import PredictiveBrief
from knowledge_base import THREAT_PROFILES

for key, data in THREAT_PROFILES.items():
    brief_data = {
        "event_id": f"evt-{key}",
        "asset_type": "Cloud" if "aws" in key else "On-Premises",
        "generated_at": "2026-06-13T12:00:00Z",
        "attacker_profile": data["attacker_profile"],
        "blast_radius": data["blast_radius"],
        "recommended_actions": data["recommended_actions"],
        "summary": f"Summary for {key}"
    }
    brief = PredictiveBrief(**brief_data)
    print(f"Validated {key} successfully: {brief.event_id}")
