import json
import os
import requests
from datetime import datetime, timezone
import uuid
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI
from models import PredictiveBrief, AttackerProfile, BlastRadius, RecommendedAction

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Scenario(BaseModel):
    asset_type: str
    display_name: str
    description: str
    threat_level: str
    icon: str

class AnalyzeRequest(BaseModel):
    asset_type: str
    source_ip: str

class ChatRequest(BaseModel):
    brief_context: str
    messages: list[dict]
    new_message: str

@app.get("/health")
def health():
    return {"status": "ok", "service": "Ghost Protocol: Threat Theatre"}

@app.get("/api/scenarios", response_model=list[Scenario])
def get_scenarios():
    return [
        Scenario(
            asset_type="canary_aws_token",
            display_name="AWS Canary Token Breach",
            description="An alert was triggered when a honeypot AWS access key was used to execute suspicious IAM lookups.",
            threat_level="CRITICAL",
            icon="🔑"
        ),
        Scenario(
            asset_type="honeypot_ssh",
            display_name="SSH Honeypot Intrusion",
            description="A perimeter firewall detected brute force SSH attempts culminating in a successful credential compromise.",
            threat_level="HIGH",
            icon="🛡️"
        ),
        Scenario(
            asset_type="fake_db_credentials",
            display_name="Decoy DB Credential Leak",
            description="Decoy database credentials stored in a staging environment configuration file were accessed.",
            threat_level="HIGH",
            icon="🗄️"
        ),
        Scenario(
            asset_type="decoy_file",
            display_name="Decoy File Access",
            description="A sensitive financial planning document containing decoy info was opened from an unauthorized endpoint.",
            threat_level="MEDIUM",
            icon="📄"
        )
    ]

@app.post("/api/analyze", response_model=PredictiveBrief)
def analyze(req: AnalyzeRequest):
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        raise HTTPException(status_code=500, detail="GITHUB_TOKEN is not configured")

    client = OpenAI(
        base_url="https://models.inference.ai.azure.com",
        api_key=github_token,
    )

    prompt = (
        "You are a cyber threat reasoning engine. Given the trigger event, reason through "
        "the likely attack pattern, identify MITRE ATT&CK techniques, predict lateral "
        "movement, and return only valid JSON matching this exact structure:\n"
        '{\n'
        '  "suspected_group": str,\n'
        '  "confidence_score": float,\n'
        '  "ttps": [{"technique_id": str, "technique_name": str, "tactic": str, "confidence": float}],\n'
        '  "compromised_asset": str,\n'
        '  "predicted_next_target": str,\n'
        '  "lateral_path": [str, str, str],\n'
        '  "assets_at_risk": [str, str],\n'
        '  "recommended_actions": [{"priority": int, "action": str, "urgency": str}],\n'
        '  "summary": str\n'
        "}\n"
        'Use urgency values exactly from: "Immediate", "Within 1 hour", "Within 24 hours". '
        f"Trigger event asset_type={req.asset_type}, source_ip={req.source_ip}."
    )

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "Return only JSON. No markdown, no commentary."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
        response_format={"type": "json_object"},
    )

    content = response.choices[0].message.content
    if not content:
        raise HTTPException(status_code=502, detail="Model returned an empty response")

    analysis = json.loads(content)

    attacker_profile_obj = AttackerProfile(
        suspected_group=analysis["suspected_group"],
        confidence_score=analysis["confidence_score"],
        ttps=analysis["ttps"],
    )
    blast_radius_obj = BlastRadius(
        compromised_asset=analysis["compromised_asset"],
        predicted_next_target=analysis["predicted_next_target"],
        lateral_path=analysis["lateral_path"],
        assets_at_risk=analysis["assets_at_risk"],
    )
    rec_actions_objs = [RecommendedAction(**ra) for ra in analysis["recommended_actions"]]

    return PredictiveBrief(
        event_id=str(uuid.uuid4()),
        asset_type=req.asset_type,
        generated_at=datetime.now(timezone.utc).isoformat(),
        attacker_profile=attacker_profile_obj,
        blast_radius=blast_radius_obj,
        recommended_actions=rec_actions_objs,
        summary=analysis["summary"]
    )

@app.post("/api/chat")
def chat(req: ChatRequest):
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        return {
            "reply": "Ghost Protocol is processing. Stand by.",
            "role": "assistant"
        }
    try:
        client = OpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=github_token,
        )
        system_prompt = f"You are Ghost Protocol, an elite cybersecurity threat intelligence analyst embedded in a SOC war room. You have just completed analysis of a deception asset breach and produced a Predictive Attacker Brief. The analyst is now asking you follow-up questions. Answer with precision, confidence, and tactical clarity. Reference specific details from the brief in your answers. Never break character. The brief context is: {req.brief_context}"
        api_messages = [{"role": "system", "content": system_prompt}]
        for msg in req.messages:
            api_messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
        api_messages.append({"role": "user", "content": req.new_message})
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=api_messages,
            temperature=0.4,
            max_tokens=400,
        )
        reply = response.choices[0].message.content
        return {
            "reply": reply,
            "role": "assistant"
        }
    except Exception:
        return {
            "reply": "Ghost Protocol is processing. Stand by.",
            "role": "assistant"
        }

@app.get("/api/threat-feed")
def get_threat_feed():
    fallback_cves = [
        {
            "cve_id": "CVE-2026-0001",
            "description": "Critical remote code execution in OpenSSL affecting TLS handshake",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published": "2026-06-01",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001"
        },
        {
            "cve_id": "CVE-2026-0002",
            "description": "Privilege escalation via kernel memory corruption in Linux",
            "severity": "CRITICAL",
            "cvss_score": 9.6,
            "published": "2026-06-03",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0002"
        },
        {
            "cve_id": "CVE-2026-0003",
            "description": "Authentication bypass in Apache HTTP Server mod_auth",
            "severity": "CRITICAL",
            "cvss_score": 9.4,
            "published": "2026-06-05",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0003"
        }
    ]
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cvssV3Severity": "CRITICAL", "resultsPerPage": 6},
            timeout=8
        )
        response.raise_for_status()
        data = response.json()
        parsed_cves = []
        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:120]
                    break
            cvss_score = 9.0
            metrics = cve_data.get("metrics", {})
            cvss_metrics = metrics.get("cvssMetricV31", [])
            if cvss_metrics:
                cvss_score = cvss_metrics[0].get("cvssData", {}).get("baseScore", 9.0)
            published = cve_data.get("published", "")[:10]
            parsed_cves.append({
                "cve_id": cve_id,
                "description": description,
                "severity": "CRITICAL",
                "cvss_score": cvss_score,
                "published": published,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })
        return {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_critical": len(parsed_cves),
            "cves": parsed_cves
        }
    except Exception:
        return {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_critical": len(fallback_cves),
            "cves": fallback_cves
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
