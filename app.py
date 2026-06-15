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
    user_environment: dict

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

    env = req.user_environment
    org_name = env.get("org_name", "")
    cloud_provider = env.get("cloud_provider", "")
    key_assets = env.get("key_assets", [])
    os_stack = env.get("os_stack", "")
    team_size = env.get("team_size", "")
    industry = env.get("industry", "")
    existing_security_tools = env.get("existing_security_tools", "")
    
    uses_active_directory = env.get("uses_active_directory", False)
    active_directory = env.get("active_directory", None)
    architecture_description = env.get("architecture_description", "")

    ad_info = ""
    if uses_active_directory and active_directory:
        ad = active_directory
        ad_info = f"- Active Directory: Domain {ad.get('domain_name', '')}, {ad.get('domain_controller_count', '')} DCs, {ad.get('forest_type', '')}, {ad.get('hybrid_mode', '')}, {ad.get('privileged_account_count', '')} privileged accounts, {ad.get('service_account_count', '')} service accounts, trusts: {ad.get('trust_relationships', '')}, AD tools: {ad.get('ad_security_tools', '')}\n"

    prompt = (
        f"Trigger Event Details:\n"
        f"- Asset Type: {req.asset_type}\n"
        f"- Source IP: {req.source_ip}\n\n"
        f"Organization Environment Under Attack:\n"
        f"- Organization Name: {org_name}\n"
        f"- Cloud Provider: {cloud_provider}\n"
        f"- Key Assets: {key_assets}\n"
        f"- OS Stack: {os_stack}\n"
        f"- Team Size: {team_size}\n"
        f"- Industry: {industry}\n"
        f"- Existing Security Tools: {existing_security_tools}\n"
        f"{ad_info}"
        f"- Architecture Description: {architecture_description}\n\n"
        f"Based on the trigger event and organization environment above, reason through "
        f"the likely attack pattern, identify MITRE ATT&CK techniques, and predict threat impact. "
        f"You must specifically:\n"
        f"- Reference the organization '{org_name}', cloud provider '{cloud_provider}', key assets {key_assets}, OS stack '{os_stack}', and industry '{industry}' explicitly.\n"
        f"- Generate a blast radius (compromised_asset, predicted_next_target, lateral_path, assets_at_risk) that names the organization's actual assets from key assets: {key_assets} instead of generic names.\n"
        f"- Generate lateral movement paths reflecting their actual cloud provider '{cloud_provider}' and OS stack '{os_stack}'.\n"
        f"- Make recommended actions specific to their existing security tools '{existing_security_tools}'.\n"
        f"- Generate a summary that feels written specifically for '{org_name}' in the '{industry}' industry.\n\n"
        f"Return only valid JSON matching this exact structure:\n"
        f"{{\n"
        f'  "suspected_group": str,\n'
        f'  "confidence_score": float,\n'
        f'  "ttps": [{{"technique_id": str, "technique_name": str, "tactic": str, "confidence": float}}],\n'
        f'  "compromised_asset": str,\n'
        f'  "predicted_next_target": str,\n'
        f'  "lateral_path": [str, str, str],\n'
        f'  "assets_at_risk": [str, str],\n'
        f'  "recommended_actions": [{{"priority": int, "action": str, "urgency": str}}],\n'
        f'  "summary": str\n'
        f"}}\n"
        f"Requirements:\n"
        f"- The lateral_path list must contain EXACTLY 3 elements.\n"
        f"- The assets_at_risk list must contain EXACTLY 2 elements.\n"
        f"- The recommended_actions list must contain EXACTLY 3 elements.\n"
        f'- Use urgency values exactly from: "Immediate", "Within 1 hour", "Within 24 hours".'
    )

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are Ghost Protocol, an elite cyber threat intelligence engine embedded in a SOC war room. "
                    "You have been given the exact infrastructure details of the organization under attack. "
                    "Every answer must be specific to their environment — never use generic asset names. "
                    "Return only valid JSON matching the exact schema provided."
                )
            },
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

class CorrelateRequest(BaseModel):
    cves: list[dict]
    asset_type: str
    user_environment: dict

@app.post("/api/correlate-cves")
def correlate_cves(req: CorrelateRequest):
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        return {
            "relevant_cves": [],
            "correlation_summary": "Correlation engine unavailable. Manual review recommended."
        }

    try:
        client = OpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=github_token,
        )

        env = req.user_environment
        cloud_provider = env.get("cloud_provider", "")
        os_stack = env.get("os_stack", "")
        key_assets = env.get("key_assets", [])
        industry = env.get("industry", "")

        cves_details = []
        for cve in req.cves:
            cve_id = cve.get("cve_id", "")
            description = cve.get("description", "")
            cvss_score = cve.get("cvss_score", 9.0)
            cves_details.append(f"- {cve_id} (Score: {cvss_score}): {description}")
        cves_str = "\n".join(cves_details)

        prompt = (
            f"Active Attack Scenario:\n"
            f"- Asset Type: {req.asset_type}\n\n"
            f"Organization Infrastructure:\n"
            f"- Cloud Provider: {cloud_provider}\n"
            f"- OS Stack: {os_stack}\n"
            f"- Key Assets: {key_assets}\n"
            f"- Industry: {industry}\n\n"
            f"Live CVEs:\n"
            f"{cves_str}\n\n"
            f"Based on the active attack scenario and organization infrastructure, identify which CVEs are most relevant. "
            f"Return only valid JSON matching this exact structure:\n"
            f"{{\n"
            f'  "relevant_cves": [\n'
            f'    {{\n'
            f'      "cve_id": str,\n'
            f'      "relevance_reason": str,\n'
            f'      "risk_level": str,\n'
            f'      "cvss_score": float\n'
            f'    }}\n'
            f'  ],\n'
            f'  "correlation_summary": str\n'
            f"}}\n"
            f"Requirements:\n"
            f'- relevance_reason must be exactly 1 sentence explaining why this CVE matters for this specific attack and organization.\n'
            f'- risk_level must be exactly one of: "Directly Exploitable", "Lateral Risk", "Background Threat".\n'
            f'- correlation_summary must be exactly 2 sentences summarizing which CVEs are most dangerous for this org right now.'
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a vulnerability correlation engine. Given a list of live CVEs and an organization's infrastructure, identify which CVEs are most relevant to the active attack scenario. Return only valid JSON."
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        if not content:
            return {
                "relevant_cves": [],
                "correlation_summary": "Correlation engine unavailable. Manual review recommended."
            }

        return json.loads(content)
    except Exception:
        return {
            "relevant_cves": [],
            "correlation_summary": "Correlation engine unavailable. Manual review recommended."
        }

class RiskProfileRequest(BaseModel):
    org_name: str
    industry: str
    cloud_provider: str
    os_stack: str
    key_assets: list[str]
    existing_security_tools: str
    team_size: str
    uses_active_directory: bool = False
    active_directory: dict | None = None
    architecture_description: str = ""

@app.post("/api/risk-profile")
def risk_profile(req: RiskProfileRequest):
    github_token = os.getenv("GITHUB_TOKEN")
    fallback_response = {
        "risk_score": 75,
        "risk_level": "HIGH",
        "top_threats": ["Credential theft via cloud metadata", "Lateral movement through misconfigured IAM", "Insider threat via privileged access"],
        "recommended_scenario": "canary_aws_token",
        "recommendation_reason": "Cloud credential attacks are the most common entry point for your stack.",
        "summary": "Your environment has significant exposure across cloud identity layers. Immediately audit IAM permissions and deploy deception assets on critical credential stores."
    }
    if not github_token:
        return fallback_response

    try:
        client = OpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=github_token,
        )

        ad_info = ""
        if req.uses_active_directory and req.active_directory:
            ad = req.active_directory
            ad_info = f"Active Directory: Domain {ad.get('domain_name', '')}, {ad.get('domain_controller_count', '')} DCs, {ad.get('forest_type', '')}, {ad.get('hybrid_mode', '')}, {ad.get('privileged_account_count', '')} privileged accounts, {ad.get('service_account_count', '')} service accounts, trusts: {ad.get('trust_relationships', '')}, AD tools: {ad.get('ad_security_tools', '')}\n"

        prompt = (
            f"Analyse this organization and return a risk profile JSON:\n"
            f"Org: {req.org_name}, Industry: {req.industry}, Cloud: {req.cloud_provider},\n"
            f"OS Stack: {req.os_stack}, Key Assets: {req.key_assets}, Team Size: {req.team_size},\n"
            f"Security Tools: {req.existing_security_tools}\n"
            f"{ad_info}"
            f"Architecture description: {req.architecture_description}\n\n"
            f"Return exactly this JSON structure:\n"
            f"{{\n"
            f"  'risk_score': integer between 1 and 100,\n"
            f"  'risk_level': one of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW',\n"
            f"  'top_threats': list of exactly 3 strings, each a specific threat relevant to their stack,\n"
            f"  'recommended_scenario': one of exactly 'canary_aws_token', 'honeypot_ssh', 'fake_db_credentials', 'decoy_file' — pick whichever is most relevant to their cloud_provider and industry,\n"
            f"  'recommendation_reason': string, 1 sentence explaining why that scenario fits their stack,\n"
            f"  'summary': string, exactly 2 sentences — first names the biggest risk, second gives one immediate action. Write it addressed to the org by name.\n"
            f"}}"
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are Ghost Protocol, an elite cyber threat intelligence engine. Given an organization's infrastructure profile, generate a concise risk assessment. Return only valid JSON."
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=400,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        if not content:
            return fallback_response
        return json.loads(content)
    except Exception:
        return fallback_response

class SuggestedQuestionsRequest(BaseModel):
    brief_summary: str
    suspected_group: str
    asset_type: str
    existing_security_tools: str
    industry: str

@app.post("/api/suggested-questions")
def suggested_questions(req: SuggestedQuestionsRequest):
    github_token = os.getenv("GITHUB_TOKEN")
    fallback_response = {"questions": ["What lateral movement has occurred?", "Which assets should I isolate first?", "Should I notify my security team now?"]}
    if not github_token:
        return fallback_response

    try:
        client = OpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=github_token,
        )

        prompt = (
            f"A {req.asset_type} deception asset was triggered. Suspected group: {req.suspected_group}.\n"
            f"The analyst works in {req.industry} and uses {req.existing_security_tools}.\n"
            f"Brief summary: {req.brief_summary}\n\n"
            f"Generate exactly 3 short follow-up questions an analyst would ask right now.\n"
            f"Each question must be specific to their tools and industry — not generic.\n"
            f"Return exactly this JSON:\n"
            f"{{\n"
            f"  'questions': [str, str, str]\n"
            f"}}"
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are Ghost Protocol. Generate analyst follow-up questions based on a threat brief. Return only valid JSON."
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.5,
            max_tokens=200,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        if not content:
            return fallback_response
        return json.loads(content)
    except Exception:
        return fallback_response

class IPReputationRequest(BaseModel):
    ip_address: str

@app.post("/api/ip-reputation")
def ip_reputation(req: IPReputationRequest):
    fallback = {
        "ip_address": req.ip_address,
        "abuse_confidence_score": 0,
        "country_code": "XX",
        "country_name": "Unknown",
        "isp": "Unknown ISP",
        "domain": "unknown",
        "usage_type": "Unknown",
        "total_reports": 0,
        "last_reported_at": "Never",
        "is_tor": False,
        "threat_level": "UNKNOWN",
        "error": "Reputation service unavailable"
    }
    
    abuseipdb_key = os.getenv("ABUSEIPDB_KEY")
    if not abuseipdb_key:
        return fallback

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": req.ip_address,
            "maxAgeInDays": 90,
            "verbose": True
        }
        headers = {
            "Key": abuseipdb_key,
            "Accept": "application/json"
        }
        
        response = requests.get(url, params=params, headers=headers, timeout=6.0)
        if response.status_code != 200:
            return fallback

        data = response.json().get("data", {})
        
        last_reported = data.get("lastReportedAt")
        if last_reported:
            last_reported_at = str(last_reported)[:10]
        else:
            last_reported_at = "Never"
            
        abuse_confidence_score = int(data.get("abuseConfidenceScore", 0))
        
        if abuse_confidence_score >= 75:
            threat_level = "CRITICAL"
        elif abuse_confidence_score >= 40:
            threat_level = "HIGH"
        elif abuse_confidence_score >= 10:
            threat_level = "SUSPICIOUS"
        else:
            threat_level = "CLEAN"
            
        return {
            "ip_address": data.get("ipAddress", req.ip_address),
            "abuse_confidence_score": abuse_confidence_score,
            "country_code": data.get("countryCode", "XX"),
            "country_name": data.get("countryName", "Unknown"),
            "isp": data.get("isp", "Unknown ISP"),
            "domain": data.get("domain", "unknown"),
            "usage_type": data.get("usageType", "Unknown"),
            "total_reports": int(data.get("totalReports", 0)),
            "last_reported_at": last_reported_at,
            "is_tor": bool(data.get("isTor", False)),
            "threat_level": threat_level
        }
    except Exception:
        return fallback

class MitreOsintRequest(BaseModel):
    suspected_group: str
    technique_ids: list[str]

@app.post("/api/mitre-osint")
def mitre_osint(req: MitreOsintRequest):
    fallback = {
        "group_name": req.suspected_group,
        "aliases": [],
        "motivation": "Unknown",
        "origin": "Unknown",
        "typical_targets": "Unknown",
        "known_campaigns": "Insufficient data.",
        "why_relevant": "Pattern matches observed TTPs."
    }

    try:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        res = requests.get(url, timeout=10.0)
        if res.status_code != 200:
            raise Exception("CTI fetch failed")
        
        objects = res.json().get("objects", [])
        groups = []
        for obj in objects:
            if obj.get("type") == "intrusion-set":
                groups.append({
                    "name": obj.get("name", ""),
                    "aliases": obj.get("aliases", []),
                    "description": obj.get("description", "")[:300]
                })

        matched_group = None
        search_term = req.suspected_group.lower()
        for g in groups:
            name_match = search_term in g["name"].lower() or g["name"].lower() in search_term
            alias_match = any(search_term in a.lower() or a.lower() in search_term for a in g["aliases"])
            if name_match or alias_match:
                matched_group = g
                break

        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            if matched_group:
                return {
                    "group_name": matched_group["name"],
                    "aliases": matched_group["aliases"],
                    "motivation": "Unknown",
                    "origin": "Unknown",
                    "typical_targets": "Unknown",
                    "known_campaigns": matched_group["description"],
                    "why_relevant": "Pattern matches observed TTPs."
                }
            return fallback

        client = OpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=github_token,
        )

        if matched_group:
            prompt = (
                f"Threat actor: {matched_group['name']}\n"
                f"Known aliases: {matched_group['aliases']}\n"
                f"MITRE description: {matched_group['description']}\n"
                f"Observed techniques in this incident: {req.technique_ids}\n\n"
                f"Return exactly this JSON:\n"
                f"{{\n"
                f"  'group_name': str,\n"
                f"  'aliases': list of str,\n"
                f"  'motivation': str (one of: Financial, Espionage, Hacktivism, Destruction, Unknown),\n"
                f"  'origin': str (suspected nation-state or origin, or Unknown),\n"
                f"  'typical_targets': str (1 sentence),\n"
                f"  'known_campaigns': str (1-2 sentences from the description, summarised),\n"
                f"  'why_relevant': str (1 sentence explaining why this group matches the observed techniques)\n"
                f"}}"
            )
        else:
            prompt = (
                f"Threat actor: {req.suspected_group}\n"
                f"Observed techniques in this incident: {req.technique_ids}\n\n"
                f"Return exactly this JSON:\n"
                f"{{\n"
                f"  'group_name': str,\n"
                f"  'aliases': list of str,\n"
                f"  'motivation': str (one of: Financial, Espionage, Hacktivism, Destruction, Unknown),\n"
                f"  'origin': str (suspected nation-state or origin, or Unknown),\n"
                f"  'typical_targets': str (1 sentence),\n"
                f"  'known_campaigns': str (1-2 sentences from the description, summarised),\n"
                f"  'why_relevant': str (1 sentence explaining why this group matches the observed techniques)\n"
                f"}}"
            )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a threat intelligence analyst. Given a threat actor group profile and their known MITRE techniques, provide a concise intel summary. Return only valid JSON."
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=350,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        if not content:
            return fallback
        return json.loads(content)
    except Exception:
        return fallback

class TimelineRequest(BaseModel):
    asset_type: str
    technique_ids: list[str]
    compromised_asset: str
    predicted_next_target: str
    lateral_path: list[str]
    org_name: str
    cloud_provider: str

@app.post("/api/attack-timeline")
def attack_timeline(req: TimelineRequest):
    fallback = {
        "timeline": [],
        "total_dwell_time": "Unknown",
        "exfiltration_window": "Unknown"
    }

    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        return fallback

    try:
        client = OpenAI(
            base_url="https://models.inference.ai.azure.com",
            api_key=github_token,
        )

        prompt = (
            f"Reconstruct the attack timeline for this incident:\n"
            f"Asset triggered: {req.asset_type}\n"
            f"Compromised asset: {req.compromised_asset}\n"
            f"Predicted next target: {req.predicted_next_target}\n"
            f"Lateral movement path: {req.lateral_path}\n"
            f"MITRE techniques: {req.technique_ids}\n"
            f"Target org: {req.org_name} on {req.cloud_provider}\n\n"
            f"Return exactly this JSON:\n"
            f"{{\n"
            f"  'timeline': [\n"
            f"    {{\n"
            f"      'offset': str (e.g. 'T+0s', 'T+30s', 'T+2m', 'T+15m', 'T+1h'),\n"
            f"      'event': str (what the attacker did, specific and technical),\n"
            f"      'phase': str (one of: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration),\n"
            f"      'severity': str (one of: low, medium, high, critical),\n"
            f"      'mitre_technique': str (technique ID if applicable, else null)\n"
            f"    }}\n"
            f"  ],\n"
            f"  'total_dwell_time': str (estimated total attack window e.g. '2-4 hours'),\n"
            f"  'exfiltration_window': str (when data exfiltration likely begins e.g. 'T+45m')\n"
            f"}}\n"
            f"Generate exactly 8 timeline events. Make them specific to the asset_type and cloud_provider."
        )

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a cyber attack timeline reconstruction engine. Given attack details, generate a realistic second-by-second to minute-by-minute timeline of the attack as it unfolds. Return only valid JSON."
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=800,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content
        if not content:
            return fallback
        return json.loads(content)
    except Exception:
        return fallback

class HistoryEntryRequest(BaseModel):
    event_id: str
    asset_type: str
    display_name: str
    org_name: str
    suspected_group: str
    confidence_score: float
    compromised_asset: str
    predicted_next_target: str
    risk_level: str
    summary: str

@app.post("/api/history/save")
def save_history(req: HistoryEntryRequest):
    entry = {
        "event_id": req.event_id,
        "asset_type": req.asset_type,
        "display_name": req.display_name,
        "org_name": req.org_name,
        "suspected_group": req.suspected_group,
        "confidence_score": req.confidence_score,
        "compromised_asset": req.compromised_asset,
        "predicted_next_target": req.predicted_next_target,
        "risk_level": req.risk_level,
        "summary": req.summary,
        "saved_at": datetime.now(timezone.utc).isoformat(),
        "id": f"hist_{req.event_id[:8]}"
    }
    return entry

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
