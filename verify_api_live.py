import requests
import json

BASE_URL = "http://127.0.0.1:8000"

print("1. Testing GET /health...")
res = requests.get(f"{BASE_URL}/health")
print(res.status_code, res.json())
assert res.status_code == 200
assert res.json()["status"] == "ok"

print("\n2. Testing GET /api/scenarios...")
res = requests.get(f"{BASE_URL}/api/scenarios")
print(res.status_code)
scenarios = res.json()
print(f"Retrieved {len(scenarios)} scenarios:")
for s in scenarios:
    print(f" - {s['display_name']} ({s['asset_type']}) - {s['threat_level']}")
assert res.status_code == 200
assert len(scenarios) > 0

print("\n3. Testing GET /api/threat-feed...")
res = requests.get(f"{BASE_URL}/api/threat-feed")
print(res.status_code)
feed = res.json()
print(f"Total Critical CVEs: {feed.get('total_critical')}")
print(f"Sample CVE: {feed.get('cves')[0] if feed.get('cves') else 'None'}")
assert res.status_code == 200
assert "cves" in feed

mock_env = {
    "org_name": "Apex Finance",
    "cloud_provider": "AWS",
    "key_assets": ["Apex RDS Primary", "S3 Customer Docs", "EC2 AutoScale Group"],
    "os_stack": "Ubuntu 22.04 LTS",
    "team_size": "11-50",
    "industry": "Financial Services",
    "existing_security_tools": "CrowdStrike Falcon, Splunk Cloud",
    "uses_active_directory": True,
    "active_directory": {
        "domain_name": "apex.corp",
        "domain_controller_count": "2",
        "forest_type": "Single Forest",
        "hybrid_mode": "Hybrid (AD + Entra ID)",
        "privileged_account_count": "4",
        "service_account_count": "10",
        "trust_relationships": "one-way trust with partner.local",
        "ad_security_tools": "Microsoft Defender for Identity"
    },
    "architecture_description": "Our environment consists of a secure DMZ, separate production VPCs in AWS connected via Transit Gateway, and an on-premise Active Directory domain synced with Entra ID."
}

print("\n4. Testing POST /api/analyze...")
analyze_payload = {
    "asset_type": "canary_aws_token",
    "source_ip": "198.51.100.42",
    "user_environment": mock_env
}
res = requests.post(f"{BASE_URL}/api/analyze", json=analyze_payload)
print(res.status_code)
if res.status_code != 200:
    print("Error response:", res.text)
assert res.status_code == 200
brief = res.json()
print("Brief Event ID:", brief.get("event_id"))
print("Suspected Group:", brief.get("attacker_profile", {}).get("suspected_group"))
print("Blast Radius lateral path:", brief.get("blast_radius", {}).get("lateral_path"))
print("Recommended actions:", [a.get("action") for a in brief.get("recommended_actions", [])])
assert brief.get("asset_type") == "canary_aws_token"
assert len(brief.get("blast_radius", {}).get("lateral_path", [])) == 3
assert len(brief.get("recommended_actions", [])) == 3

print("\n5. Testing POST /api/correlate-cves...")
correlate_payload = {
    "cves": feed.get("cves", []),
    "asset_type": "canary_aws_token",
    "user_environment": mock_env
}
res = requests.post(f"{BASE_URL}/api/correlate-cves", json=correlate_payload)
print(res.status_code)
if res.status_code != 200:
    print("Error response:", res.text)
assert res.status_code == 200
corr = res.json()
print("Correlation summary:", corr.get("correlation_summary"))
print("Relevant CVEs count:", len(corr.get("relevant_cves", [])))
assert "relevant_cves" in corr

print("\n6. Testing POST /api/chat...")
chat_payload = {
    "brief_context": json.dumps({"brief": brief, "environment": mock_env}),
    "messages": [
        {"role": "user", "content": "Tell me more about the threat actor's identity."}
    ],
    "new_message": "What is their typical motivation?"
}
res = requests.post(f"{BASE_URL}/api/chat", json=chat_payload)
print(res.status_code)
if res.status_code != 200:
    print("Error response:", res.text)
assert res.status_code == 200
chat_res = res.json()
print("Chat Reply:", chat_res.get("reply"))
assert "reply" in chat_res

print("\n7. Testing POST /api/risk-profile...")
risk_payload = {
    "org_name": "Apex Finance",
    "industry": "Financial Services",
    "cloud_provider": "AWS",
    "os_stack": "Ubuntu 22.04 LTS",
    "key_assets": ["Apex RDS Primary", "S3 Customer Docs", "EC2 AutoScale Group"],
    "existing_security_tools": "CrowdStrike Falcon, Splunk Cloud",
    "team_size": "11-50",
    "uses_active_directory": True,
    "active_directory": {
        "domain_name": "apex.corp",
        "domain_controller_count": "2",
        "forest_type": "Single Forest",
        "hybrid_mode": "Hybrid (AD + Entra ID)",
        "privileged_account_count": "4",
        "service_account_count": "10",
        "trust_relationships": "one-way trust with partner.local",
        "ad_security_tools": "Microsoft Defender for Identity"
    },
    "architecture_description": "Our environment consists of a secure DMZ, separate production VPCs in AWS connected via Transit Gateway, and an on-premise Active Directory domain synced with Entra ID."
}
res = requests.post(f"{BASE_URL}/api/risk-profile", json=risk_payload)
print(res.status_code)
if res.status_code != 200:
    print("Error response:", res.text)
assert res.status_code == 200
risk_data = res.json()
print("Risk Score:", risk_data.get("risk_score"))
print("Risk Level:", risk_data.get("risk_level"))
print("Top Threats:", risk_data.get("top_threats"))
print("Recommended Scenario:", risk_data.get("recommended_scenario"))
assert "risk_score" in risk_data
assert "risk_level" in risk_data

print("\n8. Testing POST /api/suggested-questions...")
questions_payload = {
    "brief_summary": "AWS Deception Token was triggered. Potential AWS IAM role compromise.",
    "suspected_group": "Lazarus Group",
    "asset_type": "canary_aws_token",
    "existing_security_tools": "CrowdStrike Falcon, Splunk Cloud",
    "industry": "Financial Services"
}
res = requests.post(f"{BASE_URL}/api/suggested-questions", json=questions_payload)
print(res.status_code)
if res.status_code != 200:
    print("Error response:", res.text)
assert res.status_code == 200
questions_data = res.json()
print("Suggested Questions:", questions_data.get("questions"))
assert "questions" in questions_data
assert len(questions_data.get("questions", [])) == 3

print("\nALL LIVE API VERIFICATION TESTS PASSED SUCCESSFULLY!")
