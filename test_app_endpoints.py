from app import health, get_scenarios, analyze, AnalyzeRequest, correlate_cves, CorrelateRequest

health_res = health()
print("Health:", health_res)
assert health_res["status"] == "ok"

scenarios_res = get_scenarios()
print("Scenarios count:", len(scenarios_res))
assert len(scenarios_res) == 4

mock_env = {
    "org_name": "Acme Corp",
    "cloud_provider": "AWS",
    "key_assets": ["Production RDS", "S3 Data Lake", "EC2 Fleet"],
    "os_stack": "Ubuntu 22.04",
    "team_size": "50",
    "industry": "Finance",
    "existing_security_tools": "Splunk, CrowdStrike"
}

req1 = AnalyzeRequest(
    asset_type="honeypot_ssh",
    source_ip="192.168.1.100",
    user_environment=mock_env
)
brief1 = analyze(req1)
print("Analyze honeypot_ssh event_id:", brief1.event_id)
print("Analyze honeypot_ssh summary:", brief1.summary)
assert brief1.asset_type == "honeypot_ssh"
assert len(brief1.blast_radius.lateral_path) == 3
assert len(brief1.recommended_actions) == 3

req2 = AnalyzeRequest(
    asset_type="non_existent",
    source_ip="10.0.0.5",
    user_environment=mock_env
)
brief2 = analyze(req2)
print("Analyze non_existent fallback asset_type:", brief2.asset_type)
assert brief2.asset_type == "non_existent"

cves_to_test = [
    {
        "cve_id": "CVE-2026-0001",
        "description": "Critical remote code execution in OpenSSL affecting TLS handshake",
        "cvss_score": 9.8
    },
    {
        "cve_id": "CVE-2026-0002",
        "description": "Privilege escalation via kernel memory corruption in Linux",
        "cvss_score": 9.6
    }
]

corr_req = CorrelateRequest(
    cves=cves_to_test,
    asset_type="honeypot_ssh",
    user_environment=mock_env
)
corr_res = correlate_cves(corr_req)
print("Correlation summary:", corr_res.get("correlation_summary"))
assert "relevant_cves" in corr_res
assert "correlation_summary" in corr_res

print("All tests passed successfully!")
