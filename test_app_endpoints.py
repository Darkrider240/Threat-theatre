from app import health, get_scenarios, analyze, AnalyzeRequest

health_res = health()
print("Health:", health_res)
assert health_res["status"] == "ok"

scenarios_res = get_scenarios()
print("Scenarios count:", len(scenarios_res))
assert len(scenarios_res) == 4

req1 = AnalyzeRequest(asset_type="honeypot_ssh", source_ip="192.168.1.100")
brief1 = analyze(req1)
print("Analyze honeypot_ssh event_id:", brief1.event_id)
print("Analyze honeypot_ssh summary:", brief1.summary)
assert brief1.asset_type == "honeypot_ssh"
assert len(brief1.blast_radius.lateral_path) == 3
assert len(brief1.recommended_actions) == 3

req2 = AnalyzeRequest(asset_type="non_existent", source_ip="10.0.0.5")
brief2 = analyze(req2)
print("Analyze non_existent fallback asset_type:", brief2.asset_type)
assert brief2.asset_type == "canary_aws_token"

print("All tests passed successfully!")
