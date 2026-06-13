THREAT_PROFILES = {
    "canary_aws_token": {
        "attacker_profile": {
            "suspected_group": "APT29",
            "confidence_score": 0.85,
            "ttps": [
                {
                    "technique_id": "T1552.005",
                    "technique_name": "Unsecured Credentials: Cloud Credentials",
                    "tactic": "Credential Access",
                    "confidence": 0.95
                },
                {
                    "technique_id": "T1078.004",
                    "technique_name": "Valid Accounts: Cloud Accounts",
                    "tactic": "Defense Evasion",
                    "confidence": 0.92
                }
            ]
        },
        "blast_radius": {
            "compromised_asset": "Canary AWS Credentials Token",
            "predicted_next_target": "Production IAM Console",
            "lateral_path": [
                "AWS EC2 Bastion Host",
                "S3 Bucket Backup Access",
                "Production IAM Role Policy"
            ],
            "assets_at_risk": [
                "Enterprise User Database",
                "Payment Processing API Gateway"
            ]
        },
        "recommended_actions": [
            {
                "priority": 1,
                "action": "Revoke the leaked AWS access key credentials immediately.",
                "urgency": "Immediate"
            },
            {
                "priority": 2,
                "action": "Audit CloudTrail logs for unauthorized API activity using the token.",
                "urgency": "Within 1 hour"
            },
            {
                "priority": 3,
                "action": "Rotate all IAM roles and access keys associated with the affected accounts.",
                "urgency": "Within 24 hours"
            }
        ]
    },
    "honeypot_ssh": {
        "attacker_profile": {
            "suspected_group": "APT41",
            "confidence_score": 0.78,
            "ttps": [
                {
                    "technique_id": "T1110.001",
                    "technique_name": "Brute Force: Password Guessing",
                    "tactic": "Credential Access",
                    "confidence": 0.88
                },
                {
                    "technique_id": "T1021.004",
                    "technique_name": "Remote Services: SSH",
                    "tactic": "Lateral Movement",
                    "confidence": 0.90
                }
            ]
        },
        "blast_radius": {
            "compromised_asset": "Public-Facing SSH Honeypot Server",
            "predicted_next_target": "Active Directory Domain Controller",
            "lateral_path": [
                "Internal DMZ Jumpbox",
                "Corp VPN Concentrator",
                "Domain Controller Primary Active Directory"
            ],
            "assets_at_risk": [
                "Employee HR Records DB",
                "Internal Jenkins Build Server"
            ]
        },
        "recommended_actions": [
            {
                "priority": 1,
                "action": "Block the originating IP address at the perimeter firewall.",
                "urgency": "Immediate"
            },
            {
                "priority": 2,
                "action": "Verify if the SSH key used for the brute-force exists on other hosts.",
                "urgency": "Within 1 hour"
            },
            {
                "priority": 3,
                "action": "Enforce multi-factor authentication for all remote administrative sessions.",
                "urgency": "Within 24 hours"
            }
        ]
    },
    "fake_db_credentials": {
        "attacker_profile": {
            "suspected_group": "FIN7",
            "confidence_score": 0.89,
            "ttps": [
                {
                    "technique_id": "T1213",
                    "technique_name": "Data from Information Repositories",
                    "tactic": "Collection",
                    "confidence": 0.85
                },
                {
                    "technique_id": "T1555",
                    "technique_name": "Credentials from Password Stores",
                    "tactic": "Credential Access",
                    "confidence": 0.89
                }
            ]
        },
        "blast_radius": {
            "compromised_asset": "Staging Database Credentials File",
            "predicted_next_target": "Production Database Instance",
            "lateral_path": [
                "Developer Workstation",
                "Staging Application Server",
                "Production RDS DB Cluster"
            ],
            "assets_at_risk": [
                "Customer Account Data Store",
                "Financial Ledger LedgerDB"
            ]
        },
        "recommended_actions": [
            {
                "priority": 1,
                "action": "Rotate database passwords and update all secrets manager configuration.",
                "urgency": "Immediate"
            },
            {
                "priority": 2,
                "action": "Terminate active sessions linked to the leaked db credentials.",
                "urgency": "Within 1 hour"
            },
            {
                "priority": 3,
                "action": "Implement database access control policies restricting connections to TLS only.",
                "urgency": "Within 24 hours"
            }
        ]
    },
    "decoy_file": {
        "attacker_profile": {
            "suspected_group": "Lazarus Group",
            "confidence_score": 0.72,
            "ttps": [
                {
                    "technique_id": "T1083",
                    "technique_name": "File and Directory Discovery",
                    "tactic": "Discovery",
                    "confidence": 0.82
                },
                {
                    "technique_id": "T1005",
                    "technique_name": "Data from Local System",
                    "tactic": "Collection",
                    "confidence": 0.87
                }
            ]
        },
        "blast_radius": {
            "compromised_asset": "HR Decoy Payroll Spreadsheet",
            "predicted_next_target": "Corporate File Server",
            "lateral_path": [
                "Local Endpoint Machine",
                "Department Shared Drive",
                "Corporate NAS File Server"
            ],
            "assets_at_risk": [
                "Confidential M&A Documents",
                "Executive Email Server Archive"
            ]
        },
        "recommended_actions": [
            {
                "priority": 1,
                "action": "Isolate the compromised endpoint machine from the local network.",
                "urgency": "Immediate"
            },
            {
                "priority": 2,
                "action": "Initiate full-system security scans on all neighboring endpoints.",
                "urgency": "Within 1 hour"
            },
            {
                "priority": 3,
                "action": "Review host logs to trace any data exfiltration attempts.",
                "urgency": "Within 24 hours"
            }
        ]
    }
}
