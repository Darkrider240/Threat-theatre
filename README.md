# Ghost Protocol - Threat Theatre

A clinical, modern cyber deception and threat simulation environment designed for Security Operations Center (SOC) analysts to model, analyze, and enrich network breach alerts. Built using React 18, Tailwind CSS, FastAPI, and Azure AI-powered OpenAI orchestration models.

---

## 1. System Architecture & Data Flow

The architecture decouples the frontend clinical interface (pure client-side React via CDN) from the intelligence enrichment layer (FastAPI backend). All persistent data stays client-side in the browser's `localStorage`, utilizing API endpoints for real-time validation, intelligence enrichment, and structuring.

```mermaid
graph TD
    subgraph Frontend [Client Browser - React & Tailwind]
        OB[onboarding.html - Setup Stack & AD]
        DB[index.html - Dashboard & Threat History]
        WR[theatre.html - War Room & Copilot Chat]
    end

    subgraph Backend [FastAPI Server - app.py]
        API_Risk[/api/risk-profile]
        API_Scen[/api/scenarios]
        API_NVD[/api/threat-feed]
        API_IP[/api/ip-reputation]
        API_MITRE[/api/mitre-osint]
        API_Time[/api/attack-timeline]
        API_Save[/api/history/save]
        API_AI[/api/analyze & /api/chat]
    end

    subgraph Intelligence [Enrichment & AI Services]
        Azure_AI[Azure AI Inference - GPT-4o-mini]
        AbuseIPDB[AbuseIPDB API]
        MITRE_CTI[MITRE CTI Catalog]
        NVD_API[NVD CVE Feed API]
    end

    OB -->|1. Post Stack Configuration| API_Risk
    API_Risk -->|Compute Profile| Azure_AI
    DB -->|2. Get Scenario List & CVEs| API_Scen & API_NVD
    DB -->|3. Route to Scenario| WR
    WR -->|4. Attack Analysis & TTPs| API_AI
    API_AI -->|Generate Actor & Blast Radius| Azure_AI
    WR -->|5. Run Parallel Enrichment| API_IP & API_MITRE & API_Time
    API_IP -->|Query IP Reputation| AbuseIPDB
    API_MITRE -->|Cross-reference Groups| MITRE_CTI
    API_Time -->|Construct Event Chain| Azure_AI
    WR -->|6. Save Event| API_Save
    API_Save -->|Format & Stamp| DB
```

---

## 2. Key Features

* **Advanced Risk Profiling**: Models organization stacks, including cloud infrastructure, Active Directory domain structures (DCs, trust relationships, accounts), and custom text architectures.
* **Intelligent Scenario Matching**: Recommends deception honeypot assets tailored precisely to the organization's existing tech stack.
* **Parallel Intelligence Enrichment**:
  * **IP Reputation**: Queries AbuseIPDB for real-world malicious score, country, and ISP info.
  * **MITRE Group OSINT**: Dynamically pulls threat group aliases, origin, and motivations from the official MITRE ATT&CK database.
  * **Attack Timeline Simulation**: Reconstructs a detailed second-by-second to minute-by-minute timeline showing initial access, lateral movement, and exfiltration phases.
* **Dual-Tab Intelligence Panel**: Integrates live NVD CVE feeds next to local incident history.
* **Analyst Copilot**: Interactive SOC chatbot suggesting contextual questions and accepting follow-up commands to drill down on the mitigation plan.

---

## 3. Project Directory Structure

```text
├── app.py                # FastAPI Application (Endpoints & Schemas)
├── models.py             # Pydantic schemas for Azure AI structured outputs
├── onboarding.html       # Setup wizard (AD configuration & architecture overview)
├── index.html            # Main Operations Dashboard & Incident History
├── theatre.html          # War Room simulation timeline & Chat Interface
├── verify_api_live.py    # Integration test suite validating all 12 test cases
├── .env                  # Local API Keys and environment settings
└── README.md             # Project documentation
```

---

## 4. Installation & Local Setup

### Prerequisites
Make sure you have **Python 3.10+** installed.

### 1. Install Dependencies
Install all required libraries from the terminal:
```bash
pip install fastapi uvicorn pydantic requests openai python-dotenv
```

### 2. Configure Environment Variables
Create a `.env` file in the root project directory:
```env
# Required for AI Analysis, Timelines, and Risk Profiles
GITHUB_TOKEN=your_github_model_inference_token_here

# Optional: Required for live IP checking (fallback schema applied if empty)
ABUSEIPDB_KEY=your_abuseipdb_api_key_here
```

### 3. Run the Backend Server
Start the Uvicorn local server:
```bash
python app.py
```
*The server starts listening on `http://127.0.0.1:8000`.*

### 4. Run the Client Frontend
Double-click or open [onboarding.html](onboarding.html) in your browser. The React application is origin-agnostic and will interact with the local server automatically.

---

## 5. Developer API Documentation

| Endpoint | Method | Payload | Description |
| :--- | :--- | :--- | :--- |
| `/health` | `GET` | None | Returns backend status and health. |
| `/api/scenarios` | `GET` | None | Lists all available deception honeypot scenarios. |
| `/api/threat-feed` | `GET` | None | Fetches live critical severity CVEs from the NVD API. |
| `/api/risk-profile` | `POST` | `RiskProfileRequest` | Computes security scores and selects recommended honeypots. |
| `/api/analyze` | `POST` | `AnalyzeRequest` | Processes the honeypot trigger event and generates blast radius. |
| `/api/correlate-cves` | `POST` | `CorrelateCVEsRequest` | Correlates NVD vulnerabilities against the user's OS stack. |
| `/api/suggested-questions`| `POST` | `SuggestedQuestionsRequest` | Generates 3 contextual SOC questions for the analyst. |
| `/api/ip-reputation` | `POST` | `IPReputationRequest` | Resolves IP reputation score and geolocation data. |
| `/api/mitre-osint` | `POST` | `MitreOsintRequest` | Resolves threat actor motivations from MITRE databases. |
| `/api/attack-timeline` | `POST` | `TimelineRequest` | Reconstructs step-by-step attacker timeline events. |
| `/api/history/save` | `POST` | `HistoryEntryRequest` | Validates, stamps, and structures threat history entries. |
