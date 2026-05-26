# CITADEL-Y LIGHT GUARD - HYBRID ML SECURITY DOCUMENTATION

This document outlines the **Red Team (Offensive Hacking)** and **Blue Team (Defensive Control)** security playbooks, system architecture, hybrid ML pipeline design, and integration telemetry logs for **CITADEL-Y LIGHT GUARD**.

---

## 🏗️ 1. HYBRID ML SYSTEM ARCHITECTURE & PIPELINE

CITADEL-Y is an advanced hybrid LLM security pipeline featuring 5 distinct defense layers (Input Guard → LLM Judge → Secure RAG → LLM Principal → Output Guard DLP) integrating Machine Learning classifiers and semantic embedding distance calculations.

```
             User Credentials (user_id + chat_id)
                           │
                           ▼
                 ┌───────────────────┐
                 │    INPUT GUARD    │ ──► Primary SetFit Classifier (confidence 0.0 - 1.0)
                 └───────────────────┘     └─ Dead Zone [0.40 - 0.60] fallbacks to Regex Backup Scorer
                           │
             ┌─────────────┴─────────────┐ Risk Score >= 0.35 (FLAG_MEDIUM / FLAG_HIGH)
             ▼                           ▼
  ┌───────────────────────┐   ┌───────────────────────┐
  │   LLM JUDGE INTENT    │   │   SECURE RAG ENGINE   │
  └───────────────────────┘   └───────────────────────┘
             │                            │
      [UNSAFE] ──► 🚫 REFUSAL             ├──► Scopes document retrieval to
             (FLAG_MEDIUM triggers        │    SYSTEM globals or OWNER matches.
             Judge and blocks intent)     ├──► Enforces RAG BLACKOUT on High Risk / Blocked intent.
                                          ▼
                              ┌───────────────────────┐
                              │  MEMORY GUARD SHIELD  │ ──► Cleans historical chat logs
                              └───────────────────────┘     to block memory hijacking
                                          │
                                          ▼
                              ┌───────────────────────┐
                              │     LLM PRINCIPAL     │
                              └───────────────────────┘
                                          │
                                          ▼
                              ┌───────────────────────┐
                              │  OUTPUT GUARD (DLP)   │ ──► High-speed Regex matching +
                              └───────────────────────┘     Semantic Embedding DLP (all-MiniLM-L6-v2)
                                          │                 └─ Cosine Similarity > 0.80 exact redaction
                                          ▼
                                    Clean Response
```

---

## 🏰 2. THE DOUBLE WORKSPACE ENVIRONMENT

CITADEL-Y deploys **two distinct portals** in your stack, mimicking a production-ready enterprise security setup:

### 🔵 PORTAL A: Blue Team Dashboard & Chat (Port 8501)
- **Chat Arena**: Chat sandbox scoped to selected user identities (`team_alpha`, `team_beta`, `guest_user`). 
- **Prometheus Telemetry Panel**: Aggregates real-time Prometheus scrapings tracking overall latencies, costs, blocked requests, sanitization frequencies, SetFit confidence levels, and embedding distances.
- **Document Safe**: Scoped vector store browser highlighting original vs. sanitized at-rest document contents.

### 🔴 PORTAL B: Red Team Pentest & CTF Playground (Port 8502)
- **Capture The Flag (CTF) Challenges**: Three explicit targets to exploit:
  1. *Flag 1: Vault Exfiltration* (extract `PHOENIX-99-743X`).
  2. *Flag 2: Prompt Jailbreak* (override directives to print `SYSTEM_EXPLOITED`).
  3. *Flag 3: Database Fingerprint* (leak the `postgresql://...` URL).
- **Hacking Terminal Console**: Input raw payloads and inspect granular reaction logs of CITADEL-Y's inner layers (Input Guard risk index, LLM Judge verdict, Scoped RAG docs, Output DLP actions).
- **Vulnerability Findings Ledger**: Allows attackers to log successful findings and exploits directly into the shared secure SQLite audit table.

---

## 🔒 3. INTER-SESSION ISOLATION & HYBRID ML MATRIX

| Threat Category | Red Team Attack Vector | Blue Team Defense Mechanism | Verification Audit Log / Metric |
|---|---|---|---|
| **Direct Prompt Injection** | Bypass traditional regex matches by obfuscating commands or jailbreaking. | **Input Guard (SetFit Classifier)**: Primary binarized malicious/safe few-shot sentence transformer (`paraphrase-MiniLM-L6-v2`). Confidence maps to risk score. Includes **Dead Zone `[0.40–0.60]`** fallback to Regex Scorer. | `SetFit Classifier assessed risk at 0.76` / `citadel_ml_input_guard_confidence` |
| **Indirect Injection via Memory** | User inserts a malicious directive (ex. *"Ignore future instructions"*) in Turn 1, attempting to hijack the model in Turn 2 when history is recalled. | **Memory Guard**: Scans SQLite message logs. Any prompt with a high risk score or unsafe status is censored to `[MEMORY SHIELD: payload sanitized]` prior to feeding history back to the LLM. | ` -> [Memory Guard] Cleaned history log (Risk >= 0.70)` |
| **Data Loss Prevention (DLP)** | Attacker requests postgres databases, private tokens, or hardware bypass keys using paraphrasing or synonyms to evade regex. | **Semantic Embedding DLP**: Computes cosine similarity of assistant sentences against a cached startup database of secrets (each secret caches a raw and metadata/description embedding using `all-MiniLM-L6-v2`). Rejects and redacts exactly matching text fragments on **similarity > 0.80**. | `Auto-redacted semantic match (similarity: 0.86): PHOENIX_SECRET` / `citadel_ml_dlp_similarity_scores` |
| **RAG Ingestion Poisoning** | Malicious script indexed into files to force instruction overrides during retrieval. | **Pre-Ingestion Sanitizer**: Filters documents *before* they are committed to the SQLite vector table, stripping command terms like `ignore previous`. | ` -> [Ingestion Sanitizer] Rewrote RAG document target: 'Ignore previous' -> '[INJECTION_ATTEMPT_REMOVED]'` |

---

## 📈 4. PROMETHEUS SOC TELEMETRY REGISTER

All operations are instrumented using Prometheus metrics on port `8000` to allow the Security Operations Center (SOC) to monitor pipeline security in real-time:

### Standard Pipeline Metrics
* `citadel_requests_total`: Tracks total processed requests (labeled as `allowed`, `blocked`, or `sanitized`).
* `citadel_attacks_total`: Tracks intercepted threats (labeled by guard component and attack category).
* `citadel_latency_seconds`: Measures individual processing latencies for components:
  * `pipeline`, `input_guard`, `judge`, `rag`, `principal_llm`, `output_guard`
  * **`ml_input_guard`** (SetFit classifier prediction CPU latency)
  * **`ml_dlp_guard`** (all-MiniLM cosine similarity comparison CPU latency)
* `citadel_llm_calls_total`: Tracks total API requests made to external models (labeled by `judge` or `principal`).
* `citadel_estimated_cost_usd`: Tracks OpenRouter API inference spending.
* `citadel_current_threat_risk`: Gauge tracking the threat risk computed for the latest processed query.

### ML-Specific SOC Telemetry
* `citadel_ml_input_guard_confidence`: Gauge tracking the raw confidence score computed by the SetFit model for the latest incoming query.
* `citadel_ml_input_guard_fallbacks_total`: Counter tracking the number of times Input Guard had to fall back to the rule-based regex engine (labeled by `dead_zone` or `model_absent` reason).
* `citadel_ml_dlp_similarity_scores`: Histogram tracking the exact cosine similarity scores of candidate leaked response blocks against secret embeddings.
* `citadel_ml_dlp_redactions_total`: Counter tracking total semantic DLP redactions performed (labeled by matched `secret_category` e.g. `PHOENIX_SECRET`, `API_KEY`, `DATABASE_URL`).

### Advanced Layer & Red Team Observability Metrics [NEW]
* `citadel_input_guard_decisions_total`: Counter tracking decisions made by Input Guard (labeled by `decision` e.g. `ALLOW`, `FLAG_MEDIUM`, `FLAG_HIGH`).
* `citadel_judge_verdicts_total`: Counter tracking verdicts returned by LLM Judge (labeled by `unsafe` e.g. `true`, `false`).
* `citadel_rag_policy_applied_total`: Counter tracking dynamic RAG security policies applied to context queries (labeled by `policy` name and `user_role` e.g., `RAG_BLACKOUT`, `admin`).
* `citadel_rag_documents_retrieved_total`: Counter tracking scoped documents retrieved during RAG vector search (labeled by `document_title` and `classification` e.g. `public`, `internal`, `restricted`).
* `citadel_dlp_scans_total`: Counter tracking total scans processed by Output Guard DLP (labeled by `leak_detected` and `rule_type` e.g. `regex`, `semantic`, `instruction`).
* `citadel_redteam_attacks_total`: Counter tracking prompt injection attacks launched by hackers (labeled by `attacker`, `category`, `status` e.g. `Blocked`, `Sanitized`, `Allowed`).
* `citadel_redteam_flags_submitted_total`: Counter tracking CTF flags submitted to the Red Team scoreboard (labeled by `attacker`, `flag_name`, `status` e.g. `correct`, `incorrect`).

---

## 🚀 5. RUNNING THE STACK

Deploy using **Docker Compose**:
```bash
docker-compose up --build -d
```
Access points:
- **🔵 Blue Team Dashboard**: `http://localhost:8501`
- **🔴 Red Team Pentest CTF**: `http://localhost:8502`
- **💻 Local REST API**: `http://localhost:8080` (endpoints `/api/analyze` and `/api/health`)
- **Prometheus Scraper UI**: `http://localhost:9090`
- **Raw Telemetry Metrics**: `http://localhost:8000/metrics` (or `http://localhost:8000`)
