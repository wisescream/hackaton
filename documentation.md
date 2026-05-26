# CITADEL-Y LIGHT GUARD - SECURITY DOCUMENTATION

This document outlines the **Red Team (Offensive)** and **Blue Team (Defensive)** security architectures, isolation matrices, and telemetry logs for **CITADEL-Y LIGHT GUARD**.

---

## 🏗️ 1. SYSTEM ARCHITECTURE & ISOLATION PIPELINE

CITADEL-Y acts as an intelligent security gateway, enforcing strict **Multi-User Isolation**, **Conversation Session Scoping**, and **Zero Cross-Chat Leakage**.

```
             User Credentials (user_id + chat_id)
                           │
                           ▼
                 ┌───────────────────┐
                 │    INPUT GUARD    │ ──► Heuristic threat scorer (0.0 to 1.0)
                 └───────────────────┘
                           │
             ┌─────────────┴─────────────┐ Risk Score >= 0.70
             ▼                           ▼
  ┌───────────────────────┐   ┌───────────────────────┐
  │   LLM JUDGE INTENT    │   │   SECURE RAG ENGINE   │
  └───────────────────────┘   └───────────────────────┘
             │                            │
      [UNSAFE] ──► 🚫 REFUSAL             ├──► Scopes document retrieval to
                                          │    SYSTEM globals or OWNER matches
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
                              │  OUTPUT GUARD (DLP)   │ ──► Intercepts & censors secrets
                              └───────────────────────┘     (e.g., PHOENIX keys, postgres URLs)
                                          │
                                          ▼
                                    Clean Response
```

---

## 🔒 2. INTER-SESSION ISOLATION MATRIX

| Threat Category | Red Team Attack Vector | Blue Team Defense Mechanism | Verification Audit Log |
|---|---|---|---|
| **Cross-User Data Leakage** | **User B (`team_beta`)** queries memory or documents owned by **User A (`team_alpha`)** to extract secrets. | RAG retrieval queries are scoped strictly: `WHERE user_id = 'SYSTEM' OR user_id = current_user_id`. Chat history fetches are locked by active `user_id` and `chat_id` session states. | `🚫 ACCESS DENIED: Cross-user memory access blocked. Boundary violation logged.` |
| **Indirect Injection via Memory** | User inserts a malicious directive (ex. *"Ignore future instructions"*) in Turn 1, attempting to hijack the model in Turn 2 when history is recalled. | **Memory Guard** scans the SQLite message logs. Any prompt with a high risk score or unsafe status is censored to `[MEMORY SHIELD: payload sanitized]` prior to prompt injection. | ` -> [Memory Guard] Cleaned 1 message from Turn 1 history log (Risk >= 0.70)` |
| **Data Loss Prevention (DLP)** | Attacker requests postgres databases, private tokens, or hardware bypass keys (`PHOENIX-XX-XXX`). | **Output Guard** runs context-insensitive regular expressions on raw generation output, redacting secrets and outputting audit steps. | ` -> [Output Guard] Auto-redacted regex match: PHOENIX_SECRET. Sanitized key replacement applied.` |
| **RAG Ingestion Poisoning** | Malicious script indexed into files to force instruction overrides during retrieval. | **Pre-Ingestion Sanitizer** filters documents *before* they are committed to the SQLite vector table, stripping command terms like `ignore previous`. | ` -> [Ingestion Sanitizer] Rewrote RAG document target: 'Ignore previous' -> '[INJECTION_ATTEMPT_REMOVED]'` |

---

## 📊 3. PROMETHEUS METRIC REGISTERS

All operations are instrumented using Prometheus metrics on port `8000`:
- `citadel_requests_total`: Tracks total processed requests (labeled as `allowed`, `blocked`, or `sanitized`).
- `citadel_attacks_total`: Tracks intercepted threats (labeled by guard component and attack category).
- `citadel_latency_seconds`: Measures individual processing latencies for Input Guard, LLM Judge, RAG, LLM Principal, and Output Guard.

---

## 🚀 4. RUNNING THE STACK

Deploy using **Docker Compose**:
```bash
docker-compose up --build -d
```
Access points:
- **Streamlit Arena & Dashboard**: `http://localhost:8501`
- **Prometheus Scraper UI**: `http://localhost:9090`
- **Raw Telemetry Metrics**: `http://localhost:8000`
