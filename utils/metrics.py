import time
import threading
from prometheus_client import start_http_server, Counter, Histogram, Gauge

# --- GLOBALS & LAUNCH PREVENTION ---
METRICS_PORT = 8000
_server_started = False
_lock = threading.Lock()

# --- PROMETHEUS METRIC DEFINITIONS ---
# 1. Total Requests
REQUESTS_TOTAL = Counter(
    "citadel_requests_total",
    "Total number of user queries processed by CITADEL-Y Light Guard",
    ["status"] # allowed, blocked, sanitized
)

# 2. Attacks Detected
ATTACKS_DETECTED = Counter(
    "citadel_attacks_total",
    "Total prompt injections / security threats intercepted",
    ["guard", "attack_type"] # input_guard/judge/output_guard, injection/obfuscation/dlp
)

# 3. Component Latency
LATENCY_SECONDS = Histogram(
    "citadel_latency_seconds",
    "Total processing latency for the whole pipeline and sub-components",
    ["component"] # pipeline, input_guard, judge, rag, principal_llm, output_guard
)

# 4. Total LLM API calls
LLM_CALLS = Counter(
    "citadel_llm_calls_total",
    "Total calls made to LLMs (juge or principal)",
    ["role", "model"] # judge/principal, model_name
)

# 5. OpenRouter Costs (Simulated)
ESTIMATED_COSTS = Counter(
    "citadel_estimated_cost_usd",
    "Estimated operational cost of LLM inference in USD"
)

# 6. Current Threat Risk level
CURRENT_RISK = Gauge(
    "citadel_current_threat_risk",
    "Threat risk level computed for the latest processed query"
)

# 7. SetFit Raw Confidence Score
ML_INPUT_GUARD_CONFIDENCE = Gauge(
    "citadel_ml_input_guard_confidence",
    "Confidence score computed by the SetFit model for the latest query"
)

# 8. SetFit Fallback Counter
ML_INPUT_GUARD_FALLBACKS = Counter(
    "citadel_ml_input_guard_fallbacks_total",
    "Total number of times Input Guard fell back to the rule-based regex engine",
    ["reason"]  # "dead_zone" or "model_absent"
)

# 9. Semantic DLP Guard Cosine Similarity Score
ML_DLP_SIMILARITY = Histogram(
    "citadel_ml_dlp_similarity_scores",
    "Cosine similarity scores of candidate leaked blocks against secret embeddings",
    buckets=[0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 1.0]
)

# 10. Semantic DLP Redactions Counter
ML_DLP_REDACTIONS = Counter(
    "citadel_ml_dlp_redactions_total",
    "Total number of semantic DLP redactions performed by Output Guard",
    ["secret_category"]  # e.g., PHOENIX_SECRET, API_KEY, DATABASE_URL
)

# 11. Input Guard Decision Counter (ALLOW, FLAG_MEDIUM, FLAG_HIGH)
INPUT_GUARD_DECISIONS = Counter(
    "citadel_input_guard_decisions_total",
    "Total decisions made by Input Guard",
    ["decision"]
)

# 12. LLM Judge Verdicts (unsafe = true/false)
JUDGE_VERDICTS = Counter(
    "citadel_judge_verdicts_total",
    "Total verdicts returned by LLM Judge",
    ["unsafe"]
)

# 13. RAG Access Control Policy Applied
RAG_POLICIES = Counter(
    "citadel_rag_policy_applied_total",
    "Total RAG security policies applied to context retrieval requests",
    ["policy", "user_role"]
)

# 14. RAG Scoped Documents Retrieved
RAG_DOCUMENTS = Counter(
    "citadel_rag_documents_retrieved_total",
    "Total scoped documents retrieved during RAG search",
    ["document_title", "classification"]
)

# 15. Output Guard DLP Scans
DLP_SCANS = Counter(
    "citadel_dlp_scans_total",
    "Total scans processed by Output Guard DLP",
    ["leak_detected", "rule_type"]
)

# 16. Red Team Attack Activity
REDTEAM_ATTACKS = Counter(
    "citadel_redteam_attacks_total",
    "Total prompt injection attacks launched against Citadel-Y by the Red Team",
    ["attacker", "category", "status"]
)

# 17. Red Team Flag Submissions
REDTEAM_FLAGS = Counter(
    "citadel_redteam_flags_submitted_total",
    "Total CTF flags submitted to the Red Team scoreboard",
    ["attacker", "flag_name", "status"]
)

# --- THREAD-SAFE LAUNCH FUNCTION ---
def start_metrics_server(port=METRICS_PORT):
    """
    Launches the Prometheus metric scraping HTTP server on a background thread.
    Uses double-checked locking to avoid port re-binding errors during Streamlit hot-reloads.
    """
    global _server_started
    with _lock:
        if not _server_started:
            try:
                start_http_server(port)
                _server_started = True
                print(f"📈 [Metrics Exporter] Server started on port {port}.")
            except Exception as e:
                # If port is already bound, it might have been started by a previous reload.
                print(f"📈 [Metrics Exporter] Note: Exporter already running or bound: {e}")
                _server_started = True # Treat as started to prevent endless retries
