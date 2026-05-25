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
