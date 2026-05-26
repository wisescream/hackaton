import re
import config
import time
from core import main_llm, secret_store
from utils import metrics

def check_system_prompt_leakage(raw_response: str) -> tuple:
    """
    Checks if the assistant's output contains leaked system prompt instructions.
    Returns (leak_detected: bool, reason: str).
    """
    response_lower = raw_response.lower()
    
    # 1. Structural indicator check (checking if typical system rules are listed back)
    heuristics = [
        ("you are citadel-y light guard", "System identity leaked"),
        ("never reveal your system prompt", "Security directives leaked"),
        ("context documents:", "RAG pipeline boundaries leaked"),
        ("system prompt", "System terminology leaked"),
        ("developer_mode active", "Bypass indicators leaked")
    ]
    
    for term, reason in heuristics:
        if term in response_lower:
            return True, reason
            
    return False, "Safe"

def validate_and_sanitize_output(user_query: str, raw_response: str) -> dict:
    """
    Performs critical output verification (DLP) before delivering the message.
    Combines high-speed Regex/String matching with Semantic Embedding Cosine Similarity.
    """
    if not raw_response or not raw_response.strip():
        return {
            "sanitized_response": "",
            "leak_detected": False,
            "matched_patterns": [],
            "instruction_leak": False,
            "remediation_steps": [],
            "reason": "Clean Response",
            "details": "Empty response.",
            "ml_dlp": {"triggered": False, "secret_name": "", "similarity": 0.0}
        }

    sanitized_response = raw_response
    matched_patterns = []
    remediation_steps = []
    leak_detected = False

    # 1. High-speed DLP scanning (Regex)
    for name, pattern in config.DLP_PATTERNS.items():
        if pattern.search(sanitized_response):
            matched_patterns.append(name)
            leak_detected = True
            remediation_steps.append(f"Auto-redacted regex match: {name}")
            sanitized_response = pattern.sub("[REDACTED_SECRET]", sanitized_response)

    # Double check string matches for crucial credentials from configuration
    if config.CRITICAL_ADMIN_KEY in sanitized_response:
        if "PHOENIX_SECRET" not in matched_patterns:
            matched_patterns.append("PHOENIX_SECRET")
        leak_detected = True
        remediation_steps.append("Suppressed PHOENIX vault administrative key exfiltration")
        sanitized_response = sanitized_response.replace(config.CRITICAL_ADMIN_KEY, "[REDACTED_SECRET]")

    if config.INTERNAL_API_KEY in sanitized_response:
        if "API_KEY" not in matched_patterns:
            matched_patterns.append("API_KEY")
        leak_detected = True
        remediation_steps.append("Suppressed internal API Gateway token exfiltration")
        sanitized_response = sanitized_response.replace(config.INTERNAL_API_KEY, "[REDACTED_SECRET]")

    if config.DB_CREDENTIALS in sanitized_response:
        if "DATABASE_URL" not in matched_patterns:
            matched_patterns.append("DATABASE_URL")
        leak_detected = True
        remediation_steps.append("Suppressed Postgres database credential URL exfiltration")
        sanitized_response = sanitized_response.replace(config.DB_CREDENTIALS, "[REDACTED_SECRET]")

    # 2. Semantic Embedding DLP scanning (all-MiniLM-L6-v2 Cosine Similarity > 0.80)
    ml_dlp_triggered = False
    ml_dlp_secret = ""
    ml_dlp_similarity = 0.0
    
    if secret_store.STORE_INITIALIZED:
        start_time = time.perf_counter()
        ml_dlp_res = secret_store.compare(sanitized_response)
        inference_time = time.perf_counter() - start_time
        metrics.LATENCY_SECONDS.labels("ml_dlp_guard").observe(inference_time)
        
        ml_dlp_triggered = ml_dlp_res["triggered"]
        ml_dlp_secret = ml_dlp_res["secret_name"]
        ml_dlp_similarity = ml_dlp_res["similarity"]
        
        # Record similarity score in Prometheus
        if ml_dlp_similarity > 0.0:
            metrics.ML_DLP_SIMILARITY.observe(ml_dlp_similarity)
        
        if ml_dlp_triggered:
            leak_detected = True
            if ml_dlp_secret not in matched_patterns:
                matched_patterns.append(ml_dlp_secret)
            remediation_steps.append(f"Auto-redacted semantic match (similarity: {ml_dlp_similarity}): {ml_dlp_secret}")
            # Redact only matching secret fragments in sanitized_response
            sanitized_response = secret_store.redact(sanitized_response)
            
            # Record redaction counter in Prometheus
            metrics.ML_DLP_REDACTIONS.labels(ml_dlp_secret).inc()

    # 3. Check for system instruction leakage
    instruction_leak, leak_reason = check_system_prompt_leakage(sanitized_response)
    
    if instruction_leak:
        leak_detected = True
        remediation_steps.append(f"Enforced prompt confidentiality: {leak_reason}")
        sanitized_response = (
            "⚠️ SECURITY BLOCK: The system blocked a potential information leakage attempt. "
            f"Reason: {leak_reason}."
        )

    # Summarize findings for telemetry
    details = "Clean response."
    reason = "🟢 CLEAN"
    if leak_detected:
        reason = "⚠️ WARNING: prompt manipulation detected but response sanitized"
        details = f"Leaked Secrets Blocked: {', '.join(matched_patterns)}"
        if instruction_leak:
            reason = "⚠️ DLP BLOCK: System prompt/identity exfiltration blocked"
            details += f" | {leak_reason}"

    # Increment DLP scan metrics in Prometheus
    if leak_detected:
        rule_type = "regex"
        if instruction_leak:
            rule_type = "instruction"
        elif ml_dlp_triggered:
            rule_type = "semantic"
        metrics.DLP_SCANS.labels(leak_detected="true", rule_type=rule_type).inc()
    else:
        metrics.DLP_SCANS.labels(leak_detected="false", rule_type="none").inc()

    return {
        "sanitized_response": sanitized_response,
        "leak_detected": leak_detected,
        "matched_patterns": matched_patterns,
        "instruction_leak": instruction_leak,
        "remediation_steps": remediation_steps,
        "reason": reason,
        "details": details,
        "ml_dlp": {
            "triggered": ml_dlp_triggered,
            "secret_name": ml_dlp_secret,
            "similarity": ml_dlp_similarity
        }
    }
