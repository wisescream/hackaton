import re
import config
from core import main_llm

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
            # We flag instruction leak if the output echoes back system boundaries
            return True, reason
            
    return False, "Safe"

def validate_and_sanitize_output(user_query: str, raw_response: str) -> dict:
    """
    Performs critical output verification (DLP) before delivering the message.
    Redacts any critical admin key or API tokens, and checks for system prompt leakages.
    """
    if not raw_response or not raw_response.strip():
        return {
            "sanitized_response": "",
            "leak_detected": False,
            "matched_patterns": [],
            "instruction_leak": False,
            "remediation_steps": [],
            "reason": "Clean Response",
            "details": "Empty response."
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

    # 2. Check for system instruction leakage
    instruction_leak, leak_reason = check_system_prompt_leakage(sanitized_response)
    
    if instruction_leak:
        leak_detected = True
        remediation_steps.append(f"Enforced prompt confidentiality: {leak_reason}")
        # Clean/sanitize or return a polite security blocker message if it's a major system leak
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

    return {
        "sanitized_response": sanitized_response,
        "leak_detected": leak_detected,
        "matched_patterns": matched_patterns,
        "instruction_leak": instruction_leak,
        "remediation_steps": remediation_steps,
        "reason": reason,
        "details": details
    }
