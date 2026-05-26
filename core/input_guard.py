import re
import base64
import config

def detect_obfuscation(text: str) -> list:
    """
    Detects potential obfuscation techniques such as Base64, Binary, Leetspeak, or suspicious character patterns.
    """
    indicators = []
    
    # 1. Base64 detection heuristics: sequence of alphanumeric characters ending with == or length multiple of 4
    # We look for a continuous string of base64-like text that is at least 16 chars long
    b64_pattern = re.compile(r'\b[a-zA-Z0-9+/]{16,}={0,2}\b')
    for match in b64_pattern.finditer(text):
        candidate = match.group(0)
        try:
            # Try to decode to see if it's readable text
            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
            if len(decoded) > 5 and any(c.isalnum() for c in decoded):
                indicators.append(f"Base64 Obfuscation (decodes to: '{decoded[:30]}...')")
        except Exception:
            pass

    # 2. Binary representation (e.g., 01001000 01000101)
    binary_pattern = re.compile(r'\b[01]{8}(?:\s+[01]{8}){2,}\b')
    if binary_pattern.search(text):
        indicators.append("Binary Representation Obfuscation")

    # 3. Leetspeak or weird character spacing (e.g. "i g n o r e" or "1gn0r3")
    spaced_words = re.compile(r'\b(?:[a-zA-Z]\s+){4,}[a-zA-Z]\b')
    if spaced_words.search(text):
        indicators.append("Spaced Character Obfuscation")

    # Check for excessive leetspeak (e.g. replacing E with 3, O with 0, I with 1, A with 4)
    # We check if there are words that look heavily substituted but resemble attack keywords
    leetspeak_checks = [
        (r'i[g6]n[o0]r[e3]', "ignore"),
        (r'p[r7][o0]mp[t7]', "prompt"),
        (r's[y5]s[t7][e3]m', "system"),
        (r'j[a4]1[l1]br[e3][a4]k', "jailbreak")
    ]
    for pattern, target in leetspeak_checks:
        if re.search(pattern, text, re.IGNORECASE):
            # Verify it's not a normal word (e.g. 'ignore' itself will not trigger here unless it's got numbers)
            if re.search(r'[034567]', text):
                indicators.append(f"Leetspeak Obfuscation targeting '{target}'")

    return indicators

def analyze_input(user_query: str) -> dict:
    """
    Analyzes user queries to calculate a security risk score between 0.0 and 1.0.
    Classifies the attack type and lists specific security triggers.
    """
    if not user_query or not user_query.strip():
        return {
            "risk_score": 0.0,
            "matched_rules": [],
            "obfuscation_detected": [],
            "attack_type": "Normal Query",
            "triggers": ["Empty input"],
            "decision": "ALLOW",
            "details": "Empty prompt."
        }

    matched_rules = []
    obfuscation_detected = detect_obfuscation(user_query)
    user_lower = user_query.lower()
    
    # 1. Regex rule-based scanning
    for keyword in config.INJECTION_KEYWORDS:
        if re.search(keyword, user_query, re.IGNORECASE):
            matched_rules.append(keyword)

    # 2. Heuristics for attack classification & specific triggers
    triggers = []
    attack_type = "Normal Query"
    risk_score = 0.0

    # Rule-based triggers
    if matched_rules:
        triggers.append(f"Matched {len(matched_rules)} system injection rule(s)")
        risk_score += 0.35 * len(matched_rules)
        attack_type = "Prompt Injection"
        if any("ignore" in rule or "system" in rule or "jailbreak" in rule for rule in matched_rules):
            risk_score += 0.35
            triggers.append("Direct override attempt targeting core instructions")

    # Obfuscation triggers
    if obfuscation_detected:
        triggers.append(f"Flagged {len(obfuscation_detected)} obfuscation indicator(s)")
        risk_score += 0.30 * len(obfuscation_detected)
        attack_type = "Obfuscation Attack"

    # Extraction triggers
    extraction_keywords = ["admin", "secret", "key", "phoenix", "token", "password", "credential"]
    retrieval_verbs = ["print", "give", "show", "reveal", "extract", "display", "dump"]
    
    has_extract_kw = any(kw in user_lower for kw in extraction_keywords)
    has_retrieval_verb = any(v in user_lower for v in retrieval_verbs)
    
    if has_extract_kw:
        risk_score += 0.15
        if attack_type == "Normal Query":
            attack_type = "Extraction Attempt"
        triggers.append("Query seeks sensitive data categories")
        
        if has_retrieval_verb:
            risk_score += 0.25
            attack_type = "Extraction Attempt"
            triggers.append("Direct credential extraction verb matched")

    # Structural triggers (length)
    if len(user_query) > 2000:
        risk_score += 0.10
        triggers.append("Large input length (possible payload container)")
    elif len(user_query) > 5000:
        risk_score += 0.20
        triggers.append("Critical input length (high probability of hidden payload)")

    # Clamp the risk score
    risk_score = min(max(risk_score, 0.0), 1.0)
    risk_score = round(risk_score, 2)

    # 3. Enforce Three-Status Threshold Strategy
    # 0.0 to 0.35 -> ALLOW (Safe)
    # 0.35 to 0.70 -> FLAG_MEDIUM (Limited / Degraded)
    # 0.70 to 1.00 -> FLAG_HIGH (Blocked)
    if risk_score >= config.RISK_THRESHOLD_HIGH:
        decision = "FLAG_HIGH"
    elif risk_score >= config.RISK_THRESHOLD_MEDIUM:
        decision = "FLAG_MEDIUM"
    else:
        decision = "ALLOW"

    # Set default triggers if clean
    if not triggers:
        triggers.append("No suspicious indicators matched")

    # Detail logging
    if decision == "FLAG_HIGH":
        details = f"🔴 BLOCKED: Direct {attack_type} detected. Risk score ({risk_score}) exceeds high threshold."
    elif decision == "FLAG_MEDIUM":
        details = f"🟡 LIMITED: Suspected {attack_type} or credential query. Risk score ({risk_score}) enforces RAG degradation."
    else:
        details = f"🟢 SAFE: Risk score ({risk_score}) is clean. Processing standard RAG request."

    return {
        "risk_score": risk_score,
        "matched_rules": matched_rules,
        "obfuscation_detected": obfuscation_detected,
        "attack_type": attack_type,
        "triggers": triggers,
        "decision": decision,
        "details": details
    }

def sanitize_history(history_messages: list) -> list:
    """
    🛡️ MEMORY GUARD: Scans historical user messages before feeding them into the LLM system prompt.
    If a message was flagged as blocked, had a high risk score, or contained sensitive extraction attempts,
    it is filtered or replaced with a safety block warning to prevent 'indirect prompt injection via memory'.
    """
    sanitized_history = []
    for msg in history_messages:
        role = msg.get("role")
        content = msg.get("content", "")
        status = msg.get("status", "safe")
        risk = msg.get("risk_score", 0.0)

        # Only process/sanitize User messages for injection attempts. Assistant responses are protected by Output Guard.
        if role == "user":
            # If the user prompt was blocked or had significant risk, censor its recovery to context
            if status == "blocked" or risk >= 0.70:
                content = "⚠️ [MEMORY SHIELD: Malicious prompt injection payload detected and sanitized to prevent memory hijacking]"
            elif risk >= 0.35:
                # Censor sensitive keywords/potential extractions in the retrieved history
                content = "[MEMORY SHIELD: Suspicious credential request sanitized]"
        
        sanitized_history.append({
            "role": role,
            "content": content
        })
    return sanitized_history

