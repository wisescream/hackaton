import re
import base64
import config
import time
from core import ml_classifier
from utils import metrics

def detect_obfuscation(text: str) -> tuple:
    """
    Detects potential obfuscation techniques such as Base64, Binary, Leetspeak, or suspicious character patterns.
    Returns: (indicators, decoded_contents)
    """
    indicators = []
    decoded_contents = []
    
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
                decoded_contents.append(decoded)
        except Exception:
            pass

    # 2. Binary representation (e.g., 01001000 01000101)
    binary_pattern = re.compile(r'\b([01]{8}(?:\s+[01]{8}){2,})\b')
    for match in binary_pattern.finditer(text):
        candidate = match.group(0)
        try:
            binary_values = candidate.split()
            decoded = "".join(chr(int(b, 2)) for b in binary_values)
            if len(decoded) > 3 and any(c.isalnum() for c in decoded):
                indicators.append("Binary Representation Obfuscation")
                decoded_contents.append(decoded)
        except Exception:
            pass

    # 3. Leetspeak or weird character spacing (e.g. "i g n o r e" or "1gn0r3")
    spaced_words = re.compile(r'\b(?:[a-zA-Z0-9_]\s+){3,}[a-zA-Z0-9_]\b')
    for match in spaced_words.finditer(text):
        candidate = match.group(0)
        decoded = candidate.replace(" ", "")
        if len(decoded) > 3:
            indicators.append("Spaced Character Obfuscation")
            decoded_contents.append(decoded)

    # Check for excessive leetspeak (e.g. replacing E with 3, O with 0, I with 1, A with 4)
    # We check if there are words that look heavily substituted but resemble attack keywords
    leetspeak_checks = [
        (r'i[g6]n[o0]r[e3]', "ignore"),
        (r'p[r7][o0]mp[t7]', "prompt"),
        (r's[y5]s[t7][e3]m', "system"),
        (r'j[a4]1[l1]br[e3][a4]k', "jailbreak")
    ]
    has_leet = False
    for pattern, target in leetspeak_checks:
        if re.search(pattern, text, re.IGNORECASE):
            # Verify it's not a normal word (e.g. 'ignore' itself will not trigger unless it's got numbers)
            if re.search(r'[034567]', text):
                indicators.append(f"Leetspeak Obfuscation targeting '{target}'")
                has_leet = True
                
    if has_leet:
        # Simple leet translation map
        leet_map = {'3': 'e', '4': 'a', '1': 'i', '0': 'o', '5': 's', '7': 't', '6': 'g', '@': 'a', '$': 's'}
        translated = "".join(leet_map.get(c.lower(), c.lower()) for c in text)
        decoded_contents.append(translated)

    return indicators, decoded_contents

def run_regex_scoring_engine(user_query: str, obfuscation_detected: list, decoded_contents: list) -> tuple:
    """
    Backup rule-based scoring engine for uncertain / dead zone classifications or when model is absent.
    """
    matched_rules = []
    texts_to_scan = [user_query] + decoded_contents
    
    # 1. Regex rule-based scanning
    for text in texts_to_scan:
        for keyword in config.INJECTION_KEYWORDS:
            if re.search(keyword, text, re.IGNORECASE):
                if keyword not in matched_rules:
                    matched_rules.append(keyword)

    triggers = []
    attack_type = "Normal Query"
    risk_score = 0.0

    # Rule-based triggers
    if matched_rules:
        triggers.append(f"Regex backup matched {len(matched_rules)} system injection rule(s)")
        risk_score += 0.35 * len(matched_rules)
        attack_type = "Prompt Injection"
        if any("ignore" in rule or "system" in rule or "jailbreak" in rule for rule in matched_rules):
            risk_score += 0.35
            triggers.append("Direct override attempt targeting core instructions")

    # Obfuscation triggers
    if obfuscation_detected:
        triggers.append(f"Regex backup flagged {len(obfuscation_detected)} obfuscation indicator(s)")
        risk_score += 0.30 * len(obfuscation_detected)
        attack_type = "Obfuscation Attack"

    # Extraction triggers — word-boundary regex to avoid false positives
    extraction_patterns = [
        r"\badmin\b",
        r"\bsecrets?\b(?!\s+(?:sauce|recipe|weapon|ingredient|menu|to\s))",
        r"\bphoenix\b",
        r"\btokens?\b",
        r"\bpasswords?\b",
        r"\bcredentials?\b",
        r"\bvault\b",
        r"\bconfig\b",
        r"\b(?:api|admin|secret|access|private|encryption|auth)\s*[-_]?\s*keys?\b",
        r"\b(?:postgres|postgresql|mysql|mongodb)\b",
        r"\b(?:database|db)\s*(?:url|uri|gateway|connection|string|cred)\b",
        r"\bconnection\s*string\b",
    ]
    retrieval_verb_patterns = [
        r"\bprint\b", r"\bgive\b", r"\bshow\b", r"\breveal\b",
        r"\bextract\b", r"\bdisplay\b", r"\bdump\b",
    ]
    
    has_extract_kw = False
    has_retrieval_verb = False
    for text in texts_to_scan:
        text_lower = text.lower()
        if any(re.search(pat, text_lower) for pat in extraction_patterns):
            has_extract_kw = True
        if any(re.search(v, text_lower) for v in retrieval_verb_patterns):
            has_retrieval_verb = True
            
    if has_extract_kw:
        risk_score += 0.35
        if attack_type == "Normal Query":
            attack_type = "Extraction Attempt"
        triggers.append("Query seeks sensitive data categories")
        
        if has_retrieval_verb:
            risk_score += 0.40
            attack_type = "Extraction Attempt"
            triggers.append("Direct credential extraction verb matched")

    # Structural triggers (length)
    if len(user_query) > 5000:
        risk_score += 0.20
        triggers.append("Critical input length")
    elif len(user_query) > 2000:
        risk_score += 0.10
        triggers.append("Large input length")

    return risk_score, matched_rules, obfuscation_detected, attack_type, triggers

def analyze_input(user_query: str) -> dict:
    """
    Analyzes user queries to calculate a security risk score between 0.0 and 1.0.
    Integrates fine-tuned SetFit classifier as primary, with regex fallback for dead zone.
    """
    if not user_query or not user_query.strip():
        return {
            "risk_score": 0.0,
            "matched_rules": [],
            "obfuscation_detected": [],
            "attack_type": "Normal Query",
            "triggers": ["Empty input"],
            "decision": "ALLOW",
            "details": "Empty prompt.",
            "model_absent": not ml_classifier.MODEL_LOADED,
            "model_warning": ml_classifier.MODEL_WARNING
        }

    matched_rules = []
    obfuscation_detected, decoded_contents = detect_obfuscation(user_query)
    
    # 1. Critical Hardcoded Regex Guardrails (Base64, ignore previous instructions, direct injection)
    critical_matched = False
    guardrail_triggers = []
    
    # Check direct override keywords
    critical_override_keywords = [
        r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules|directives)",
        r"reveal\s+(?:your\s+)?system\s+prompt",
        r"system\s+prompt\s+extraction",
        r"developer_mode\s+active"
    ]
    
    texts_to_scan = [user_query] + decoded_contents
    for text in texts_to_scan:
        for kw in critical_override_keywords:
            if re.search(kw, text, re.IGNORECASE):
                critical_matched = True
                guardrail_triggers.append(f"Critical hardcoded override keyword: '{kw}'")
                
    if obfuscation_detected:
        critical_matched = True
        guardrail_triggers.append(f"Critical obfuscation pattern: {obfuscation_detected[0]}")

    # 2. Main Machine Learning Inference
    start_time = time.perf_counter()
    ml_res = ml_classifier.predict(user_query)
    inference_time = time.perf_counter() - start_time
    metrics.LATENCY_SECONDS.labels("ml_input_guard").observe(inference_time)
    
    risk_score = 0.0
    triggers = []
    attack_type = "Normal Query"
    
    if ml_classifier.MODEL_LOADED:
        # Record raw confidence score
        metrics.ML_INPUT_GUARD_CONFIDENCE.set(ml_res["score"])
        
        if ml_res["confident"]:
            # ML is confident -> use ML score directly
            risk_score = ml_res["score"]
            attack_type = "ML Threat Assessment" if risk_score >= 0.50 else "Normal Query"
            triggers.append(f"SetFit Classifier assessed risk at {risk_score}")
        else:
            # ML is not confident (Dead Zone [0.40 - 0.60]) -> Fall back to regex backup scorer!
            metrics.ML_INPUT_GUARD_FALLBACKS.labels("dead_zone").inc()
            triggers.append(f"SetFit Classifier uncertain (Score: {ml_res['score']}) -> Running Regex Backup Scorer")
            regex_risk, matched_rules, obfuscation_detected, attack_type, triggers_regex = run_regex_scoring_engine(
                user_query, obfuscation_detected, decoded_contents
            )
            risk_score = regex_risk
            triggers.extend(triggers_regex)
    else:
        # Model is absent -> Synch startup fallback to full regex backup
        metrics.ML_INPUT_GUARD_FALLBACKS.labels("model_absent").inc()
        triggers.append("SetFit Model Absent -> Synch Startup Fallback to Regex Backup")
        regex_risk, matched_rules, obfuscation_detected, attack_type, triggers_regex = run_regex_scoring_engine(
            user_query, obfuscation_detected, decoded_contents
        )
        risk_score = regex_risk
        triggers.extend(triggers_regex)

    # Apply Critical hardcoded regex guardrail override (Enforces minimum FLAG_HIGH risk)
    if critical_matched:
        risk_score = max(risk_score, 0.75)
        attack_type = "Direct Prompt Injection"
        triggers.extend(guardrail_triggers)

    # Clamp the risk score
    risk_score = min(max(risk_score, 0.0), 1.0)
    risk_score = round(risk_score, 2)

    # Enforce Three-Status Threshold Strategy
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

    # Increment input guard decisions in Prometheus
    metrics.INPUT_GUARD_DECISIONS.labels(decision=decision).inc()

    return {
        "risk_score": risk_score,
        "matched_rules": matched_rules,
        "obfuscation_detected": obfuscation_detected,
        "attack_type": attack_type,
        "triggers": triggers,
        "decision": decision,
        "details": details,
        "model_absent": not ml_classifier.MODEL_LOADED,
        "model_warning": ml_classifier.MODEL_WARNING
    }

def sanitize_history(history_messages: list) -> list:
    """
    MEMORY GUARD: Scans historical user messages before feeding them into the LLM system prompt.
    """
    sanitized_history = []
    for msg in history_messages:
        role = msg.get("role")
        content = msg.get("content", "")
        status = msg.get("status", "safe")
        risk = msg.get("risk_score", 0.0)

        if role == "user":
            if status == "blocked" or risk >= 0.70:
                content = "⚠️ [MEMORY SHIELD: Malicious prompt injection payload detected and sanitized to prevent memory hijacking]"
            elif risk >= 0.35:
                content = "[MEMORY SHIELD: Suspicious credential request sanitized]"
        
        sanitized_history.append({
            "role": role,
            "content": content
        })
    return sanitized_history
