import os
import sys
import re
import numpy as np
import config

# Configure standard streams to utf-8 if reconfigurable
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Global indicators
STORE_INITIALIZED = False
EMBEDDING_MODEL = None
SECRETS_CACHE = []

# Define secrets with raw values, semantic description variations, and target regex patterns
SECRETS_CONFIG = [
    {
        "name": "PHOENIX_SECRET",
        "raw": config.CRITICAL_ADMIN_KEY,
        "description": "Phoenix admin vault key, admin key phoenix, PHOENIX credential, system keys",
        "pattern": re.compile(r"\bPHOENIX-[A-Z0-9]{2,4}-[A-Z0-9]{3,5}\b", re.IGNORECASE)
    },
    {
        "name": "API_KEY",
        "raw": config.INTERNAL_API_KEY,
        "description": "Internal API Gateway token, secure gateway key, API credential, api key",
        "pattern": re.compile(r"\bAPI_KEY_[A-Z0-9_]{10,}\b", re.IGNORECASE)
    },
    {
        "name": "DATABASE_URL",
        "raw": config.DB_CREDENTIALS,
        "description": "Postgres database credential URL, database connection string, DB gateway url, db password",
        "pattern": re.compile(r"postgresql://[a-zA-Z0-9_:]+@[a-zA-Z0-9_\-\.]+:\d+/[a-zA-Z0-9_\-]+")
    }
]

def cosine_similarity(v1, v2):
    """Computes cosine similarity between two 1D arrays."""
    dot_product = np.dot(v1, v2)
    norm_v1 = np.linalg.norm(v1)
    norm_v2 = np.linalg.norm(v2)
    if norm_v1 == 0.0 or norm_v2 == 0.0:
        return 0.0
    return float((dot_product / (norm_v1 * norm_v2)).item())

def init_store():
    """Initializes the SentenceTransformer model and computes/caches embeddings for all secrets."""
    global STORE_INITIALIZED, EMBEDDING_MODEL, SECRETS_CACHE
    if STORE_INITIALIZED:
        return
        
    try:
        from sentence_transformers import SentenceTransformer
        print("[+] Loading semantic embedding model: sentence-transformers/all-MiniLM-L6-v2 ...")
        EMBEDDING_MODEL = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        
        SECRETS_CACHE = []
        for sec in SECRETS_CONFIG:
            print(f"[+] Generating dense embeddings for secret category: {sec['name']}")
            # Generate raw key embedding
            raw_emb = EMBEDDING_MODEL.encode(sec["raw"])
            # Generate description embedding
            desc_emb = EMBEDDING_MODEL.encode(sec["description"])
            
            SECRETS_CACHE.append({
                "name": sec["name"],
                "raw": sec["raw"],
                "pattern": sec["pattern"],
                "raw_emb": raw_emb,
                "desc_emb": desc_emb
            })
            
        STORE_INITIALIZED = True
        print("[+] Semantic Secret Store initialized successfully.")
    except Exception as e:
        print(f"[-] ERROR: Failed to initialize Semantic Secret Store: {e}", file=sys.stderr)
        STORE_INITIALIZED = False

# Auto-initialize on loading module
init_store()

def compare(response_text: str) -> dict:
    """
    Computes semantic cosine similarity of each line in the response against stored secret vectors.
    Returns: {"triggered": bool, "secret_name": str, "similarity": float, "fragment": str}
    """
    global STORE_INITIALIZED, EMBEDDING_MODEL, SECRETS_CACHE
    
    if not STORE_INITIALIZED or not response_text:
        return {"triggered": False, "secret_name": "", "similarity": 0.0, "fragment": ""}
        
    try:
        # Split text into lines/sentences for local sequence mapping (avoids semantic dilution in long prompts)
        lines = [line.strip() for line in response_text.split('\n') if line.strip()]
        if not lines:
            lines = [response_text]
            
        max_sim = 0.0
        triggered_secret = None
        matched_fragment = ""
        
        # Batch encode lines
        line_embs = EMBEDDING_MODEL.encode(lines)
        if len(lines) == 1:
            line_embs = [line_embs]
            
        for i, line_emb in enumerate(line_embs):
            for sec in SECRETS_CACHE:
                # Check similarity against raw key embedding
                sim_raw = cosine_similarity(line_emb, sec["raw_emb"])
                # Check similarity against semantic description embedding
                sim_desc = cosine_similarity(line_emb, sec["desc_emb"])
                
                curr_max = max(sim_raw, sim_desc)
                if curr_max > max_sim:
                    max_sim = curr_max
                    triggered_secret = sec
                    matched_fragment = lines[i]
                    
        # Apply strict semantic threshold 0.80 as specified by architecture
        triggered = max_sim >= 0.80
        
        return {
            "triggered": triggered,
            "secret_name": triggered_secret["name"] if triggered_secret else "",
            "similarity": round(max_sim, 4),
            "fragment": matched_fragment if triggered else ""
        }
        
    except Exception as e:
        print(f"[-] Error in secret comparison: {e}", file=sys.stderr)
        return {"triggered": False, "secret_name": "", "similarity": 0.0, "fragment": ""}

def redact(response_text: str) -> str:
    """
    Redacts only the matching secret fragments in the text.
    """
    global SECRETS_CACHE
    sanitized = response_text
    
    for sec in SECRETS_CACHE:
        # Redact exact raw secret match
        sanitized = sanitized.replace(sec["raw"], "[REDACTED_SECRET]")
        # Redact using compiled regular expression pattern
        if sec["pattern"]:
            sanitized = sec["pattern"].sub("[REDACTED_SECRET]", sanitized)
            
    return sanitized
