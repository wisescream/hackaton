import sqlite3
import json
import re
import math
import config

DB_PATH = "citadel_rag.db"

# --- HELPER FUNCTIONS FOR VECTOR SEARCH ---
def tokenize(text: str) -> list:
    """Tokenizes text and returns lowercase alphabetic words."""
    return re.findall(r'\b[a-z]{3,}\b', text.lower())

def compute_tfidf_cosine_similarity(query: str, documents: list) -> list:
    """
    Computes TF-IDF cosine similarity between a query string and a list of documents.
    """
    query_tokens = tokenize(query)
    if not query_tokens:
        return [(doc, 0.0) for doc in documents]

    corpus_tokens = [tokenize(doc["content"]) for doc in documents]
    num_docs = len(documents)
    
    df = {}
    for tokens in corpus_tokens:
        unique_tokens = set(tokens)
        for t in unique_tokens:
            df[t] = df.get(t, 0) + 1

    query_tf = {}
    for t in query_tokens:
        query_tf[t] = query_tf.get(t, 0) + 1
        
    query_tfidf = {}
    query_norm = 0.0
    for t, tf in query_tf.items():
        doc_freq = df.get(t, 0)
        idf = math.log((1 + num_docs) / (1 + doc_freq)) + 1
        query_tfidf[t] = tf * idf
        query_norm += query_tfidf[t] ** 2
    query_norm = math.sqrt(query_norm)

    if query_norm == 0.0:
        return [(doc, 0.0) for doc in documents]

    scored_docs = []
    for doc, tokens in zip(documents, corpus_tokens):
        if not tokens:
            scored_docs.append((doc, 0.0))
            continue
            
        doc_tf = {}
        for t in tokens:
            doc_tf[t] = doc_tf.get(t, 0) + 1
            
        doc_tfidf = {}
        doc_norm = 0.0
        for t, tf in doc_tf.items():
            doc_freq = df.get(t, 0)
            idf = math.log((1 + num_docs) / (1 + doc_freq)) + 1
            doc_tfidf[t] = tf * idf
            doc_norm += doc_tfidf[t] ** 2
        doc_norm = math.sqrt(doc_norm)
        
        if doc_norm == 0.0:
            scored_docs.append((doc, 0.0))
            continue

        dot_product = 0.0
        for t in query_tokens:
            if t in doc_tfidf:
                dot_product += query_tfidf[t] * doc_tfidf[t]
                
        cosine_sim = dot_product / (query_norm * doc_norm)
        scored_docs.append((doc, round(cosine_sim, 4)))

    return sorted(scored_docs, key=lambda x: x[1], reverse=True)


# --- RAG PIPELINE INTERFACE ---
def init_db():
    """Initializes the SQLite database for document storage and secure chat logs."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Documents Table (with user_id scope)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            original_content TEXT NOT NULL,
            content TEXT NOT NULL,
            classification TEXT NOT NULL, -- public, internal, restricted
            metadata TEXT NOT NULL,
            user_id TEXT NOT NULL DEFAULT 'SYSTEM'
        )
    """)
    
    # 2. Chat History Table (scoped by user_id and chat_id)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            role TEXT NOT NULL, -- user or assistant
            content TEXT NOT NULL,
            sanitized_content TEXT NOT NULL,
            risk_score REAL NOT NULL,
            status TEXT NOT NULL, -- safe, limited, blocked
            timestamp TEXT NOT NULL
        )
    """)
    
    # 3. Vulnerability Reports Table (for Red Team Capture The Flag submissions)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerability_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attacker_name TEXT NOT NULL,
            payload TEXT NOT NULL,
            vulnerability_type TEXT NOT NULL,
            status TEXT NOT NULL, -- Blocked, Sanitized, Bypassed
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_vulnerability_report(attacker_name: str, payload: str, vulnerability_type: str, status: str) -> int:
    """Saves a vulnerability report submitted by the Red Team."""
    init_db()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO vulnerability_reports (attacker_name, payload, vulnerability_type, status, timestamp) VALUES (?, ?, ?, ?, ?)",
        (attacker_name, payload, vulnerability_type, status, timestamp)
    )
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id

def get_vulnerability_reports() -> list:
    """Retrieves all vulnerability reports submitted by attackers."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, attacker_name, payload, vulnerability_type, status, timestamp FROM vulnerability_reports ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    
    reports = []
    for r in rows:
        reports.append({
            "id": r[0],
            "attacker_name": r[1],
            "payload": r[2],
            "vulnerability_type": r[3],
            "status": r[4],
            "timestamp": r[5]
        })
    return reports


def sanitize_content(text: str) -> str:
    """
    Sanitizes documents prior to ingestion.
    """
    sanitized = text
    for name, pattern in config.DLP_PATTERNS.items():
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)

    sanitized = sanitized.replace(config.CRITICAL_ADMIN_KEY, "[REDACTED_SECRET]")
    sanitized = sanitized.replace(config.INTERNAL_API_KEY, "[REDACTED_SECRET]")
    sanitized = sanitized.replace(config.DB_CREDENTIALS, "[REDACTED_SECRET]")

    indirect_injection_terms = ["ignore previous", "you are now", "developer mode", "system prompt"]
    for term in indirect_injection_terms:
        sanitized = re.sub(rf"\b{term}\b", "[INJECTION_ATTEMPT_REMOVED]", sanitized, flags=re.IGNORECASE)

    return sanitized

def ingest_document(title: str, content: str, classification: str = "public", meta_dict: dict = None, user_id: str = "SYSTEM") -> int:
    """
    Ingests and sanitizes a document into the SQLite RAG database with strict user scoping.
    """
    init_db()
    sanitized_text = sanitize_content(content)
    
    meta_dict = meta_dict or {}
    meta_dict["classification"] = classification
    meta_dict["user_id"] = user_id
    meta_json = json.dumps(meta_dict)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO documents (title, original_content, content, classification, metadata, user_id) VALUES (?, ?, ?, ?, ?, ?)",
        (title, content, sanitized_text, classification, meta_json, user_id)
    )
    doc_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return doc_id

def delete_all_documents():
    """Wipes all documents, persistent chat logs, and vulnerability reports for clean testing/seeding."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM documents")
    cursor.execute("DELETE FROM chat_messages")
    cursor.execute("DELETE FROM vulnerability_reports")
    conn.commit()
    conn.close()

def get_all_documents(user_id: str = "SYSTEM") -> list:
    """Retrieves all documents accessible to a specific user (System global + User's scoped files)."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, title, original_content, content, classification, metadata, user_id FROM documents WHERE user_id = 'SYSTEM' OR user_id = ?",
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    
    docs = []
    for r in rows:
        docs.append({
            "id": r[0],
            "title": r[1],
            "original_content": r[2],
            "content": r[3],
            "classification": r[4],
            "metadata": json.loads(r[5]),
            "user_id": r[6]
        })
    return docs


# --- MULTI-USER CHAT SESSION MANAGEMENT ---

def save_chat_message(user_id: str, chat_id: str, role: str, content: str, sanitized_content: str, risk_score: float, status: str) -> int:
    """Saves a message in the secure chat log scoped by user_id and chat_id."""
    init_db()
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO chat_messages (user_id, chat_id, role, content, sanitized_content, risk_score, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, chat_id, role, content, sanitized_content, risk_score, status, timestamp)
    )
    msg_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return msg_id

def get_chat_history(user_id: str, chat_id: str) -> list:
    """Retrieves the chat history for a specific chat session, ordered by timestamp."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT role, content, sanitized_content, risk_score, status, timestamp FROM chat_messages WHERE user_id = ? AND chat_id = ? ORDER BY timestamp ASC",
        (user_id, chat_id)
    )
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for r in rows:
        history.append({
            "role": r[0],
            "content": r[1],
            "sanitized_content": r[2],
            "risk_score": r[3],
            "status": r[4],
            "timestamp": r[5]
        })
    return history

def get_user_chats(user_id: str) -> list:
    """Returns a list of distinct chat_id sessions for a user."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT DISTINCT chat_id FROM chat_messages WHERE user_id = ?",
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [r[0] for r in rows]

def delete_chat_session(user_id: str, chat_id: str):
    """Deletes all messages for a specific user chat session."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM chat_messages WHERE user_id = ? AND chat_id = ?",
        (user_id, chat_id)
    )
    conn.commit()
    conn.close()


# --- SCOPED CONTEXT RETRIEVAL ---

def retrieve_context(query: str, risk_score: float, current_user_id: str) -> tuple:
    """
    Retrieves relevant context documents from RAG, strictly scoped to standard SYSTEM docs
    or documents belonging directly to current_user_id.
    
    🔐 SECURITY ADAPTATION RULES:
    - 🟢 LOW RISK (< 0.35): Access system (public/internal) and user files. Restricted redacted.
    - 🟡 MEDIUM RISK (>= 0.35): Strict public-only search. Internal/Restricted scoped documents filtered out.
    - 🔴 HIGH RISK (>= 0.70): Vector Blackout. No documents returned.
    """
    init_db()
    filtering_logs = []
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Filter documents scoped to SYSTEM or the current user_id
    cursor.execute(
        "SELECT id, title, content, classification, original_content, user_id FROM documents WHERE user_id = 'SYSTEM' OR user_id = ?",
        (current_user_id,)
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return [], "No documents in scoped database.", [{"title": "N/A", "classification": "N/A", "status": "EMPTY", "reason": "No documents found."}]

    # High-Risk Blackout Policy
    if risk_score >= config.RISK_THRESHOLD_HIGH:
        policy_note = "🔴 RAG BLACKOUT: High-risk prompt prevents any document retrieval."
        for r in rows:
            filtering_logs.append({
                "title": r[1],
                "classification": r[3],
                "status": "FILTERED",
                "reason": f"RAG Blackout: Input risk {risk_score} >= high threshold ({config.RISK_THRESHOLD_HIGH})"
            })
        return [], policy_note, filtering_logs

    # Determine allowed classifications
    elif risk_score >= config.RISK_THRESHOLD_MEDIUM:
        allowed_classifications = ["public"]
        policy_note = f"🟡 ADAPTIVE SECURITY ACTIVE: Medium-risk query. Search restricted to public scoped database only."
    else:
        allowed_classifications = ["public", "internal", "restricted"]
        policy_note = f"🟢 STANDARD SECURITY ACTIVE: Low-risk query. Search includes scoped system & user documents."

    docs_to_rank = []
    for r in rows:
        doc_id, title, content, doc_class, original_content, doc_owner = r
        
        # Check if classification is blocked under current policy
        if doc_class not in allowed_classifications:
            filtering_logs.append({
                "title": title,
                "classification": doc_class,
                "status": "FILTERED",
                "reason": f"Excluded: '{doc_class}' files blocked under Medium-Risk strategy (risk score {risk_score} >= {config.RISK_THRESHOLD_MEDIUM})"
            })
            continue

        docs_to_rank.append({
            "id": doc_id,
            "title": title,
            "content": content,
            "classification": doc_class,
            "original_content": original_content,
            "user_id": doc_owner
        })

    if not docs_to_rank:
        return [], f"{policy_note} (All documents filtered)", filtering_logs

    # Cosine Similarity Ranking
    scored_docs = compute_tfidf_cosine_similarity(query, docs_to_rank)
    top_k = [item for item in scored_docs if item[1] > 0.0][:3]
    
    retrieved_contexts = []
    for doc, score in top_k:
        text_to_inject = doc["content"]
        status = "ALLOWED"
        reason = "Passed similarity match."
        
        if doc["classification"] == "restricted":
            status = "REDACTED"
            reason = "Sensitive fields redacted prior to injection."
            text_to_inject = f"[RESTRICTED ACCESS - VIEW LIMITED] Sanitized content: {sanitize_content(doc['original_content'])}"
        elif doc["classification"] == "internal":
            reason = "Internal context retrieved safely."
            
        filtering_logs.append({
            "title": doc["title"],
            "classification": doc["classification"],
            "status": status,
            "reason": f"Match Score {score} | Scope: {doc['user_id']} | {reason}"
        })
        
        retrieved_contexts.append({
            "id": doc["id"],
            "title": doc["title"],
            "content": text_to_inject,
            "classification": doc["classification"],
            "score": score
        })

    retrieved_ids = {d["id"] for d in retrieved_contexts}
    for doc in docs_to_rank:
        if doc["id"] not in retrieved_ids:
            filtering_logs.append({
                "title": doc["title"],
                "classification": doc["classification"],
                "status": "SKIPPED",
                "reason": f"Similarity score was 0.0 or too low."
            })

    return retrieved_contexts, policy_note, filtering_logs


import time
