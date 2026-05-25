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
    Each document is a dict: {"id": id, "content": text, ...}
    Returns a sorted list of documents with their score: [(doc, score), ...]
    """
    query_tokens = tokenize(query)
    if not query_tokens:
        return [(doc, 0.0) for doc in documents]

    # Calculate corpus statistics
    corpus_tokens = [tokenize(doc["content"]) for doc in documents]
    num_docs = len(documents)
    
    # Vocabulary & Document Frequency (DF)
    df = {}
    for tokens in corpus_tokens:
        unique_tokens = set(tokens)
        for t in unique_tokens:
            df[t] = df.get(t, 0) + 1

    # TF-IDF of the query
    query_tf = {}
    for t in query_tokens:
        query_tf[t] = query_tf.get(t, 0) + 1
        
    query_tfidf = {}
    query_norm = 0.0
    for t, tf in query_tf.items():
        # Calculate Inverse Document Frequency (IDF)
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

        # Dot product
        dot_product = 0.0
        for t in query_tokens:
            if t in doc_tfidf:
                dot_product += query_tfidf[t] * doc_tfidf[t]
                
        cosine_sim = dot_product / (query_norm * doc_norm)
        scored_docs.append((doc, round(cosine_sim, 4)))

    # Sort descending by score
    return sorted(scored_docs, key=lambda x: x[1], reverse=True)


# --- RAG PIPELINE INTERFACE ---
def init_db():
    """Initializes the SQLite database for document storage."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            original_content TEXT NOT NULL,
            content TEXT NOT NULL,
            classification TEXT NOT NULL, -- public, internal, restricted
            metadata TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def sanitize_content(text: str) -> str:
    """
    Sanitizes documents prior to ingestion.
    - Suppresses secrets (regex-based matching)
    - Strips injection instructions (e.g. system commands)
    """
    sanitized = text
    # 1. Redact defined DLP secrets
    for name, pattern in config.DLP_PATTERNS.items():
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)

    # Also make sure the specific critical config secrets are redacted if they match
    sanitized = sanitized.replace(config.CRITICAL_ADMIN_KEY, "[REDACTED_SECRET]")
    sanitized = sanitized.replace(config.INTERNAL_API_KEY, "[REDACTED_SECRET]")
    sanitized = sanitized.replace(config.DB_CREDENTIALS, "[REDACTED_SECRET]")

    # 2. Prevent indirect prompt injections inside documents:
    # Strip keywords that look like system orders to prevent RAG poisoning
    indirect_injection_terms = ["ignore previous", "you are now", "developer mode", "system prompt"]
    for term in indirect_injection_terms:
        # Case insensitive replacement with warning tag
        sanitized = re.sub(rf"\b{term}\b", f"[INJECTION_ATTEMPT_REMOVED]", sanitized, flags=re.IGNORECASE)

    return sanitized

def ingest_document(title: str, content: str, classification: str = "public", meta_dict: dict = None) -> int:
    """
    Ingests and sanitizes a document into the SQLite RAG database.
    """
    init_db()
    sanitized_text = sanitize_content(content)
    
    meta_dict = meta_dict or {}
    meta_dict["classification"] = classification
    meta_json = json.dumps(meta_dict)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO documents (title, original_content, content, classification, metadata) VALUES (?, ?, ?, ?, ?)",
        (title, content, sanitized_text, classification, meta_json)
    )
    doc_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return doc_id

def delete_all_documents():
    """Wipes the RAG database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM documents")
    conn.commit()
    conn.close()

def get_all_documents() -> list:
    """Retrieves all documents currently in the RAG database."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, original_content, content, classification, metadata FROM documents")
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
            "metadata": json.loads(r[5])
        })
    return docs

def retrieve_context(query: str, risk_score: float) -> tuple:
    """
    Retrieves the top_k relevant contexts based on similarity and the computed risk score.
    Returns: (retrieved_contexts, policy_note, filtering_logs)
    
    🔐 SECURITY ADAPTATION RULES:
    - 🟢 LOW RISK (< 0.35): Access to public & internal docs. Restricted docs are redacted.
    - 🟡 MEDIUM RISK (>= 0.35): Strict public-only search. Internal & Restricted files are filtered.
    - 🔴 HIGH RISK (>= 0.70): Entire document safe is blacked out. Zero retrieval.
    """
    init_db()
    filtering_logs = []
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, content, classification, original_content FROM documents")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return [], "No documents in RAG database.", [{"title": "N/A", "classification": "N/A", "status": "EMPTY", "reason": "No documents found."}]

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
        policy_note = "🟡 ADAPTIVE SECURITY ACTIVE: Medium-risk query. Search restricted to public database only."
    else:
        allowed_classifications = ["public", "internal", "restricted"]
        policy_note = "🟢 STANDARD SECURITY ACTIVE: Low-risk query. Search includes all documents."

    docs_to_rank = []
    for r in rows:
        doc_id, title, content, doc_class, original_content = r
        
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
            "original_content": original_content
        })

    if not docs_to_rank:
        return [], f"{policy_note} (All documents filtered)", filtering_logs

    # Rank documents using similarity
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
            "reason": f"Match Score {score} | {reason}"
        })
        
        retrieved_contexts.append({
            "id": doc["id"],
            "title": doc["title"],
            "content": text_to_inject,
            "classification": doc["classification"],
            "score": score
        })

    # Record any un-retrieved but allowed documents as bypassed due to low similarity
    retrieved_ids = {d["id"] for d in retrieved_contexts}
    for doc in docs_to_rank:
        if doc["id"] not in retrieved_ids:
            filtering_logs.append({
                "title": doc["title"],
                "classification": doc["classification"],
                "status": "SKIPPED",
                "reason": f"Similarity score was 0.0 or too low to rank in top 3."
            })

    return retrieved_contexts, policy_note, filtering_logs
