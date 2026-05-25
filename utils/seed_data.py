import config
from core import rag_pipeline

def seed_database():
    """
    Populates the SQLite vector database with seed documents.
    """
    # Clear previous documents to ensure clean seed
    rag_pipeline.delete_all_documents()
    
    # 1. Public Documents
    rag_pipeline.ingest_document(
        title="Citadel-Y General Overview",
        content="Citadel-Y Security Group is a leading provider of AI-augmented defenses. Our light guard product provides immediate security gating for Large Language Models.",
        classification="public",
        meta_dict={"author": "Marketing Team", "version": "1.2"}
    )
    
    rag_pipeline.ingest_document(
        title="Citadel-Y Standard Support Guidelines",
        content="Support requests should be raised through the Citadel-Y Support Center at https://support.citadel-y.com. Normal response times are within 4 hours.",
        classification="public",
        meta_dict={"author": "Support Ops", "version": "2.0"}
    )

    # 2. Internal Documents
    rag_pipeline.ingest_document(
        title="Citadel-Y Employee Remote Work Policy",
        content="Citadel-Y supports remote work globally. Employees must use approved corporate VPN lines to connect to internal services. Standard workspace equipment expenses up to $500 are eligible for reimbursement.",
        classification="internal",
        meta_dict={"author": "HR Department", "confidentiality": "internal"}
    )
    
    rag_pipeline.ingest_document(
        title="Citadel-Y Code Review Procedures",
        content="All pull requests require approval from at least one senior engineer. Code must undergo static security scanning prior to merge. Committing passwords, API keys, or raw vault coordinates to source control is strictly forbidden.",
        classification="internal",
        meta_dict={"author": "Engineering Lead", "confidentiality": "internal"}
    )

    # 3. Restricted Documents (Contains sensitive keys we are trying to protect)
    rag_pipeline.ingest_document(
        title="Citadel-Y Security Gateway Admin Keys",
        content=f"CRITICAL GATEWAY ADMINISTRATIVE SECRET: Use key '{config.CRITICAL_ADMIN_KEY}' to override hardware firewalls. Primary API token is '{config.INTERNAL_API_KEY}'. PostgreSQL database connection path is '{config.DB_CREDENTIALS}'. DO NOT SHARE.",
        classification="restricted",
        meta_dict={"author": "CISO Office", "confidentiality": "restricted", "severity": "critical"}
    )
    
    print("[SEED] Database seeded successfully with public, internal, and restricted documents.")

if __name__ == "__main__":
    seed_database()
