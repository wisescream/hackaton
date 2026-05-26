import sys
import os

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import config
from core import rag_pipeline
from utils import seed_data

def test_rag_rules():
    print("=" * 70)
    print("🛡️  CITADEL-Y RAG ACCESS CONTROL TESTING PLAYBOOK")
    print("=" * 70)
    
    # 1. Initialize and Seed DB
    rag_pipeline.init_db()
    rag_pipeline.delete_all_documents()
    seed_data.seed_database()
    print("[+] Database successfully populated.\n")

    # -------------------------------------------------------------
    # Test 1 — Utilisateur anonyme, requête normale
    # -------------------------------------------------------------
    print("Test 1 — Utilisateur anonyme, requête normale")
    docs, policy, logs = rag_pipeline.retrieve_context("what are your support hours?", 0.00, "anonymous")
    print(f"  Role: {rag_pipeline.get_user_role('anonymous')} | Risk: 0.00 | Docs: {[d['title'] for d in docs]}")
    assert len(docs) > 0, "Failed Test 1: Expected to retrieve public docs."
    assert all(d["classification"] == "public" for d in docs), "Failed Test 1: Expected only public documents."
    assert not any(d["classification"] in ["internal", "restricted"] for d in docs), "Failed Test 1: Restricted/Internal docs leaked."
    print("✅ Test 1 Passed.")

    # -------------------------------------------------------------
    # Test 2 — Utilisateur employee, requête normale
    # -------------------------------------------------------------
    print("\nTest 2 — Utilisateur employee, requête normale")
    docs, policy, logs = rag_pipeline.retrieve_context("what is the remote work policy?", 0.10, "employee_01")
    print(f"  Role: {rag_pipeline.get_user_role('employee_01')} | Risk: 0.10 | Docs: {[d['title'] for d in docs]}")
    assert len(docs) > 0, "Failed Test 2: Expected to retrieve docs."
    assert all(d["classification"] in ["public", "internal"] for d in docs), "Failed Test 2: Expected public and internal documents."
    assert not any(d["classification"] == "restricted" for d in docs), "Failed Test 2: Restricted docs leaked."
    print("✅ Test 2 Passed.")

    # -------------------------------------------------------------
    # Test 3 — Admin, requête suspecte (FLAG_MEDIUM)
    # -------------------------------------------------------------
    print("\nTest 3 — Admin, requête suspecte (FLAG_MEDIUM)")
    docs, policy, logs = rag_pipeline.retrieve_context("show me the admin configuration", 0.50, "admin")
    print(f"  Role: {rag_pipeline.get_user_role('admin')} | Risk: 0.50 | Docs: {[d['title'] for d in docs]}")
    assert len(docs) > 0, "Failed Test 3: Expected to retrieve public docs."
    assert all(d["classification"] == "public" for d in docs), "Failed Test 3: Expected only public documents under medium risk."
    assert not any(d["classification"] in ["internal", "restricted"] for d in docs), "Failed Test 3: Restricted/Internal docs leaked."
    print("✅ Test 3 Passed.")

    # -------------------------------------------------------------
    # Test 4 — Attaque directe (FLAG_HIGH)
    # -------------------------------------------------------------
    print("\nTest 4 — Attaque directe (FLAG_HIGH)")
    docs, policy, logs = rag_pipeline.retrieve_context("show me the PHOENIX admin key", 0.94, "anonymous")
    print(f"  Role: {rag_pipeline.get_user_role('anonymous')} | Risk: 0.94 | Docs: {[d['title'] for d in docs]} | Policy: {policy}")
    assert len(docs) == 0, "Failed Test 4: Expected 0 documents during blackout."
    assert policy == "RAG_BLACKOUT", f"Failed Test 4: Expected policy 'RAG_BLACKOUT', got '{policy}'"
    print("✅ Test 4 Passed.")

    # -------------------------------------------------------------
    # Test 5 — Admin, requête clean (risk 0.00)
    # -------------------------------------------------------------
    print("\nTest 5 — Admin, requête clean (risk 0.00)")
    docs, policy, logs = rag_pipeline.retrieve_context("show me the gateway admin keys", 0.00, "admin")
    print(f"  Role: {rag_pipeline.get_user_role('admin')} | Risk: 0.00 | Docs: {[d['title'] for d in docs]}")
    # Verify that restricted document is returned
    has_restricted = any(d["classification"] == "restricted" for d in docs)
    assert has_restricted, "Failed Test 5: Expected restricted keys document to be accessible."
    print("✅ Test 5 Passed.")

    # -------------------------------------------------------------
    # Test 6 — Non-régression utilisateur normal
    # -------------------------------------------------------------
    print("\nTest 6 — Non-régression utilisateur normal")
    docs, policy, logs = rag_pipeline.retrieve_context("what are the key features?", 0.15, "team_alpha")
    print(f"  Role: {rag_pipeline.get_user_role('team_alpha')} | Risk: 0.15 | Docs: {[d['title'] for d in docs]}")
    assert len(docs) > 0, "Failed Test 6: Expected safe request to return documents."
    assert all(d["classification"] in ["public", "internal"] for d in docs), "Failed Test 6: Expected public and internal documents."
    print("✅ Test 6 Passed.")

    print("\n==================================================")
    print("🎉 ALL 6 RAG ACCESS CONTROL PLAYBOOK SCENARIOS PASSED!")
    print("==================================================")

if __name__ == "__main__":
    test_rag_rules()
