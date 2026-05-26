import sys
import os
import json
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

# Import Citadel-Y components
import config
from core import input_guard, judge, rag_pipeline, main_llm, output_guard
from utils import metrics

async def analyze_prompt(request):
    """
    Endpoint: POST /api/analyze
    JSON Request Body:
    {
      "prompt": "what are the key features?",
      "user": "employee_01",
      "chat_id": "API Session"
    }
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON payload"}, status_code=400)

    prompt = body.get("prompt", "")
    user = body.get("user", "guest_user")
    chat_id = body.get("chat_id", "API Session")

    if not prompt or not prompt.strip():
        return JSONResponse({"error": "Prompt field is required and cannot be empty"}, status_code=400)

    start_time = time.time()

    # Layer 1: Input Guard
    ig_res = input_guard.analyze_input(prompt)
    risk_score = ig_res["risk_score"]
    decision = ig_res["decision"]

    # Layer 2: LLM Judge (triggered on FLAG_MEDIUM or FLAG_HIGH)
    is_blocked = False
    judge_details = "Skipped"
    judge_res = None
    
    if risk_score >= config.RISK_THRESHOLD_MEDIUM:
        judge_res = judge.classify_intent(prompt)
        judge_details = f"Intent classification unsafe: {judge_res['unsafe']} | Confidence {judge_res['confidence']}"
        if judge_res["unsafe"]:
            is_blocked = True

    # Layer 3: Scoped RAG
    # Scoped to the API user id
    retrieved_docs, rag_policy, filtering_logs = rag_pipeline.retrieve_context(prompt, risk_score, user)

    # Layer 4: LLM Principal
    llm_response = ""
    if not is_blocked:
        context_str = "\n\n".join([f"Doc: {d['title']}\n{d['content']}" for d in retrieved_docs])
        system_prompt = config.SYSTEM_PROMPT_PRINCIPAL.format(context=context_str)
        try:
            llm_response = main_llm.call_llm(system_prompt, prompt)
        except Exception as e:
            return JSONResponse({"error": f"LLM Gateway Error: {e}"}, status_code=502)
    else:
        llm_response = f"🚫 CITADEL-Y SECURITY EXCEPTION: Prompt blocked by Judge. Reason: {judge_details}"

    # Layer 5: Output Guard DLP
    dlp_res = {}
    final_response = llm_response
    if not is_blocked:
        dlp_res = output_guard.validate_and_sanitize_output(prompt, llm_response)
        final_response = dlp_res["sanitized_response"]

    # Log query and reply to global SQLite database
    db_status = "safe"
    if is_blocked:
        db_status = "blocked"
    elif dlp_res.get("leak_detected", False):
        db_status = "limited"

    # Save to secure session history
    rag_pipeline.save_chat_message(
        user_id=f"api_{user}",
        chat_id=chat_id,
        role="user",
        content=prompt,
        sanitized_content=prompt,
        risk_score=risk_score,
        status=db_status
    )
    rag_pipeline.save_chat_message(
        user_id=f"api_{user}",
        chat_id=chat_id,
        role="assistant",
        content=final_response,
        sanitized_content=final_response,
        risk_score=0.0,
        status="safe"
    )

    latency = round(time.time() - start_time, 4)

    response_payload = {
        "status": "success",
        "latency_seconds": latency,
        "input_guard": {
            "risk_score": risk_score,
            "decision": decision,
            "attack_type": ig_res["attack_type"],
            "triggers": ig_res["triggers"]
        },
        "llm_judge": {
            "verdict": judge_details,
            "unsafe": judge_res["unsafe"] if judge_res else False,
            "confidence": judge_res["confidence"] if judge_res else 0.0,
            "reason": judge_res["reason"] if judge_res else ""
        },
        "rag_pipeline": {
            "policy": rag_policy,
            "documents_retrieved": [d["title"] for d in retrieved_docs],
            "filtering_logs": filtering_logs
        },
        "output_guard_dlp": {
            "leak_detected": dlp_res.get("leak_detected", False),
            "matched_patterns": dlp_res.get("matched_patterns", []),
            "remediation_steps": dlp_res.get("remediation_steps", [])
        },
        "response": final_response
    }

    return JSONResponse(response_payload)

async def health_check(request):
    """Simple API health-check endpoint."""
    return JSONResponse({
        "status": "healthy",
        "service": "citadel_local_api",
        "time": time.strftime("%Y-%m-%dT%H:%M:%S")
    })

routes = [
    Route("/api/analyze", analyze_prompt, methods=["POST"]),
    Route("/api/health", health_check, methods=["GET"])
]

app = Starlette(debug=True, routes=routes)

@app.on_event("startup")
def startup_event():
    metrics.start_metrics_server(port=8000)
