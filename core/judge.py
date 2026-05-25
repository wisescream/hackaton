import config
from core import main_llm

def classify_intent(user_query: str) -> dict:
    """
    Classifies the user's intent to detect prompt injection or jailbreak attempts.
    This is triggered for queries identified as having higher risk potential by Input Guard.
    """
    if not user_query or not user_query.strip():
        return {"unsafe": False, "confidence": 1.0, "reason": "Empty query."}

    system_prompt = config.SYSTEM_PROMPT_JUDGE
    
    # We call the JSON parser utility to guarantee structured output
    result = main_llm.call_llm_json(
        system_prompt=system_prompt,
        user_prompt=user_query,
        model_name=config.JUDGE_MODEL
    )
    
    return {
        "unsafe": bool(result.get("unsafe", False)),
        "confidence": float(result.get("confidence", 0.5)),
        "reason": str(result.get("reason", "No reason provided."))
    }
