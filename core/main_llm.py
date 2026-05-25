import httpx
import json
import re
import config

def call_live_openrouter(system_prompt: str, user_prompt: str, model: str) -> str:
    """
    Performs a live call to OpenRouter API.
    """
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://citadel-y-guard.local", # Optional
        "X-Title": "Citadel-Y Light Guard" # Optional
    }
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1
    }
    
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.post(url, headers=headers, json=payload)
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"]
            else:
                print(f"OpenRouter Error: Status {response.status_code} - {response.text}")
                return ""
    except Exception as e:
        print(f"OpenRouter Exception: {e}")
        return ""

def call_live_gemini(system_prompt: str, user_prompt: str) -> str:
    """
    Performs a live call to Google Gemini API (using standard developer endpoint).
    """
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={config.GEMINI_API_KEY}"
    headers = {"Content-Type": "application/json"}
    
    # Bundle system instructions inside the chat format or systemInstruction param if supported
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": f"SYSTEM INSTRUCTIONS:\n{system_prompt}\n\nUSER PROMPT:\n{user_prompt}"}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.1
        }
    }
    
    try:
        with httpx.Client(timeout=15.0) as client:
            response = client.post(url, headers=headers, json=payload)
            if response.status_code == 200:
                data = response.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            else:
                print(f"Gemini Error: Status {response.status_code} - {response.text}")
                return ""
    except Exception as e:
        print(f"Gemini Exception: {e}")
        return ""

def call_llm(system_prompt: str, user_prompt: str, model_name: str = None, is_judge: bool = False) -> str:
    """
    Orchestrates live API calling based on API key availability.
    Raises ValueError if no keys are found.
    """
    model = model_name or config.MAIN_MODEL
    
    # 1. Use OpenRouter if key is present
    if config.OPENROUTER_API_KEY:
        res = call_live_openrouter(system_prompt, user_prompt, model)
        if res:
            return res
            
    # 2. Use Gemini if key is present
    if config.GEMINI_API_KEY:
        res = call_live_gemini(system_prompt, user_prompt)
        if res:
            return res
            
    raise ValueError("Configuration Error: No active LLM API keys configured. Please configure OPENROUTER_API_KEY or GEMINI_API_KEY.")

def call_llm_json(system_prompt: str, user_prompt: str, model_name: str = None) -> dict:
    """
    Guarantees a JSON output from the LLM, extremely useful for structural classification.
    """
    raw_response = call_llm(system_prompt, user_prompt, model_name or config.JUDGE_MODEL, is_judge=True)
    
    # Attempt to extract JSON block from markdown fences if returned
    json_match = re.search(r"({.*})", raw_response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except Exception:
            pass
            
    try:
        return json.loads(raw_response)
    except Exception:
        # Fallback dictionary if JSON parsing completely fails on live payload
        return {
            "unsafe": "ignore" in user_prompt.lower() or "jailbreak" in user_prompt.lower(),
            "confidence": 0.50,
            "reason": "Failed to parse LLM judge response; evaluated via rule fallback."
        }

