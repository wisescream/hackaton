import os
import sys

# Configure standard streams to utf-8 if reconfigurable
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Global indicators
MODEL_LOADED = False
MODEL = None
MODEL_WARNING = ""

MODEL_PATH = "models/setfit_input_guard"

def init_model():
    global MODEL, MODEL_LOADED, MODEL_WARNING
    if MODEL_LOADED:
        return
    
    if not os.path.exists(MODEL_PATH):
        MODEL_WARNING = f"SetFit model path '{MODEL_PATH}' not found. Sync startup backup triggered."
        print(f"[-] WARNING: {MODEL_WARNING}", file=sys.stderr)
        MODEL_LOADED = False
        return
        
    try:
        from setfit import SetFitModel
        MODEL = SetFitModel.from_pretrained(MODEL_PATH)
        MODEL_LOADED = True
        MODEL_WARNING = ""
        print("[+] SetFit Input Guard model loaded successfully.")
    except Exception as e:
        MODEL_WARNING = f"Failed to load SetFit model: {e}"
        print(f"[-] WARNING: {MODEL_WARNING}", file=sys.stderr)
        MODEL_LOADED = False

# Synchronous startup model initialization
init_model()

def predict(text: str) -> dict:
    """
    Analyzes input query text using fine-tuned SetFit classifier.
    Returns: {"score": float, "label": str, "confident": bool}
    """
    global MODEL, MODEL_LOADED, MODEL_WARNING
    
    if not MODEL_LOADED or MODEL is None:
        return {
            "score": 0.0,
            "label": "safe",
            "confident": False,
            "warning": MODEL_WARNING or "Model not loaded."
        }
        
    try:
        # Run prediction
        probs = MODEL.predict_proba([text])
        prob_malicious = float(probs[0][1])
        
        # Risk score is mapped to the malicious class probability
        score = round(prob_malicious, 4)
        
        # Dead Zone [0.40 - 0.60] check
        confident = not (0.40 <= score <= 0.60)
        
        label = "malicious" if score >= 0.50 else "safe"
        
        return {
            "score": score,
            "label": label,
            "confident": confident,
            "warning": ""
        }
    except Exception as e:
        return {
            "score": 0.0,
            "label": "safe",
            "confident": False,
            "warning": f"Prediction failed: {e}"
        }
