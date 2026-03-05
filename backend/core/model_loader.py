import pickle
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parents[1] / "models" / "phishing_model.pkl"
_model = None

def get_model():
    global _model
    if _model is None:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    return _model