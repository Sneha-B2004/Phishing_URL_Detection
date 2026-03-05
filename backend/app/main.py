from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.schemas import PredictRequest, PredictResponse
from backend.core.model_loader import get_model
from backend.core.feature_extraction import extract_features

app = FastAPI(title="PhishGuard API", version="1.0")

# For local dev. We can lock this down later.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    model = get_model()

    X = extract_features(req.url)

    risk_score = 0.0
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(X)[0]
        # assumes phishing prob at index 1
        risk_score = float(probs[1])

    pred = model.predict(X)[0]
    status = "LEGITIMATE" if pred == 1 else "PHISHING"

    return PredictResponse(url=req.url, status=status, risk_score=risk_score)