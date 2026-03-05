from pydantic import BaseModel

class PredictRequest(BaseModel):
    url: str

class PredictResponse(BaseModel):
    url: str
    status: str          # LEGITIMATE or PHISHING
    risk_score: float    # 0.0 to 1.0