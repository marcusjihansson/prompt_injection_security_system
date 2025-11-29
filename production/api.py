from fastapi import FastAPI
from pydantic import BaseModel
from production.deploy import ProductionThreatDetector


def create_app(skip_model_setup: bool = True, use_openrouter: bool = False) -> FastAPI:
    """
    Create a FastAPI app for the threat detector service.
    Defaults to offline-friendly configuration (no OpenRouter) for demos.
    """
    app = FastAPI(title="Threat Detection API", version="1.0.0")

    detector = ProductionThreatDetector(
        use_openrouter=use_openrouter,
        enable_regex_baseline=True,
        skip_model_setup=skip_model_setup,
    )

    class DetectionRequest(BaseModel):
        text: str

    class DetectionResponse(BaseModel):
        is_threat: bool
        threat_type: str
        confidence: float
        reasoning: str

    @app.post("/detect", response_model=DetectionResponse)
    async def detect_threat(req: DetectionRequest) -> DetectionResponse:
        result = detector.detect_threat(req.text)
        return DetectionResponse(**result)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "healthy"}

    return app


app = create_app()
