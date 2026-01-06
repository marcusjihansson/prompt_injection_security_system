from fastapi import FastAPI
from pydantic import BaseModel

from trust.production.detectors.detector import ProductionThreatDetector


def create_fastapi_app():
    """Create a FastAPI app for the threat detector service"""
    app = FastAPI(title="Threat Detection API", version="1.0.0")

    # Initialize detector
    # We assume this app is running in an environment where it can access the model/API
    detector = ProductionThreatDetector(enable_regex_baseline=True)

    class DetectionRequest(BaseModel):
        text: str

    class DetectionResponse(BaseModel):
        is_threat: bool
        threat_type: str
        confidence: float
        reasoning: str

    @app.post("/detect", response_model=DetectionResponse)
    async def detect_threat(request: DetectionRequest):
        """Detect threats in the provided text (Legacy Input Guard)"""
        result = detector.detect_threat(request.text)
        return DetectionResponse(**result)

    @app.post("/process")
    async def process_request(request: DetectionRequest):
        """Run full Chain of Trust pipeline (Input -> Core -> Output)"""
        return detector.process_request(request.text)

    @app.get("/health")
    async def health_check():
        """Health check endpoint"""
        return {"status": "healthy"}

    return app


# Expose the app object for uvicorn
app = create_fastapi_app()
