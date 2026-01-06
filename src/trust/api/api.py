import asyncio
from typing import List

from fastapi import FastAPI
from pydantic import BaseModel

from trust.guards.output_guard import OutputGuard
from trust.production.detectors.detector import ProductionThreatDetector


def create_app(enable_regex_baseline: bool = True) -> FastAPI:
    """
    Create a FastAPI app for the threat detector service.
    """
    app = FastAPI(title="Threat Detection API", version="2.0.0")

    # Initialize detector with new optimizations
    detector = ProductionThreatDetector(
        enable_regex_baseline=enable_regex_baseline,
        use_optimized_detector=True,  # Enable optimized DSPy detectors
    )

    # Initialize enhanced OutputGuard
    output_guard = OutputGuard(
        use_llm=False,  # Keep DSPy optional for API service
        use_llm_guard=True,  # Enable Llama-Guard-3-1B-INT4
        strict_mode=True,  # Enhanced validation
        confidence_threshold=0.8,  # Tunable confidence
    )

    class DetectionRequest(BaseModel):
        text: str

    class BatchDetectionRequest(BaseModel):
        texts: List[str]

    class DetectionResponse(BaseModel):
        is_threat: bool
        threat_type: str
        confidence: float
        reasoning: str

    class OutputValidationRequest(BaseModel):
        text: str
        original_input: str = ""  # Optional context

    class OutputValidationResponse(BaseModel):
        safe: bool
        violation_type: str
        confidence: float
        violation_details: str
        matches: List[str] = []

    @app.post("/detect", response_model=DetectionResponse)
    async def detect_threat(req: DetectionRequest) -> DetectionResponse:
        """Detect threat in a single text (uses deduplication)"""
        result = await detector.async_detect(req.text)
        return DetectionResponse(**result)

    @app.post("/detect/batch", response_model=List[DetectionResponse])
    async def detect_threats_batch(
        req: BatchDetectionRequest,
    ) -> List[DetectionResponse]:
        """Batch detection with concurrent processing"""
        # Process in parallel
        tasks = [detector.async_detect(t) for t in req.texts]
        results = await asyncio.gather(*tasks)
        return [DetectionResponse(**r) for r in results]

    @app.post("/validate/output", response_model=OutputValidationResponse)
    async def validate_output(req: OutputValidationRequest) -> OutputValidationResponse:
        """Validate LLM output for safety violations"""
        result = output_guard.validate(model_output=req.text, original_input=req.original_input)

        return OutputValidationResponse(
            safe=result.is_safe,
            violation_type=result.violation_type.value,
            confidence=result.confidence,
            violation_details=result.violation_details,
            matches=result.matches,
        )

    @app.post("/validate/pipeline")
    async def validate_pipeline(req: DetectionRequest) -> dict:
        """Complete pipeline validation: input → LLM processing → output"""
        # Step 1: Input validation
        input_result = await detector.async_detect(req.text)

        if input_result["is_threat"]:
            return {
                "safe": False,
                "blocked_at": "input",
                "input_validation": input_result,
                "message": "Input blocked for security reasons",
            }

        # Step 2: Simulate LLM processing (in real usage, this would be your LLM call)
        # For API demo, we'll use a placeholder response
        simulated_llm_output = f"Processed: {req.text}"

        # Step 3: Output validation
        output_result = output_guard.validate(
            model_output=simulated_llm_output, original_input=req.text
        )

        if not output_result.is_safe:
            return {
                "safe": False,
                "blocked_at": "output",
                "input_validation": input_result,
                "output_validation": {
                    "safe": output_result.is_safe,
                    "violation_type": output_result.violation_type.value,
                    "confidence": output_result.confidence,
                    "violation_details": output_result.violation_details,
                },
                "message": "Output blocked for security reasons",
            }

        return {
            "safe": True,
            "input_validation": input_result,
            "output_validation": {
                "safe": output_result.is_safe,
                "violation_type": output_result.violation_type.value,
                "confidence": output_result.confidence,
            },
            "simulated_response": simulated_llm_output,
            "message": "Pipeline validation passed",
        }

    @app.get("/health")
    async def health() -> dict:
        return {"status": "healthy", "metrics": detector.metrics}

    return app


app = create_app()
