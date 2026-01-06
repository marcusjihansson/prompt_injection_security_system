import dspy

from trust.guards.input_guard import SelfLearningShield
from trust.production.detectors.detector import ProductionThreatDetector
from trust.production.models.ml import create_input_guard_from_optimized


class Trust(ProductionThreatDetector):
    """
    Enhanced Unified Chain of Trust interface with research-based security improvements.

    Implements 4 priorities from research plan:
    1. Embedding-based anomaly detection (+20-40% attack detection)
    2. Confidence-based routing (60-70% latency reduction)
    3. Ensemble disagreement detection (adversarial robustness)
    4. Spotlighting/delimiter-based prompts (98% injection prevention)

    Features:
    - Multi-layer detection with confidence-based routing
    - Embedding anomaly detection for obfuscated attacks
    - Ensemble disagreement tracking for adversarial attacks
    - Spotlighting for prompt injection prevention
    - Optimized DSPy detectors for fast, accurate input validation
    - Enhanced output guards with semantic analysis
    - Production-ready with comprehensive error handling

    Usage:
        my_bot = dspy.ChainOfThought("question -> answer")
        trusted_bot = Trust(my_bot)  # All enhanced features enabled by default
        result = trusted_bot("What is the capital of France?")

    Advanced Usage:
        # Customize feature set
        trusted_bot = Trust(
            my_bot,
            enable_embedding_detector=True,
            enable_confidence_routing=True,
            enable_ensemble_analysis=True,
            enable_spotlighting=True
        )

        # High-performance mode (minimal features for speed)
        trusted_bot = Trust(my_bot, fast_mode=True)
    """

    def __init__(
        self,
        target_module,
        fast_mode: bool = False,
        # Enhanced features (all enabled by default for maximum security)
        enable_embedding_detector: bool = True,
        enable_confidence_routing: bool = True,
        enable_ensemble_analysis: bool = True,
        enable_spotlighting: bool = True,
        enable_regex_baseline: bool = True,
        use_optimized_detector: bool = True,
        **kwargs,
    ):
        """
        Initialize enhanced Trust wrapper.

        Args:
            target_module: DSPy module to wrap with security
            fast_mode: Disable heavy features for maximum speed
            enable_embedding_detector: Enable embedding-based anomaly detection
            enable_confidence_routing: Enable confidence-based layer routing
            enable_ensemble_analysis: Enable ensemble disagreement detection
            enable_spotlighting: Enable delimiter-based prompt protection
            enable_regex_baseline: Enable fast regex-based detection
            use_optimized_detector: Use GEPA-optimized DSPy detector
        """
        # Configure features based on fast_mode
        if fast_mode:
            # Minimal features for speed
            enable_embedding_detector = False
            enable_ensemble_analysis = False
            enable_spotlighting = False
            enable_confidence_routing = True  # Keep routing for speed benefits

        # Initialize the enhanced ProductionThreatDetector with all features
        super().__init__(
            enable_regex_baseline=enable_regex_baseline,
            use_optimized_detector=use_optimized_detector,
            enable_embedding_detector=enable_embedding_detector,
            enable_confidence_routing=enable_confidence_routing,
            enable_ensemble_analysis=enable_ensemble_analysis,
            enable_spotlighting=enable_spotlighting,
            **kwargs,
        )

        self.target_module = target_module

        # Enhanced Core Logic with Spotlighting Integration
        def enhanced_core_logic_adapter(input_text):
            """Enhanced core logic with spotlighting and better error handling."""
            try:
                # Try common DSPy patterns
                if hasattr(self.target_module, "__call__"):
                    try:
                        pred = self.target_module(question=input_text)
                    except TypeError:
                        try:
                            pred = self.target_module(input=input_text)
                        except TypeError:
                            pred = self.target_module(input_text)
                else:
                    return f"Error: Target module not callable"

                # Enhanced text extraction with more field support
                if hasattr(pred, "answer"):
                    return str(pred.answer)
                elif hasattr(pred, "response"):
                    return str(pred.response)
                elif hasattr(pred, "output"):
                    return str(pred.output)
                elif hasattr(pred, "result"):
                    return str(pred.result)
                elif hasattr(pred, "text"):
                    return str(pred.text)
                elif hasattr(pred, "content"):
                    return str(pred.content)
                elif hasattr(pred, "keys") and callable(getattr(pred, "keys", None)):
                    # Dict-like object, get last meaningful field
                    keys = list(pred.keys())
                    for key in reversed(keys):
                        if key not in ["question", "input", "prompt"]:
                            return str(pred[key])
                    return str(pred)
                else:
                    return str(pred)

            except Exception as e:
                return f"Error executing target module: {str(e)}"

        # Setup input guard - use enhanced detection pipeline
        input_guard = self.detect_threat  # Use the enhanced detect_threat method

        # Output Guard is already configured in parent class
        # Additional configuration can be done here if needed

        # Initialize enhanced shield with parallel execution
        self.shield = SelfLearningShield(
            input_guard=input_guard,
            core_logic=enhanced_core_logic_adapter,
            output_guard=self.output_guard,
            parallel_execution=not fast_mode,  # Parallel in normal mode, sequential in fast mode
        )

        # Log configuration
        features_enabled = []
        if enable_embedding_detector:
            features_enabled.append("embedding")
        if enable_confidence_routing:
            features_enabled.append("routing")
        if enable_ensemble_analysis:
            features_enabled.append("ensemble")
        if enable_spotlighting:
            features_enabled.append("spotlighting")
        if enable_regex_baseline:
            features_enabled.append("regex")
        if use_optimized_detector:
            features_enabled.append("optimized")

        print(f"🔧 Enhanced Trust initialized with features: {', '.join(features_enabled)}")

    def process_request(self, input_text: str):
        """
        Enhanced Chain of Trust Pipeline with Spotlighting:
        Input Guard -> Core Logic -> Output Guard.
        Returns a dict with response and trust status.
        """
        # Apply spotlighting if enabled
        if self.enable_spotlighting and self.spotlighter:
            # Create a basic system prompt for spotlighting
            system_prompt = (
                "You are a helpful AI assistant. Answer user questions accurately and safely."
            )
            spotlighted = self.spotlighter.apply(system_prompt, input_text)
            if spotlighted["escape_detection"]["is_safe"] is False:
                self.metrics["spotlighting_applied"] += 1
                return {
                    "response": "Request blocked due to prompt injection attempt",
                    "trust_status": "blocked",
                    "reason": f"Spotlighting detected: {spotlighted['escape_detection'].get('reason', 'escape attempt')}",
                    "confidence": 0.95,
                }

        return self.shield.predict(user_input=input_text)

    def __call__(self, input_text):
        return self.process_request(input_text)

    def forward(self, input_text):
        return self.process_request(input_text)
