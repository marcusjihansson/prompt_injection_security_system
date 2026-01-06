"""
Embedding-Based Anomaly Detector for Jailbreak Pattern Detection

Implements Priority 1 from research plan: Use embeddings + classical ML classifier
to detect jailbreak patterns that evade regex and prompt-based defenses.

Key Features:
- Uses all-MiniLM-L6-v2 embeddings (already in stack)
- Lightweight Random Forest classifier (~10-20MB)
- Fast inference (~10-20ms)
- Catches obfuscated attacks (unicode tricks, paraphrasing, whitespace manipulation)
"""

import logging
import os
import pickle
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


class EmbeddingAnomalyDetector:
    """Detect jailbreak patterns using embedding similarity + classical ML classifier."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        threshold: float = 0.5,
        use_cached_embeddings: bool = True,
    ):
        """
        Initialize the embedding anomaly detector.

        Args:
            model_path: Path to trained classifier model (Random Forest, XGBoost, etc.)
            threshold: Classification threshold (0-1)
            use_cached_embeddings: Whether to cache embeddings for repeated queries
        """
        self.threshold = threshold
        self.use_cached_embeddings = use_cached_embeddings
        self._embedding_model = None
        self._classifier = None
        self._model_path = model_path or self._get_default_model_path()
        self._embedding_cache: Dict[str, np.ndarray] = {}

        # Load classifier if exists
        self._load_classifier()

    def _get_default_model_path(self) -> str:
        """Get default path for trained classifier."""
        return str(Path(__file__).parent / "models" / "jailbreak_classifier.pkl")

    @property
    def embedding_model(self):
        """Lazy-load embedding model (ONNX optimized)."""
        if self._embedding_model is None:
            try:
                from trust.production.models.embeddings_lm import embedding_model

                self._embedding_model = embedding_model()
                logger.info("✅ Loaded ONNX embedding model for anomaly detection")
            except ImportError as e:
                logger.warning(
                    f"⚠️ Failed to import ONNX embedding model: {e}. Embedding anomaly detection disabled."
                )
                return None
            except Exception as e:
                logger.error(f"⚠️ Failed to load ONNX embedding model: {e}")
                return None

        return self._embedding_model

    def _load_classifier(self):
        """Load pre-trained classifier if available."""
        if not os.path.exists(self._model_path):
            logger.warning(
                f"⚠️ No pre-trained classifier found at {self._model_path}. "
                "Detector will use embedding similarity only."
            )
            self._classifier = None
            return

        try:
            with open(self._model_path, "rb") as f:
                self._classifier = pickle.load(f)
            logger.info(f"✅ Loaded jailbreak classifier from {self._model_path}")
        except Exception as e:
            logger.error(f"Failed to load classifier: {e}")
            self._classifier = None

    def _get_embedding(self, text: str) -> Optional[np.ndarray]:
        """Get embedding for text, with optional caching."""
        # Check cache first
        if self.use_cached_embeddings and text in self._embedding_cache:
            return self._embedding_cache[text]

        model = self.embedding_model
        if model is None:
            return None

        try:
            result = model.embed(text)
            embedding = result.embedding

            # Cache if enabled
            if self.use_cached_embeddings:
                # Simple cache management - keep last 1000
                if len(self._embedding_cache) > 1000:
                    # Remove oldest entry (simplified - would use LRU in production)
                    self._embedding_cache.pop(next(iter(self._embedding_cache)))
                self._embedding_cache[text] = embedding

            return embedding
        except Exception as e:
            logger.error(f"Failed to generate embedding: {e}")
            return None

    def detect(self, text: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Detect jailbreak patterns using embeddings.

        Args:
            text: Input text to analyze
            metadata: Additional context

        Returns:
            Detection result with confidence, is_threat, and reasoning
        """
        start_time = time.time()
        metadata = metadata or {}

        # Get embedding
        embedding = self._get_embedding(text)
        if embedding is None:
            return {
                "is_threat": False,
                "confidence": 0.0,
                "method": "embedding_anomaly",
                "reason": "Embedding model unavailable",
                "latency_ms": (time.time() - start_time) * 1000,
            }

        # Strategy 1: Use trained classifier if available
        if self._classifier is not None:
            try:
                confidence = self._classify_with_ml(embedding)
                is_threat = confidence >= self.threshold

                return {
                    "is_threat": is_threat,
                    "confidence": float(confidence),
                    "method": "embedding_anomaly_ml",
                    "reason": (
                        f"ML classifier detected jailbreak pattern (confidence: {confidence:.3f})"
                        if is_threat
                        else "No jailbreak pattern detected"
                    ),
                    "latency_ms": (time.time() - start_time) * 1000,
                }
            except Exception as e:
                logger.error(f"Classifier inference failed: {e}")
                # Fall through to similarity-based detection

        # Strategy 2: Similarity-based detection (fallback or when no classifier)
        result = self._detect_with_similarity(text, embedding, metadata)
        result["latency_ms"] = (time.time() - start_time) * 1000

        return result

    def _classify_with_ml(self, embedding: np.ndarray) -> float:
        """Use trained ML classifier to detect jailbreak patterns."""
        # Reshape for sklearn
        embedding_reshaped = embedding.reshape(1, -1)

        # Get probability of jailbreak class
        if hasattr(self._classifier, "predict_proba"):
            proba = self._classifier.predict_proba(embedding_reshaped)
            # Assuming binary classification: [safe, jailbreak]
            return proba[0][1]
        else:
            # Binary prediction fallback
            prediction = self._classifier.predict(embedding_reshaped)
            return float(prediction[0])

    def _detect_with_similarity(
        self,
        text: str,
        embedding: np.ndarray,
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Fallback: Use embedding similarity to known jailbreak patterns.

        This is a simpler approach when no trained classifier is available.
        Compares input embedding to a library of known jailbreak embeddings.
        """
        # Known jailbreak pattern embeddings (would be loaded from file in production)
        known_patterns = self._get_known_jailbreak_patterns()

        if not known_patterns:
            return {
                "is_threat": False,
                "confidence": 0.0,
                "method": "embedding_anomaly_similarity",
                "reason": "No trained classifier or known patterns available",
            }

        # Calculate similarity to known jailbreaks
        max_similarity = 0.0
        most_similar_pattern = None

        for pattern_name, pattern_embedding in known_patterns.items():
            similarity = self._cosine_similarity(embedding, pattern_embedding)
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar_pattern = pattern_name

        # High similarity to known jailbreak = likely threat
        # Threshold: 0.85 for high confidence
        is_threat = max_similarity >= 0.85

        return {
            "is_threat": is_threat,
            "confidence": float(max_similarity),
            "method": "embedding_anomaly_similarity",
            "reason": (
                f"High similarity ({max_similarity:.3f}) to known jailbreak: {most_similar_pattern}"
                if is_threat
                else f"Low similarity ({max_similarity:.3f}) to known jailbreak patterns"
            ),
            "most_similar_pattern": most_similar_pattern,
        }

    def _cosine_similarity(self, emb1: np.ndarray, emb2: np.ndarray) -> float:
        """Calculate cosine similarity between two embeddings."""
        norm1 = np.linalg.norm(emb1)
        norm2 = np.linalg.norm(emb2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(np.dot(emb1, emb2) / (norm1 * norm2))

    def _get_known_jailbreak_patterns(self) -> Dict[str, np.ndarray]:
        """
        Get embeddings of known jailbreak patterns.

        In production, this would load from a curated dataset.
        For now, returns empty dict - classifier is preferred approach.
        """
        # TODO: Load from file or train using examples from research
        # Examples from DAN, PAIR, prompt injection datasets
        return {}

    def update_classifier(self, X: np.ndarray, y: np.ndarray):
        """
        Train or update the classifier with new data.

        Args:
            X: Feature matrix (embeddings), shape (n_samples, embedding_dim)
            y: Labels (0=safe, 1=jailbreak), shape (n_samples,)
        """
        try:
            from sklearn.ensemble import RandomForestClassifier

            logger.info(f"Training classifier on {len(X)} samples...")

            if self._classifier is None:
                # Initialize new classifier
                self._classifier = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    min_samples_split=5,
                    random_state=42,
                    n_jobs=-1,
                )

            # Train
            self._classifier.fit(X, y)

            # Save
            os.makedirs(os.path.dirname(self._model_path), exist_ok=True)
            with open(self._model_path, "wb") as f:
                pickle.dump(self._classifier, f)

            logger.info(f"✅ Classifier trained and saved to {self._model_path}")

        except ImportError:
            logger.error("scikit-learn not installed. Cannot train classifier.")
        except Exception as e:
            logger.error(f"Failed to train classifier: {e}")

    def prepare_training_data(
        self,
        safe_texts: List[str],
        jailbreak_texts: List[str],
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare training data from text examples.

        Args:
            safe_texts: List of safe/benign prompts
            jailbreak_texts: List of known jailbreak attempts

        Returns:
            (X, y) tuple of embeddings and labels
        """
        model = self.embedding_model
        if model is None:
            raise RuntimeError("Embedding model not available")

        # Generate embeddings
        safe_results = model.embed_batch(safe_texts)
        jailbreak_results = model.embed_batch(jailbreak_texts)
        safe_embeddings = np.array([r.embedding for r in safe_results])
        jailbreak_embeddings = np.array([r.embedding for r in jailbreak_results])

        # Combine
        X = np.vstack([safe_embeddings, jailbreak_embeddings])
        y = np.array([0] * len(safe_texts) + [1] * len(jailbreak_texts))

        logger.info(
            f"Prepared training data: {len(safe_texts)} safe, {len(jailbreak_texts)} jailbreak"
        )

        return X, y


if __name__ == "__main__":
    """Test script to verify classifier loading and basic functionality."""
    import sys

    print("🔍 Testing EmbeddingAnomalyDetector classifier loading...")
    print("=" * 60)

    # Initialize detector
    detector = EmbeddingAnomalyDetector()

    # Check classifier status
    has_classifier = detector._classifier is not None
    model_path = detector._model_path

    print(f"📁 Model path: {model_path}")
    print(f"📊 Classifier loaded: {'✅ YES' if has_classifier else '❌ NO'}")

    if has_classifier:
        print(f"🔧 Classifier type: {type(detector._classifier).__name__}")
        try:
            # Test basic functionality
            test_input = "Hello, this is a test message."
            result = detector.detect(test_input)

            print(
                f"🧪 Test detection result: {result['is_threat']} (confidence: {result['confidence']:.3f})"
            )
            print(f"🎯 Detection method: {result['method']}")
            print("✅ Classifier integration working correctly!")

        except Exception as e:
            print(f"❌ Error during test detection: {e}")
            sys.exit(1)
    else:
        print("ℹ️  Using embedding similarity fallback (no trained classifier)")
        print("💡 To enable classifier, run:")
        print("   python scripts/train_embedding_classifier.py --use-hf")

    print("=" * 60)
    print("🎉 Verification complete!")
