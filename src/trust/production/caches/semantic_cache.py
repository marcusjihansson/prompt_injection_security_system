import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


class SemanticCache:
    """Cache threat detection results by semantic similarity"""

    def __init__(self, similarity_threshold=0.95, max_size=1000):
        self.threshold = similarity_threshold
        # List of (embedding, result, timestamp) tuples
        self.cache: List[Tuple[np.ndarray, Dict[str, Any], float]] = []
        self.max_size = max_size
        self._embedding_model = None

    @property
    def embedding_model(self):
        if self._embedding_model is None:
            try:
                # Lazy load lightweight embedding model
                from sentence_transformers import SentenceTransformer

                # Using a very small, fast model
                self._embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
                logger.info("✅ Loaded semantic cache embedding model")
            except ImportError:
                logger.warning("⚠️ sentence-transformers not installed. Semantic cache disabled.")
                self._embedding_model = None
            except Exception as e:
                logger.error(f"⚠️ Failed to load embedding model: {e}")
                self._embedding_model = None

        return self._embedding_model

    def get(self, text: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached result if semantically similar input exists"""
        model = self.embedding_model
        if model is None or not self.cache:
            return None

        start_time = time.time()
        try:
            query_emb = model.encode(text, convert_to_numpy=True)

            # Linear scan is fast enough for size < 5000
            # For larger sizes, would use FAISS or similar
            best_sim = -1.0
            best_result = None

            for cached_emb, result, _ in self.cache:
                # Cosine similarity
                query_norm = np.linalg.norm(query_emb)
                cached_norm = np.linalg.norm(cached_emb)

                # Avoid division by zero
                if query_norm == 0 or cached_norm == 0:
                    similarity = 0.0
                else:
                    similarity = np.dot(query_emb, cached_emb) / (query_norm * cached_norm)

                if similarity > best_sim:
                    best_sim = similarity
                    best_result = result

            if best_sim >= self.threshold:
                logger.debug(f"Semantic cache hit: {best_sim:.4f} similarity")
                return best_result

        except Exception as e:
            logger.error(f"Error in semantic cache lookup: {e}")

        return None

    def set(self, text: str, result: Dict[str, Any]):
        """Cache a result"""
        model = self.embedding_model
        if not model:
            return

        try:
            embedding = model.encode(text, convert_to_numpy=True)

            if len(self.cache) >= self.max_size:
                self.cache.pop(0)  # FIFO eviction for simplicity

            self.cache.append((embedding, result, time.time()))

        except Exception as e:
            logger.error(f"Error setting semantic cache: {e}")
