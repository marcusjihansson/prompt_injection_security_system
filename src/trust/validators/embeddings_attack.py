import re
from typing import Any, Dict, List, Optional

from trust.validators.base import OnFailAction, TrustResult, TrustValidator


class EmbeddingSecurityValidator(TrustValidator):
    """Validates vector/embedding security in RAG systems.

    OWASP LLM08:2025 - Vector and Embedding Weaknesses
    Protects against RAG poisoning and embedding attacks.
    """

    def __init__(
        self,
        check_retrieval_relevance: bool = True,
        similarity_threshold: float = 0.5,
        on_fail: OnFailAction = OnFailAction.WARN,
    ):
        super().__init__(
            on_fail=on_fail,
            tags=["owasp-llm08", "rag-security", "embedding-validation"],
        )
        self.check_retrieval_relevance = check_retrieval_relevance
        self.similarity_threshold = similarity_threshold

    def validate(self, value: Any, metadata: Dict) -> TrustResult:
        """Validate RAG pipeline security."""

        issues = []

        # Check retrieved documents for relevance
        if self.check_retrieval_relevance:
            retrieved_docs = metadata.get("retrieved_documents", [])
            query = metadata.get("query", "")

            if retrieved_docs and query:
                irrelevant = self._check_retrieval_quality(query, retrieved_docs)
                if irrelevant:
                    issues.append(f"Low-relevance retrievals: {len(irrelevant)}")

        # Check for adversarial embeddings
        if "embeddings" in metadata:
            if self._detect_adversarial_embedding(metadata["embeddings"]):
                issues.append("Adversarial embedding detected")

        # Check document source integrity
        for doc in metadata.get("retrieved_documents", []):
            if not doc.get("source_verified", True):
                issues.append(f"Unverified source: {doc.get('source', 'unknown')}")

        if issues:
            return TrustResult(
                outcome="fail",
                validator_name=self.name,
                error_message=f"Embedding security issues: {issues}",
                metadata={"issues": issues, "owasp_category": "LLM08"},
            )

        return TrustResult(
            outcome="pass",
            validator_name=self.name,
            metadata={"owasp_category": "LLM08"},
        )

    def _check_retrieval_quality(self, query: str, retrieved_docs: List[Dict]) -> List[int]:
        """Check if retrieved documents are actually relevant."""
        if self._resources is None:
            from sentence_transformers import SentenceTransformer, util

            self._resources = SentenceTransformer("all-MiniLM-L6-v2")

        query_embedding = self._resources.encode(query, convert_to_tensor=True)
        irrelevant_indices = []

        for idx, doc in enumerate(retrieved_docs):
            doc_text = doc.get("content", doc.get("text", ""))
            doc_embedding = self._resources.encode(doc_text, convert_to_tensor=True)

            from sentence_transformers import util

            similarity = util.cos_sim(query_embedding, doc_embedding).item()

            if similarity < self.similarity_threshold:
                irrelevant_indices.append(idx)

        return irrelevant_indices

    def _detect_adversarial_embedding(self, embeddings: List[float]) -> bool:
        """Detect adversarially crafted embeddings."""
        import numpy as np

        # Check for statistical anomalies
        embedding_array = np.array(embeddings)

        # Unusually high/low values
        if np.any(np.abs(embedding_array) > 10.0):
            return True

        # Check for uniform distributions (synthetic)
        std = np.std(embedding_array)
        if std < 0.01:  # Too uniform
            return True

        return False
