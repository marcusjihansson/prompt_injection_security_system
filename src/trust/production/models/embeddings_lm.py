from dataclasses import dataclass
from functools import lru_cache

import numpy as np
from optimum.onnxruntime import ORTModelForFeatureExtraction
from transformers.models.auto.tokenization_auto import AutoTokenizer


@dataclass
class EmbeddingResult:
    embedding: np.ndarray
    model_name: str


class EmbeddingModel:
    def __init__(
        self,
        model_id: str = "sentence-transformers/all-MiniLM-L6-v2",
        use_gpu: bool = False,
        cache_size: int = 1024,
    ):
        self.tokenizer = AutoTokenizer.from_pretrained(model_id)

        provider = "CUDAExecutionProvider" if use_gpu else "CPUExecutionProvider"

        self.model = ORTModelForFeatureExtraction.from_pretrained(
            model_id,
            export=True,
            provider=provider,
        )

        self.model_name = model_id
        self._cache_size = cache_size

        # Create cached embedding method
        self._cached_embed = lru_cache(maxsize=cache_size)(self._embed_impl)

    def _embed_impl(self, text: str) -> np.ndarray:
        """Implementation that returns cacheable embedding."""
        inputs = self.tokenizer(
            text,
            return_tensors="np",
            truncation=True,
            max_length=512,
            padding=True,
        )

        outputs = self.model(**inputs)
        # For sentence transformers, we typically use mean pooling
        embeddings = outputs.last_hidden_state
        # Simple mean pooling over sequence length
        embedding = np.mean(embeddings, axis=1)
        # Normalize
        embedding = embedding / np.linalg.norm(embedding, axis=1, keepdims=True)

        return embedding[0]  # Return first (and only) embedding

    def embed(self, text: str) -> EmbeddingResult:
        """
        Generate embedding for input text.

        Args:
            text: The input text to embed.

        Returns:
            EmbeddingResult with embedding vector and model name.
        """
        embedding = self._cached_embed(text)
        return EmbeddingResult(
            embedding=embedding,
            model_name=self.model_name,
        )

    def embed_batch(self, texts: list[str]) -> list[EmbeddingResult]:
        """
        Batch embedding for multiple texts.

        Args:
            texts: List of input texts to embed.

        Returns:
            List of EmbeddingResult objects.
        """
        inputs = self.tokenizer(
            texts,
            return_tensors="np",
            truncation=True,
            max_length=512,
            padding=True,
        )

        outputs = self.model(**inputs)
        embeddings = outputs.last_hidden_state

        # Mean pooling
        embeddings = np.mean(embeddings, axis=1)
        # Normalize
        embeddings = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)

        results = []
        for i, embedding in enumerate(embeddings):
            results.append(
                EmbeddingResult(
                    embedding=embedding,
                    model_name=self.model_name,
                )
            )

        return results

    def clear_cache(self):
        """Clear the embedding cache."""
        self._cached_embed.cache_clear()

    def cache_info(self):
        """Get cache statistics."""
        return self._cached_embed.cache_info()


_embedding_model_instance = None


def embedding_model(use_gpu: bool = False) -> EmbeddingModel:
    """
    Singleton factory function to return an EmbeddingModel instance.
    Loads the model only once.
    """
    global _embedding_model_instance
    if _embedding_model_instance is None:
        _embedding_model_instance = EmbeddingModel(use_gpu=use_gpu)
    return _embedding_model_instance


if __name__ == "__main__":
    model = embedding_model()

    # Single embedding
    text = "This is a test sentence for embedding."
    result = model.embed(text)
    print(f"Text: {text}")
    print(f"Embedding shape: {result.embedding.shape}")
    print(f"Model: {result.model_name}")
    print()

    # Batch embedding
    texts = [
        "Hello, how are you?",
        "This is another test sentence.",
        "Sentence transformers are useful for NLP tasks.",
    ]
    results = model.embed_batch(texts)

    print("Batch Results:")
    for text, result in zip(texts, results):
        print(f"  '{text[:30]}...' -> shape {result.embedding.shape}")
