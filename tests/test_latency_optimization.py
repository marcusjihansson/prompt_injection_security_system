import asyncio
import time

import pytest

from trust import ProductionThreatDetector


def test_caching():
    print("Initializing detector...")
    detector = ProductionThreatDetector(enable_regex_baseline=True)

    input_text = "What is the capital of France?"

    print("\n--- Testing LRU Cache ---")
    # Cold run
    start = time.time()
    detector.detect_threat(input_text)
    cold_time = time.time() - start
    print(f"Cold run: {cold_time:.4f}s")

    # Warm run (LRU hit expected)
    start = time.time()
    detector.detect_threat(input_text)
    warm_time = time.time() - start
    print(f"Warm run: {warm_time:.4f}s")

    if warm_time < cold_time * 0.1:
        print("[SUCCESS] LRU Cache working")
    else:
        print("[WARNING] LRU Cache might not be working effectively")

    print("\n--- Testing Semantic Cache ---")
    # Similar but different text
    similar_text = "What is the capital city of France?"

    # First, ensure semantic cache is populated (it happens in background/during detect_threat)
    # The previous calls should have populated it for the exact match.
    # Let's try a new pair.

    text_a = "Tell me a joke about AI"
    text_b = "Tell me a joke about artificial intelligence"

    # Run text_a
    detector.detect_threat(text_a)

    # Run text_b (should hit semantic cache if threshold is met)
    start = time.time()
    result = detector.detect_threat(text_b)
    sem_time = time.time() - start
    print(f"Semantic run: {sem_time:.4f}s")

    # Note: Semantic cache requires embedding calculation, so it won't be instant like LRU,
    # but should be faster than the full model if the model is slow.
    # Since our local model is small (86M), embedding might be comparable in speed.
    # But let's check if it returns the cached result.

    # Actually, we need to see if cache was hit.
    # metrics["cache_hits"] should increment.
    print(f"Cache hits: {detector.metrics['cache_hits']}")


@pytest.mark.asyncio
async def test_dedup():
    print("\n--- Testing Request Deduplication ---")
    detector = ProductionThreatDetector(enable_regex_baseline=True)
    input_text = "Concurrent Request Test"

    async def make_req():
        return await detector.async_detect(input_text)

    # Launch 5 concurrent requests
    start = time.time()
    results = await asyncio.gather(*[make_req() for _ in range(5)])
    total_time = time.time() - start

    print(f"Processed 5 concurrent requests in {total_time:.4f}s")
    print(f"Total internal processing requests: {detector.metrics['total_requests']}")

    # If dedup works, 'total_requests' should be 1 (or close to 1 if race conditions allowed a few)
    # Ideally 1.
    if detector.metrics["total_requests"] == 1:
        print("[SUCCESS] Request Deduplication working (only 1 internal execution)")
    else:
        print(
            f"[WARNING] Request Deduplication: executed {detector.metrics['total_requests']} times"
        )


if __name__ == "__main__":
    test_caching()
    asyncio.run(test_dedup())
