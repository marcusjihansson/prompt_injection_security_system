import time

import dspy

from trust import Trust


# Mock module that simulates latency
class SlowQA(dspy.Module):
    def __init__(self, delay=1.0):
        super().__init__()
        self.delay = delay
        self.prog = dspy.ChainOfThought("question -> answer")

    def forward(self, question):
        time.sleep(self.delay)
        return self.prog(question=question)


def main():
    print("Testing Latency Optimization...")

    # Mock Input Guard latency in the wrapper via a subclass hook or just knowing
    # ProductionThreatDetector uses regex (fast) + detector (slow)
    # For this test, we assume the detector is mocked to be slow if we could,
    # but we can at least verify parallel execution logic works.

    slow_bot = SlowQA(delay=2.0)

    # Initialize Trusted Bot
    # skip_model_setup=True because we don't have real keys
    trusted_bot = dspy.Trust(slow_bot, skip_model_setup=True)

    # Mock internal components
    # Mock Input Guard to take 1.5s
    original_detect = trusted_bot._detect_threat_internal

    def slow_guard(text):
        time.sleep(1.5)
        return {"is_threat": False, "reasoning": "Safe"}

    trusted_bot._detect_threat_internal = slow_guard

    # Update shield to use new mock
    trusted_bot.shield.input_guard = slow_guard

    # Mock Core Logic (in adapter)
    # The adapter calls slow_bot, which sleeps 2.0s
    # We need to patch the target module's forward method to return a dummy prediction
    slow_bot.prog = lambda question: type("obj", (object,), {"answer": "Paris"})

    # Mock Output Guard (fast)
    trusted_bot.output_guard.validate = lambda m, u, s: type("obj", (object,), {"is_safe": True})

    print("Running with Speculative Execution (Parallel)...")
    start = time.time()
    result = trusted_bot("test input")
    duration = time.time() - start

    print(f"Total Duration: {duration:.2f}s")

    # Expected: max(1.5, 2.0) + overhead ~ 2.0s + overhead
    # Sequential would be 1.5 + 2.0 = 3.5s

    if duration < 3.0:
        print("[SUCCESS] Parallel execution verified! (Saved ~1.5s)")
    else:
        print("[FAIL] Looks sequential (Too slow)")

    print("\nTesting Fast Mode...")
    fast_bot = dspy.Trust(slow_bot, skip_model_setup=True, fast_mode=True)
    if fast_bot.output_guard.llm_guard.use_dspy is False:
        print("[SUCCESS] Fast Mode verified (LLM Output Guard disabled)")
    else:
        print("[FAIL] Fast Mode failed")


if __name__ == "__main__":
    main()
