import dspy

from trust import Trust


# Simple Chain of Thought module
class SimpleQA(dspy.Module):
    def __init__(self):
        super().__init__()
        self.prog = dspy.ChainOfThought("question -> answer")

    def forward(self, question):
        return self.prog(question=question)


def main():
    print("Testing dspy.Trust wrapper...")

    # Initialize the user module
    my_bot = SimpleQA()

    # Wrap it with Chain of Trust (this uses the monkeypatched class)
    # Note: We use skip_model_setup=True to avoid needing API keys for this simple test
    # In a real scenario, you'd configure dspy.LM first.
    try:
        trusted_bot = dspy.Trust(my_bot, skip_model_setup=True)
        print("[SUCCESS] Successfully initialized dspy.Trust wrapper")
    except AttributeError:
        # If monkeypatching failed or isn't visible yet (e.g. import order), fall back to direct import
        print("[WARNING] dspy.Trust not found on module, using direct class")
        trusted_bot = Trust(my_bot, skip_model_setup=True)

    # Mock the internal detector for this test since we don't have a model loaded
    trusted_bot._detect_threat_internal = lambda x: {
        "is_threat": False,
        "reasoning": "Mock safe",
    }

    # Mock the output guard for this test
    trusted_bot.output_guard.validate = lambda m, u, s: type("obj", (object,), {"is_safe": True})

    # Test the call
    input_text = "What is the capital of France?"
    print(f"Input: {input_text}")

    # We need to mock the target module execution too since we have no LM
    my_bot.forward = lambda question: "Paris"

    result = trusted_bot(input_text)
    print(f"Result: {result}")

    if result["is_trusted"] and result["response"] == "Paris":
        print("[SUCCESS] dspy.Trust wrapper functioning correctly")
    else:
        print("[FAIL] Wrapper failed verification")


if __name__ == "__main__":
    main()
