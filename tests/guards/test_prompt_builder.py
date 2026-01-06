import pytest

from trust.guards.primitives import SecureField, TrustLevel
from trust.guards.prompt_builder import SecurePromptBuilder


def test_secure_prompt_builder_xml():
    builder = SecurePromptBuilder()
    fields = {
        "system": (SecureField("instruction", TrustLevel.SYSTEM), "Answer questions."),
        "user": (SecureField("query", TrustLevel.USER), "What is <AI>?"),
    }
    prompt = builder.build(fields)
    assert "<system_instructions>" in prompt
    assert "<user_input_zone>" in prompt
    assert "&lt;" in prompt  # Escaped XML


# Note: SecurePromptBuilder only supports XML style currently
