import pytest

from trust.guards.prompt_cache import PromptCache


def test_prompt_cache_get_or_build():
    cache = PromptCache()
    sections = {"system": "Answer", "user": "Question"}
    prompt = cache.get_or_build(sections, lambda s: f"{s['system']} {s['user']}")
    assert prompt == "Answer Question"
    assert cache.size() == 1

    # Cache hit
    prompt2 = cache.get_or_build(sections, lambda s: "Different")
    assert prompt2 == "Answer Question"  # Should return cached


def test_prompt_cache_clear():
    cache = PromptCache()
    sections = {"test": "value"}
    cache.get_or_build(sections, lambda s: "prompt")
    assert cache.size() == 1
    cache.clear()
    assert cache.size() == 0
