# prompt_cache.py

import hashlib
import json
from typing import Any, Dict


class PromptCache:
    """Caches fully constructed prompts keyed by their content and trust-level layout."""

    def __init__(self):
        self._cache = {}  # cache_key : prompt_str

    def _compute_cache_key(self, sections: Dict[str, Any]) -> str:
        """Create a stable hash from all relevant trust-level fields and values."""
        # Canonicalize: sort keys, dump as json, then hash
        canonical = json.dumps(sections, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def get_or_build(self, sections: Dict[str, Any], build_func) -> str:
        """
        - sections: dict of prompt fields (ideally including trust level)
        - build_func: function to call to generate prompt string if not cached
        Returns prompt string, caching it for identical key in future.
        """
        key = self._compute_cache_key(sections)
        if key in self._cache:
            return self._cache[key]
        prompt = build_func(sections)
        self._cache[key] = prompt
        return prompt

    def clear(self):
        """Clear the entire cache."""
        self._cache.clear()

    def size(self) -> int:
        return len(self._cache)
