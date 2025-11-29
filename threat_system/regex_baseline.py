"""
RegexBaseline module for fast threat detection
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
import json
import os
from pathlib import Path

from threat_system.threat_types import ThreatType


@dataclass
class RegexResult:
    threats: Set[ThreatType]
    severity: int  # 0: benign, 1: low/medium, 3: high
    matches: Dict[ThreatType, List[str]]


class RegexBaseline:
    """
    Fast regex-based baseline threat detection.
    Returns threats, severity, and matches for fusion with DSPy detector.
    Includes optional fast substring pre-filters to avoid heavy regex work.
    """

    def __init__(self, patterns_by_type: Optional[Dict[ThreatType, List[str]]] = None, patterns_path: Optional[str] = None):
        if patterns_by_type is None:
            # Try to load external patterns if provided or default file exists
            loaded = None
            path = patterns_path or "threat_system/regex_patterns.json"
            try:
                p = Path(path)
                if p.exists():
                    data = json.loads(p.read_text())
                    loaded = self._from_json(data)
            except Exception:
                loaded = None
            patterns_by_type = loaded or self._default_patterns()
        self.compiled = {
            t: [re.compile(p, re.IGNORECASE) for p in ps]
            for t, ps in patterns_by_type.items()
        }
        # Lightweight fast substrings for early filtering (derived from patterns)
        self.substrings = {
            ThreatType.SYSTEM_PROMPT_ATTACK: ["system prompt", "reveal", "override"],
            ThreatType.AUTH_BYPASS: ["admin", "bypass", "authentication"],
            ThreatType.CODE_INJECTION: ["<script", "eval(", "os.system("],
            ThreatType.DATA_EXFILTRATION: ["database", "user data", "api key"],
        }
        self.high_severity = {
            ThreatType.SYSTEM_PROMPT_ATTACK,
            ThreatType.AUTH_BYPASS,
            ThreatType.CODE_INJECTION,
            ThreatType.DATA_EXFILTRATION,
        }
        # Allow overriding high severity via JSON file
        path = patterns_path or "threat_system/regex_patterns.json"
        try:
            p = Path(path)
            if p.exists():
                data = json.loads(p.read_text())
                hs = data.get("high_severity_types", [])
                if isinstance(hs, list) and hs:
                    mapping = {t.value: t for t in ThreatType}
                    mapping.update({t.name: t for t in ThreatType})
                    self.high_severity = {mapping[x] for x in hs if x in mapping}
        except Exception:
            pass

    def _default_patterns(self) -> Dict[ThreatType, List[str]]:
        """Default regex patterns extracted and simplified from advanced_security.py"""
        return {
            ThreatType.PROMPT_INJECTION: [
                r"(?i)ignore\s+(?:previous|all|your)\s+(?:instructions?|prompts?|rules?)",
                r"(?i)ignore\s+(?:the\s+)?instructions?",
                r"(?i)disregard\s+(?:previous|all|system)\s+(?:instructions?|constraints?)",
                r"(?i)(?:system|assistant)[\s:]*(?:prompt|message|instruction)",
                r"(?i)you\s+are\s+now\s+(?:a|an|the)\s+\w+",
                r"(?i)forget\s+(?:everything|all|your)\s+(?:above|previous|instructions?)",
                r"(?i)new\s+(?:instructions?|task|role|persona)",
                r"(?i)switch\s+to\s+\w+\s+mode",
                r"(?i)act\s+as\s+(?:if|a|an)\s+\w+",
                r"(?i)developer\s+mode",
                r"(?i)jailbreak|bypass|circumvent",
                r"(?i)unrestricted|uncensored|unfiltered",
                r"</?(?:system|instruction|prompt|rules?)>",
                r"(?i)print\s+(?:the|your)\s+(?:prompt|instructions?|system)",
                r"(?i)reveal\s+(?:your|the)\s+(?:prompt|instructions?)",
            ],
            ThreatType.AUTH_BYPASS: [
                r"(?i)(?:admin|root|administrator|superuser)[\s:]+(?:access|login|auth)",
                r"(?i)bypass\s+(?:authentication|authorization|login|security)",
                r"(?i)(?:skip|ignore)\s+(?:auth|login|verification)",
                r"(?i)backdoor|master\s+password|override",
                r"(?i)privilege\s+escalation",
                r"(?i)(?:sudo|su)\s+",
            ],
            ThreatType.DATA_EXFILTRATION: [
                r"(?i)(?:show|display|print|return|give)\s+(?:me\s+)?(?:all\s+)?(?:the\s+)?(?:user|customer|client)\s+(?:data|info|details)",
                r"(?i)database\s+(?:dump|export|backup|content)",
                r"(?i)list\s+(?:all\s+)?(?:users?|customers?|accounts?|emails?)",
                r"(?i)access\s+(?:logs?|records?|files?|database)",
                r"\b(?:ssn|social\s+security|tax\s+id)[\s:]\s*\d{3}[-\s]?\d{2}[-\s]?\d{4}",
                r"\b(?:credit\s+card|cc|visa|mastercard)[\s:]\s*\d{4}[-\s]*\d{4}[-\s]*\d{4}[-\s]*\d{4}",
                r"\b(?:api[_\s]?key|secret[_\s]?key|access[_\s]?token)[\s:]\s*[a-zA-Z0-9]{20,}",
            ],
            ThreatType.DOS_ATTACK: [
                r"(?i)(?:dos|ddos|denial\s+of\s+service)",
                r"(?i)(?:flood|spam|overload)\s+(?:with\s+)?(?:requests?|traffic)",
                r"(?i)exhaust\s+(?:server|system)\s+resources",
            ],
            ThreatType.BUSINESS_LOGIC: [
                r"(?i)(?:free|unlimited|infinite)\s+(?:credits?|points?|tokens?|money|balance)",
                r"(?i)(?:increase|add|give)\s+(?:me\s+)?\d+\s+(?:credits?|points?|dollars?)",
                r"(?i)(?:skip|bypass|ignore)\s+(?:payment|billing|subscription|limit)",
                r"(?i)test\s+(?:transaction|payment|order)",
                r"(?i)refund\s+(?:all|everything|\$\d+)",
            ],
            ThreatType.CONTENT_MANIPULATION: [
                r"(?i)(?:manipulate|alter|change)\s+(?:content|output|response)",
                r"(?i)(?:inject|embed)\s+(?:malicious|hidden)\s+content",
                r"(?i)(?:censor|bypass)\s+(?:filters|moderation)",
            ],
            ThreatType.SYSTEM_PROMPT_ATTACK: [
                r"(?i)system\s+prompt",
                r"(?i)override\s+(?:system|the\s+system)",
                r"(?i)reveal\s+(?:system\s+prompt|the\s+prompt)",
                r"(?i)modify\s+(?:system|the\s+system)",
                r"(?i)change\s+(?:system\s+prompt|the\s+prompt)",
                r"(?i)access\s+(?:system\s+prompt|the\s+prompt)",
            ],
            ThreatType.JAILBREAK: [
                r"(?i)jailbreak|break\s+out|escape\s+jail",
                r"(?i)unrestricted\s+mode|free\s+mode",
                r"(?i)developer\s+mode|admin\s+mode",
                r"(?i)bypass\s+(?:restrictions|filters|rules)",
            ],
            ThreatType.TOXIC_CONTENT: [
                r"(?i)(?:how\s+to|teach\s+me|instructions?\s+for)\s+(?:make|create|build)\s+(?:bomb|weapon|drug|poison)",
                r"(?i)(?:generate|create|write)\s+(?:hate\s+speech|racist|violent|illegal)\s+content",
                r"(?i)(?:harmful|dangerous|illegal)\s+(?:advice|instructions?|guide)",
                r"(?i)how\s+to\s+hack\s+(?:a\s+)?(?:website|account|system)",
            ],
            ThreatType.CODE_INJECTION: [
                r"(?i)(?:inject|execute|run)\s+(?:code|script|command)",
                r"(?i)(?:sql\s+injection|xss|csrf)",
                r"(?i)(?:eval|exec|system)\s*\(",
                r"(?i)(?:<script|eval\(|os\.system\()",
                r"(?i)(?:DROP\s+TABLE|UNION\s+SELECT)",
            ],
            ThreatType.CONTEXT_MANIPULATION: [
                r"(?i)(?:forget|ignore|clear)\s+(?:previous|all|conversation)\s+(?:messages?|history)",
                r"(?i)reset\s+(?:context|conversation|session)",
                r"(?i)manipulate\s+(?:context|history|memory)",
            ],
            ThreatType.OUTPUT_MANIPULATION: [
                r"(?i)(?:change|alter|modify)\s+(?:your\s+)?(?:output|response|answer)",
                r"(?i)(?:format|structure)\s+(?:output|response)\s+in\s+(?:json|xml|html)",
                r"(?i)(?:include|add|remove)\s+(?:metadata|headers|tags)",
            ],
            ThreatType.RESOURCE_EXHAUSTION: [
                r"(?i)(?:flood|spam|overload)\s+(?:requests?|server|system)",
                r"(?i)infinite\s+(?:loop|recursion|generation)",
                r"(?i)exhaust\s+(?:resources|memory|cpu)",
            ],
            ThreatType.INFORMATION_DISCLOSURE: [
                r"(?i)(?:reveal|show|tell\s+me)\s+(?:your\s+)?(?:training\s+data|source\s+code|internal\s+info)",
                r"(?i)(?:what\s+is\s+your|tell\s+me\s+about)\s+(?:model|architecture|parameters)",
                r"(?i)(?:debug|verbose|detailed)\s+(?:mode|output|logging)",
            ],
            ThreatType.PRIVILEGE_ESCALATION: [
                r"(?i)(?:escalate|gain|obtain)\s+(?:admin|root|superuser)\s+(?:privileges?|access)",
                r"(?i)(?:become|act\s+as)\s+(?:administrator|root|superuser)",
                r"(?i)(?:sudo|su)\s+(?:command|access)",
            ],
            ThreatType.SESSION_HIJACKING: [
                r"(?i)(?:hijack|take\s+over|steal)\s+(?:session|conversation|context)",
                r"(?i)(?:impersonate|pretend\s+to\s+be)\s+(?:user|admin|system)",
                r"(?i)(?:session\s+id|cookie|token)\s+(?:steal|intercept)",
            ],
            ThreatType.MAN_IN_THE_MIDDLE: [
                r"(?i)(?:man\s+in\s+the\s+middle|mitm|intercept)\s+(?:communication|traffic|messages)",
                r"(?i)(?:eavesdrop|spy\s+on|monitor)\s+(?:conversation|requests)",
            ],
            ThreatType.MODEL_INVERSION: [
                r"(?i)(?:invert|reverse\s+engineer)\s+(?:model|training\s+data)",
                r"(?i)(?:extract|reconstruct)\s+(?:training\s+data|personal\s+info)",
                r"(?i)(?:membership\s+inference|attribute\s+inference)",
            ],
            ThreatType.ADVERSARIAL_INPUT: [
                r"(?i)(?:adversarial|crafted|malicious)\s+(?:input|prompt|query)",
                r"(?i)(?:fool|trick|bypass)\s+(?:detection|filters|security)",
                r"(?i)(?:unicode\s+tricks|homoglyphs|invisible\s+characters)",
            ],
        }

    def check(self, text: str) -> RegexResult:
        """Check text for threats using regex patterns."""
        threats = set()
        matches = {}
        # Cheap normalization: limit length to prevent DoS
        t = text[:10000]
        for ttype, patterns in self.compiled.items():
            # Optional prefilter (soft): we do not skip regex entirely to avoid false negatives
            _ = self.substrings.get(ttype, None)  # placeholder for future tighter gating
            hit_list = []
            for pat in patterns:
                m = pat.search(t)
                if m:
                    hit_list.append(m.group(0))
            if hit_list:
                threats.add(ttype)
                matches[ttype] = hit_list
        severity = (
            3
            if any(tt in self.high_severity for tt in threats)
            else (1 if threats else 0)
        )
        return RegexResult(threats=threats, severity=severity, matches=matches)

    @staticmethod
    def _from_json(data: Dict) -> Dict[ThreatType, List[str]]:
        patterns = data.get("patterns", {})
        out: Dict[ThreatType, List[str]] = {}
        # Map string keys to ThreatType
        key_to_type = {t.name: t for t in ThreatType}
        key_to_type.update({t.value: t for t in ThreatType})
        for k, vs in patterns.items():
            ttype = key_to_type.get(k)
            if not ttype:
                continue
            if isinstance(vs, list):
                out[ttype] = [str(v) for v in vs]
        return out
