# OWASP LLM Top 10 Coverage

dspy.Trust implements **complete protection** against the OWASP Top 10 for LLM Applications (2025).

## Coverage Matrix

| OWASP Category                  | Validator                      | Status         | Default |
| ------------------------------- | ------------------------------ | -------------- | ------- |
| **LLM01** Prompt Injection      | `PromptInjectionValidator`     | Implemented | Enabled |
| **LLM02** Sensitive Information | `SensitiveInfoValidator`       | Implemented | Enabled |
| **LLM03** Supply Chain          | `SupplyChainValidator`         | Implemented | Opt-in  |
| **LLM04** Data Poisoning        | `DataPoisoningValidator`       | Implemented | Opt-in  |
| **LLM05** Output Handling       | `OutputHandlingValidator`      | Implemented | Enabled |
| **LLM06** Excessive Agency      | `ExcessiveAgencyValidator`     | Implemented | Enabled |
| **LLM07** System Prompt Leakage | `SystemPromptLeakageValidator` | Implemented | Enabled |
| **LLM08** Vector/Embedding      | `EmbeddingSecurityValidator`   | Implemented | Opt-in  |
| **LLM09** Misinformation        | `MisinformationValidator`      | Implemented | Enabled |
| **LLM10** Unbounded Consumption | `ResourceConsumptionValidator` | Implemented | Enabled |

**Coverage: 100%** - All OWASP Top 10 categories protected

## Quick Start

```python
from dspy_trust.owasp import OWASPGuard

# Use preset configuration
guard = OWASPGuard.create_preset("standard")  # 70% coverage

# Wrap any DSPy module
protected_module = guard.wrap(your_dspy_module)

# Or maximum protection
guard = OWASPGuard.create_preset("maximum")  # 100% coverage
```

## Presets

- **minimal** (30%): Critical only - LLM01, LLM06, LLM09
- **standard** (70%): Common threats - LLM01, 02, 05, 06, 07, 09, 10
- **maximum** (100%): All validators enabled
- **rag** (50%): Optimized for RAG - includes LLM08
- **agent** (50%): Optimized for agents - focuses on LLM06

## Why OWASP Matters

The OWASP Top 10 represents collaborative research from **370+ industry experts**
identifying the most critical security risks. By aligning with OWASP, dspy.Trust
provides battle-tested, industry-recognized protection.

[Learn more about OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
