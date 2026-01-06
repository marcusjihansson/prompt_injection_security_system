"""
Exporter script to convert DSPy optimized program into a language-agnostic JSON config.
This allows the "brain" optimized in Python to be run in TypeScript/Node.js.

NOTE: This is the basic export that includes regex patterns and prompt structure.
For FULL architecture export including local model integration and GEPA-optimized
prompts, see: export_adapter_enhanced.py

The enhanced version exports:
- GEPA-optimized prompts with few-shot examples
- Local small model (86M) integration guides
- Complete TypeScript/Go implementations
- Deployment architecture patterns

Run: python src/trust/production/export_adapter_enhanced.py
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import dspy

from trust.core.config import GEPA_MODEL_PATH
from trust.core.detector import ThreatDetector
from trust.core.regex_baseline import RegexBaseline


def extract_dspy_config(program_path: str) -> Dict[str, Any]:
    """
    Load a DSPy program and extract its prompt template and demos.
    """
    # Initialize a blank detector to load weights into
    detector = ThreatDetector()

    # Load the optimized program
    full_path = Path(program_path)
    if full_path.is_dir():
        full_path = full_path / "program.json"

    # If not found, use default/empty detector for structure
    if full_path.exists():
        print(f"Loading program from: {full_path}")
        try:
            detector.load(str(full_path))
        except Exception as e:
            print(
                f"Warning: Failed to load program weights ({e}). Using default structure."
            )
    else:
        print(f"Warning: Program not found at {full_path}. Using default structure.")

    # Extract the CoT predictor
    cot = detector.detector

    # 1. Extract Instructions (System Prompt)
    dspy_signature = None
    if hasattr(cot, "signature"):
        dspy_signature = getattr(cot, "signature")
    elif hasattr(cot, "predictor"):
        predictor = getattr(cot, "predictor")
        if hasattr(predictor, "signature"):
            dspy_signature = getattr(predictor, "signature")

    if dspy_signature is None:
        from trust.core.detector import ThreatDetectionSignature

        dspy_signature = ThreatDetectionSignature

    instructions = getattr(dspy_signature, "instructions", dspy_signature.__doc__)

    # 2. Extract Fields (Input/Output Schema)
    fields = []
    # Accessing fields from the signature class/object
    sig_fields = getattr(dspy_signature, "fields", dspy_signature.__annotations__)

    for name, field in sig_fields.items():
        # Handle both dspy.InputField/OutputField objects and raw annotations
        prefix = f"{name}:"
        desc = ""

        # Check if field has json_schema_extra attribute safely
        if hasattr(field, "json_schema_extra"):
            prefix = field.json_schema_extra.get("prefix", prefix)
            desc = field.json_schema_extra.get("desc", desc)

        fields.append({"name": name, "prefix": prefix, "description": desc})

    # 3. Extract Demos (Few-shot examples)
    demos = []
    # Check for demos on the CoT object (standard DSPy)
    raw_demos = getattr(cot, "demos", [])

    # If not found, check if it's wrapped in a predictor
    if not raw_demos and hasattr(cot, "predictor"):
        raw_demos = getattr(cot.predictor, "demos", [])

    for example in raw_demos:
        demo_obj = {}
        # Copy input fields
        if hasattr(example, "input_text"):
            demo_obj["input_text"] = example.input_text

        # Copy output fields (rationale/reasoning + actual outputs)
        # DSPy stores reasoning in 'reasoning' field usually
        if hasattr(example, "reasoning"):
            demo_obj["reasoning"] = example.reasoning
        if hasattr(example, "is_threat"):
            demo_obj["is_threat"] = str(example.is_threat)
        if hasattr(example, "threat_type"):
            demo_obj["threat_type"] = example.threat_type
        if hasattr(example, "confidence"):
            demo_obj["confidence"] = str(example.confidence)

        demos.append(demo_obj)

    return {
        "metadata": {
            "source": "DSPy Optimized Program",
            "exported_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "version": "1.0",
        },
        "prompt_config": {"instructions": instructions, "fields": fields},
        "demos": demos,
    }


def extract_regex_patterns() -> Dict[str, Any]:
    """Extract default regex patterns from RegexBaseline."""
    baseline = RegexBaseline()
    patterns = baseline._default_patterns()

    # Convert ThreatType enum keys to strings
    return {
        "patterns": {k.value: v for k, v in patterns.items()},
        "high_severity_types": [t.value for t in baseline.high_severity],
    }


def generate_go_code(config: Dict[str, Any], regex_config: Dict[str, Any]) -> str:
    """Generate Go code for the threat detector."""

    # Escape backticks in strings for Go raw string literals
    def escape_go_string(s: str) -> str:
        return s.replace("`", '` + "`" + `')

    instructions = escape_go_string(config["prompt_config"]["instructions"])

    go_code = []
    go_code.append("package guard")
    go_code.append("")
    go_code.append("import (")
    go_code.append('\t"regexp"')
    go_code.append(")")
    go_code.append("")
    go_code.append("// ThreatResult represents the outcome of a threat check")
    go_code.append("type ThreatResult struct {")
    go_code.append('\tIsThreat   bool    `json:"is_threat"`')
    go_code.append('\tThreatType string  `json:"threat_type"`')
    go_code.append('\tConfidence float64 `json:"confidence"`')
    go_code.append('\tReasoning  string  `json:"reasoning"`')
    go_code.append("}")
    go_code.append("")
    go_code.append("// Field represents a field in the prompt schema")
    go_code.append("type Field struct {")
    go_code.append("\tName        string")
    go_code.append("\tPrefix      string")
    go_code.append("\tDescription string")
    go_code.append("}")
    go_code.append("")
    go_code.append("// Configuration constants extracted from Python")
    go_code.append("const (")
    go_code.append(f"\tInstructions = `{instructions}`")
    go_code.append(")")
    go_code.append("")
    go_code.append("var PromptFields = []Field{")

    for field in config["prompt_config"]["fields"]:
        go_code.append(
            f'\t{{Name: "{field["name"]}", Prefix: "{field["prefix"]}", Description: "{field["description"]}"}},'
        )

    go_code.append("}")
    go_code.append("")
    go_code.append("// RegexPatterns maps threat types to their regex patterns")
    go_code.append("var RegexPatterns = map[string][]string{")

    for t_type, patterns in regex_config["patterns"].items():
        go_code.append(f'\t"{t_type}": {{')
        for p in patterns:
            go_code.append(f"\t\t`{escape_go_string(p)}`,")
        go_code.append("\t},")

    go_code.append("}")
    go_code.append("")
    go_code.append(
        "// HighSeverityTypes contains types that trigger immediate blocking"
    )
    go_code.append("var HighSeverityTypes = map[string]bool{")
    for t_type in regex_config["high_severity_types"]:
        go_code.append(f'\t"{t_type}": true,')

    go_code.append("}")
    go_code.append("")
    go_code.append("// CheckRegex performs fast regex-based threat detection")
    go_code.append("func CheckRegex(text string) *ThreatResult {")
    go_code.append("\tfor tType, patterns := range RegexPatterns {")
    go_code.append("\t\tfor _, pattern := range patterns {")
    go_code.append("\t\t\t// Simple case-insensitive check")
    go_code.append("\t\t\t// Note: This compiles regex on every check which is slow.")
    go_code.append("\t\t\t// In production, these should be pre-compiled.")
    go_code.append('\t\t\tre, err := regexp.Compile("(?i)" + pattern)')
    go_code.append("\t\t\tif err != nil {")
    go_code.append("\t\t\t\tcontinue")
    go_code.append("\t\t\t}")
    go_code.append("\t\t\tif re.MatchString(text) {")
    go_code.append("\t\t\t\tisHighSev := HighSeverityTypes[tType]")
    go_code.append("\t\t\t\tconfidence := 0.5")
    go_code.append("\t\t\t\tif isHighSev {")
    go_code.append("\t\t\t\t\tconfidence = 0.95")
    go_code.append("\t\t\t\t}")
    go_code.append("\t\t\t\treturn &ThreatResult{")
    go_code.append("\t\t\t\t\tIsThreat:   true,")
    go_code.append("\t\t\t\t\tThreatType: tType,")
    go_code.append("\t\t\t\t\tConfidence: confidence,")
    go_code.append('\t\t\t\t\tReasoning:  "Regex match: " + pattern,')
    go_code.append("\t\t\t\t}")
    go_code.append("\t\t\t}")
    go_code.append("\t\t}")
    go_code.append("\t}")
    go_code.append("\treturn nil")
    go_code.append("}")

    return "\n".join(go_code)


def main():
    # Define paths
    ts_output_dir = Path("ts-integration")
    go_output_dir = Path("go-integration")
    go_pkg_dir = go_output_dir / "pkg" / "guard"

    # Ensure output directories exist
    ts_output_dir.mkdir(exist_ok=True)
    go_output_dir.mkdir(exist_ok=True)
    go_pkg_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Extract configuration
        config = extract_dspy_config(GEPA_MODEL_PATH)
        regex_config = extract_regex_patterns()

        # 1. TS Integration Outputs
        with open(ts_output_dir / "guard-config.json", "w") as f:
            json.dump(config, f, indent=2)
        with open(ts_output_dir / "regex_patterns.json", "w") as f:
            json.dump(regex_config, f, indent=2)

        # 2. Go Integration Outputs
        # JSON configs are needed in the root for demos to load
        with open(go_output_dir / "guard-config.json", "w") as f:
            json.dump(config, f, indent=2)
        with open(go_output_dir / "regex_patterns.json", "w") as f:
            json.dump(regex_config, f, indent=2)

        # Generate and Write Go Code
        go_code = generate_go_code(config, regex_config)
        with open(go_pkg_dir / "guard.go", "w") as f:
            f.write(go_code)

        print(f"✅ Successfully exported artifacts:")
        print(f"   - TS Integration: {ts_output_dir}")
        print(f"   - Go Integration: {go_output_dir}")

        print(
            f"   - Instructions length: {len(config['prompt_config']['instructions'])} chars"
        )
        print(f"   - Few-shot demos: {len(config['demos'])}")
        print(f"   - Regex categories: {len(regex_config['patterns'])}")

    except Exception as e:
        print(f"❌ Export failed: {e}")
        exit(1)


if __name__ == "__main__":
    main()
