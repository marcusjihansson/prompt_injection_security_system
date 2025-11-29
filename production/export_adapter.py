"""
Exporter script to convert DSPy optimized program into a language-agnostic JSON config.
This allows the "brain" optimized in Python to be run in TypeScript/Node.js.
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any

import dspy
from threat_system.config import GEPA_MODEL_PATH
from threat_system.threat_detector import ThreatDetector

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
    
    if not full_path.exists():
        raise FileNotFoundError(f"Could not find DSPy program at {full_path}")
    
    print(f"Loading program from: {full_path}")
    detector.load(str(full_path))
    
    # Extract the CoT predictor
    cot = detector.detector
    
    # 1. Extract Instructions (System Prompt)
    # The signature is actually on the detector.predictor in some versions or just detector
    # Let's inspect what we have.
    # When loaded from disk, DSPy structures might vary.
    
    # Try to find signature on the CoT module directly
    signature = None
    if hasattr(cot, "signature"):
        signature = cot.signature
    elif hasattr(cot, "predictor") and hasattr(cot.predictor, "signature"):
         signature = cot.predictor.signature
         
    if signature is None:
        # Fallback: if we can't find it on the loaded object, execute the original class definition
        # since the signature is static class logic anyway.
        from threat_system.threat_detector import ThreatDetectionSignature
        signature = ThreatDetectionSignature

    instructions = signature.instructions if hasattr(signature, "instructions") else signature.__doc__
    
    # 2. Extract Fields (Input/Output Schema)
    fields = []
    # Accessing fields from the signature class/object
    sig_fields = signature.fields if hasattr(signature, "fields") else signature.__annotations__
    
    for name, field in sig_fields.items():
        # Handle both dspy.InputField/OutputField objects and raw annotations
        prefix = f"{name}:"
        desc = ""
        
        if hasattr(field, "json_schema_extra"):
             prefix = field.json_schema_extra.get("prefix", prefix)
             desc = field.json_schema_extra.get("desc", desc)
             
        fields.append({
            "name": name,
            "prefix": prefix,
            "description": desc
        })
        
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
            "version": "1.0"
        },
        "prompt_config": {
            "instructions": instructions,
            "fields": fields
        },
        "demos": demos
    }

def main():
    # Define paths
    output_dir = Path("ts-integration")
    output_file = output_dir / "guard-config.json"
    
    # Ensure output directory exists
    output_dir.mkdir(exist_ok=True)
    
    try:
        # Extract configuration
        config = extract_dspy_config(GEPA_MODEL_PATH)
        
        # Write to JSON
        with open(output_file, "w") as f:
            json.dump(config, f, indent=2)
            
        print(f"✅ Successfully exported guard config to: {output_file}")
        print(f"   - Instructions length: {len(config['prompt_config']['instructions'])} chars")
        print(f"   - Few-shot demos: {len(config['demos'])}")
        
    except Exception as e:
        print(f"❌ Export failed: {e}")
        exit(1)

if __name__ == "__main__":
    main()
