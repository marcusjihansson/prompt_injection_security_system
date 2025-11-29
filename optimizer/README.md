# Optimizer

This directory contains the training and optimization scripts for the DSPy-based threat detector.

## Training Process

The `train_gepa.py` script performs GEPA (Generative Program Optimization) to optimize the threat detection DSPy program using a two-model setup:

1. **Setup Models**: Initializes main LM and reflection LM using OpenRouter.
2. **Create Training Data**: Aggregates examples from configured datasets.
3. **Wrap Detector**: Integrates regex baseline with DSPy detector for enhanced signals.
4. **Run GEPA**: Optimizes the program using the threat detection metric.
5. **Save Optimized Program**: Stores the optimized program and metadata in `threat_detector_optimized/`.

## Running Training

Execute the training script:
```bash
uv run optimizer/train_gepa.py
```

This requires:
- OPENROUTER_API_KEY environment variable
- Access to configured datasets

## Datasets

Datasets are configured in `threat_system/config.py` under `DATASET_CONFIG`. Each entry can be:

- **Simple string**: `"dataset_name": "path/to/dataset"` (threat type inferred from name)
- **Detailed dict**: Specify path, split, threat_type, size, etc.

Current datasets:
- `deepset/prompt-injections`: Prompt injection examples
- `TrustAIRLab/in-the-wild-jailbreak-prompts`: Jailbreak prompts
- `xTRam1/safe-guard-prompt-injection`: Additional prompt injection data

## Optimization Parameters

Key parameters in `threat_system/config.py`:
- `TRAINING_CONFIG["budget"]`: Optimization intensity ('light', 'medium', 'heavy')
- Dataset sizes: Controlled by environment variables like `MAX_PROMPT_INJECTION`
- Model settings: `TRAINING_LM_MODEL`, `REFLECTION_LM_MODEL`, etc.

## Output

Training saves optimized programs to timestamped directories in `threat_detector_optimized/`, updating the `latest` symlink.