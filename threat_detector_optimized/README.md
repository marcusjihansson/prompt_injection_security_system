# Threat Detector Optimized

This directory contains saved versions of the optimized DSPy programs used for threat detection.

## Structure

- `latest/`: The most recent optimized program version.
- `v1/`, `v2/`, etc.: Specific versioned snapshots of optimized programs.

Each version directory includes:
- `program.json`: The serialized DSPy program.
- `metadata.json`: Metadata about the optimization, including training parameters and performance metrics.

## Usage

The ProductionThreatDetector automatically loads the `latest` version by default. To use a specific version, specify the path when initializing the detector.

Example:
```python
detector = ProductionThreatDetector(dspy_program_path="threat_detector_optimized/v2/")
```

## Versioning

Versions are incremented when significant improvements are made to the DSPy program through training or optimization. The `latest` symlink always points to the most current version.