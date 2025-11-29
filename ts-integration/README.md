# TypeScript Integration

This directory provides a TypeScript/Node.js runtime for the threat detector,
consuming optimized artifacts from the Python training pipeline.

## Overview

The TypeScript implementation mirrors the Python threat detection logic, including:

- Regex baseline fast-path
- DSPy program inference using optimized prompts
- Fusion logic for high-confidence decisions

## Setup

1. Install dependencies:

   ```bash
   npm install
   ```

2. Build the project:
   ```bash
   npm run build
   ```

## Usage

### Basic Detection

```typescript
import { ThreatDetector } from "./src/guard";

const detector = new ThreatDetector();
const result = await detector.detect("Your input text here");

if (result.is_threat) {
  console.log(`Blocked: ${result.threat_type} - ${result.reasoning}`);
} else {
  console.log(`Allowed: ${result.reasoning}`);
}
```

### Configuration

- `guard-config.json`: Contains the optimized DSPy program configuration and system prompt structure.
- `regex_patterns.json`: Regex patterns from the Python system (automatically loaded from `../threat_system/`).

## Running Demos

- Basic demo: `npm start`
- Advanced demo: `npm run start:advanced`

The demos include automated test cases and interactive mode for real-time testing.

## Architecture

- `src/guard.ts`: Main ThreatDetector class implementing the detection logic.
- `guard-config.json`: Exported configuration from Python optimization.
- Demos showcase integration with the Python-optimized artifacts.

## Dependencies

- Node.js runtime
- Optimized artifacts from `threat_detector_optimized/`
- Regex patterns from `threat_system/regex_patterns.json`
