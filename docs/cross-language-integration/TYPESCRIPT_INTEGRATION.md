
# TypeScript Integration with Local Model

## Option 1: Transformers.js (Recommended)

```typescript
import { pipeline } from '@xenova/transformers';

// Load the model (runs in Node.js or browser)
const classifier = await pipeline(
  'text-classification',
  'Xenova/Llama-Prompt-Guard-2-86M'  // ONNX-converted version
);

async function detectThreat(text: string) {
  // Run inference
  const result = await classifier(text);
  
  return {
    is_threat: result[0].label === 'MALICIOUS',
    confidence: result[0].score,
    reasoning: 'Local model prediction'
  };
}
```

## Option 2: ONNX Runtime

```typescript
import * as ort from 'onnxruntime-node';

// Load ONNX model
const session = await ort.InferenceSession.create('./model.onnx');

async function detectThreat(text: string) {
  // Tokenize and prepare input
  const input = prepareInput(text);
  
  // Run inference
  const results = await session.run(input);
  
  return parseResults(results);
}
```

## Option 3: FastAPI Microservice

```typescript
async function detectThreat(text: string) {
  const response = await fetch('http://localhost:8000/detect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text })
  });
  
  return await response.json();
}
```

## Integration with GEPA-Optimized Prompts

```typescript
import config from './guard-config.json';

async function detectWithOptimizedPrompt(text: string) {
  // Stage 1: Regex pre-filter (fast)
  const regexResult = checkRegex(text);
  if (regexResult && regexResult.severity >= 3) {
    return {
      is_threat: true,
      threat_type: regexResult.threats[0],
      confidence: 0.95,
      reasoning: 'Regex high-severity match'
    };
  }
  
  // Stage 2: Build optimized prompt with few-shot examples
  const prompt = buildPromptFromConfig(config, text);
  
  // Stage 3: Run local model with optimized prompt
  const modelResult = await runLocalModel(prompt);
  
  // Stage 4: Fusion logic
  return fuseResults(regexResult, modelResult);
}

function buildPromptFromConfig(config: any, input: string): string {
  let prompt = config.prompt_config.instructions + '\n\n';
  
  // Add few-shot demonstrations (GEPA-optimized)
  for (const demo of config.demos) {
    prompt += `Example:\n`;
    prompt += `Input: ${demo.input_text}\n`;
    prompt += `Reasoning: ${demo.reasoning}\n`;
    prompt += `Is Threat: ${demo.is_threat}\n\n`;
  }
  
  // Add current input
  prompt += `Now analyze this input:\n`;
  prompt += `Input: ${input}\n`;
  
  return prompt;
}
```

## Performance

- **Regex pre-filter**: <1ms
- **Local model inference**: ~50-100ms (CPU)
- **Total latency**: ~100ms with caching
- **Memory**: ~350MB model size

The GEPA-optimized prompts improve accuracy by 10-15% compared to generic prompts.
