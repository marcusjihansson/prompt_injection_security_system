
# Go Integration with Local Model

## Option 1: HTTP API Client (Recommended)

```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

type ThreatRequest struct {
    Text string `json:"text"`
}

type ThreatResponse struct {
    IsThreat   bool    `json:"is_threat"`
    ThreatType string  `json:"threat_type"`
    Confidence float64 `json:"confidence"`
    Reasoning  string  `json:"reasoning"`
}

func detectThreat(text string) (*ThreatResponse, error) {
    // Call Python FastAPI server
    reqBody, _ := json.Marshal(ThreatRequest{Text: text})
    
    resp, err := http.Post(
        "http://localhost:8000/detect",
        "application/json",
        bytes.NewBuffer(reqBody),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result ThreatResponse
    json.NewDecoder(resp.Body).Decode(&result)
    
    return &result, nil
}
```

## Option 2: ONNX Runtime

```go
import (
    ort "github.com/yalue/onnxruntime_go"
)

type LocalModel struct {
    session *ort.AdvancedSession
}

func NewLocalModel(modelPath string) (*LocalModel, error) {
    session, err := ort.NewAdvancedSession(
        modelPath,
        []string{"input_ids", "attention_mask"},
        []string{"logits"},
        nil,
    )
    if err != nil {
        return nil, err
    }
    
    return &LocalModel{session: session}, nil
}

func (m *LocalModel) Predict(text string) (*ThreatResponse, error) {
    // Tokenize input
    inputs := tokenize(text)
    
    // Run inference
    outputs, err := m.session.Run(inputs)
    if err != nil {
        return nil, err
    }
    
    // Parse results
    return parseModelOutput(outputs), nil
}
```

## Integration with GEPA-Optimized Prompts

```go
import (
    "encoding/json"
    "os"
)

type GuardConfig struct {
    PromptConfig struct {
        Instructions string  `json:"instructions"`
        Fields       []Field `json:"fields"`
    } `json:"prompt_config"`
    Demos []Demo `json:"demos"`
}

type Demo struct {
    InputText  string `json:"input_text"`
    Reasoning  string `json:"reasoning"`
    IsThreat   string `json:"is_threat"`
    ThreatType string `json:"threat_type"`
}

func DetectWithOptimizedPrompt(text string) (*ThreatResponse, error) {
    // Load GEPA-optimized config
    config := loadConfig("./guard-config.json")
    
    // Stage 1: Regex pre-filter
    regexResult := CheckRegex(text)
    if regexResult != nil && regexResult.IsThreat {
        return regexResult, nil
    }
    
    // Stage 2: Build optimized prompt with few-shot examples
    prompt := buildPromptFromConfig(config, text)
    
    // Stage 3: Call local model via API
    modelResult, err := callModelAPI(prompt)
    if err != nil {
        return nil, err
    }
    
    // Stage 4: Fusion logic
    return fuseResults(regexResult, modelResult), nil
}

func buildPromptFromConfig(config *GuardConfig, input string) string {
    prompt := config.PromptConfig.Instructions + "\n\n"
    
    // Add few-shot demonstrations (GEPA-optimized)
    for _, demo := range config.Demos {
        prompt += fmt.Sprintf("Example:\nInput: %s\n", demo.InputText)
        prompt += fmt.Sprintf("Reasoning: %s\n", demo.Reasoning)
        prompt += fmt.Sprintf("Is Threat: %s\n\n", demo.IsThreat)
    }
    
    // Add current input
    prompt += fmt.Sprintf("Now analyze this input:\nInput: %s\n", input)
    
    return prompt
}
```

## Deployment Options

1. **Microservice Architecture** (Recommended)
   - Python FastAPI server with the 86M model
   - Go API gateway handling routing and business logic
   - Clear separation of concerns

2. **ONNX Runtime**
   - Export model to ONNX format
   - Use Go ONNX bindings for native inference
   - More complex but eliminates Python dependency

3. **HuggingFace Inference API**
   - Serverless model hosting
   - Simple HTTP calls from Go
   - Pay-per-use pricing

## Performance

- **Regex + API call**: ~100-150ms
- **ONNX native**: ~50-80ms
- **Microservice**: ~100ms with proper caching

The GEPA optimization reduces false positives by 20-30% compared to baseline prompts.
