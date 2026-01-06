package detector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/marcusjohansson/trust-go/pkg/guard"
)

// EnhancedDetector implements the full hybrid threat detection pipeline
type EnhancedDetector struct {
	configPath    string
	regexPath     string
	modelEndpoint string
	client        *http.Client
}

// NewEnhanced creates a new enhanced detector
func NewEnhanced(configPath, regexPath, modelEndpoint string) (*EnhancedDetector, error) {
	return &EnhancedDetector{
		configPath:    configPath,
		regexPath:     regexPath,
		modelEndpoint: modelEndpoint,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

// Detect performs full threat detection
func (d *EnhancedDetector) Detect(text string) (*guard.ThreatResult, error) {
	// Stage 1: Regex Pre-filter
	regexResult := guard.CheckRegex(text)
	if regexResult != nil && regexResult.Confidence >= 0.9 {
		// High confidence regex match (blocking)
		return regexResult, nil
	}

	// Stage 2: API Call to Model
	apiResult, err := d.callModelAPI(text)
	if err != nil {
		// Fallback to regex result if available, otherwise return error
		if regexResult != nil {
			regexResult.Reasoning += " (API Unavailable)"
			return regexResult, nil
		}
		// If API fails and no regex match, treat as benign but warn
		return &guard.ThreatResult{
			IsThreat:   false,
			ThreatType: "benign",
			Confidence: 0.0,
			Reasoning:  fmt.Sprintf("API Unavailable: %v", err),
		}, nil
	}

	// Stage 3: Fusion Logic
	if regexResult != nil && regexResult.IsThreat {
		// If regex found something but API didn't, or API confidence is low
		// For safety, we might trust regex if it was a clear match
		if !apiResult.IsThreat {
			return &guard.ThreatResult{
				IsThreat:   true,
				ThreatType: regexResult.ThreatType,
				Confidence: 0.5, // Lower confidence since model disagreed
				Reasoning:  fmt.Sprintf("Regex match '%s' (Model disagreed)", regexResult.Reasoning),
			}, nil
		}
	}

	return apiResult, nil
}

type apiRequest struct {
	Text string `json:"text"`
}

func (d *EnhancedDetector) callModelAPI(text string) (*guard.ThreatResult, error) {
	reqBody, err := json.Marshal(apiRequest{Text: text})
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Post(
		d.modelEndpoint+"/detect",
		"application/json",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status: %s", resp.Status)
	}

	var result guard.ThreatResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
