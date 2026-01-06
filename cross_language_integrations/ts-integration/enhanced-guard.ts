
import * as fs from 'fs';
import * as path from 'path';

// Types
interface ThreatResult {
  is_threat: boolean;
  threat_type: string;
  confidence: number;
  reasoning: string;
}

interface GuardConfig {
  prompt_config: {
    instructions: string;
    fields: Array<{ name: string; prefix: string; description: string }>;
  };
  demos: Array<{
    input_text: string;
    reasoning: string;
    is_threat: string;
    threat_type: string;
    confidence: string;
  }>;
  model_integration: {
    local_model: string;
    integration_options: any;
  };
}

/**
 * Enhanced ThreatDetector with Local Model Integration
 * 
 * This demonstrates the FULL architecture ported to TypeScript:
 * - Regex baseline (fast pre-filter)
 * - GEPA-optimized prompts (few-shot learning)
 * - Local 86M model (deep analysis)
 */
export class EnhancedThreatDetector {
  private regexPatterns: Record<string, string[]> = {};
  private highSeverityTypes: Set<string> = new Set();
  private config!: GuardConfig;
  private modelAPI: string;

  constructor(
    configPath: string = path.join(__dirname, '../guard-config.json'),
    regexPath: string = path.join(__dirname, '../regex_patterns.json'),
    modelAPI: string = 'http://localhost:8000'
  ) {
    this.loadRegexPatterns(regexPath);
    this.loadConfig(configPath);
    this.modelAPI = modelAPI;
  }

  private loadRegexPatterns(filePath: string) {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    this.regexPatterns = data.patterns || {};
    this.highSeverityTypes = new Set(data.high_severity_types || []);
  }

  private loadConfig(filePath: string) {
    this.config = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    console.log(`✅ Loaded GEPA-optimized config with ${this.config.demos.length} few-shot examples`);
  }

  /**
   * Stage 1: Regex Pre-Filter (Fast Path)
   */
  private checkRegex(text: string): { threats: string[]; severity: number } | null {
    const foundThreats = new Set<string>();
    let maxSeverity = 0;

    for (const [type, patterns] of Object.entries(this.regexPatterns)) {
      for (const pattern of patterns) {
        try {
          const cleanPattern = pattern.replace(/^\(\?i\)/, '');
          const regex = new RegExp(cleanPattern, 'i');

          if (regex.test(text)) {
            foundThreats.add(type);
            const severity = this.highSeverityTypes.has(type) ? 3 : 1;
            maxSeverity = Math.max(maxSeverity, severity);
          }
        } catch (e) {
          // Invalid regex
        }
      }
    }

    if (foundThreats.size === 0) return null;

    return {
      threats: Array.from(foundThreats),
      severity: maxSeverity,
    };
  }

  /**
   * Stage 2: Build GEPA-Optimized Prompt with Few-Shot Examples
   */
  private buildOptimizedPrompt(input: string): string {
    let prompt = this.config.prompt_config.instructions + '\n\n';

    // Add field descriptions
    prompt += 'Follow the following format:\n\n';
    for (const field of this.config.prompt_config.fields) {
      prompt += `${field.prefix} ${field.description}\n`;
    }
    prompt += '\n';

    // Add few-shot demonstrations (GEPA-optimized examples)
    for (const demo of this.config.demos) {
      prompt += '---\n';
      prompt += `Input Text: ${demo.input_text}\n`;
      prompt += `Reasoning: ${demo.reasoning}\n`;
      prompt += `Is Threat: ${demo.is_threat}\n`;
      prompt += `Threat Type: ${demo.threat_type}\n`;
      prompt += `Confidence: ${demo.confidence}\n\n`;
    }

    // Add current input
    prompt += '---\n';
    prompt += `Input Text: ${input}\n`;
    prompt += 'Reasoning:';

    return prompt;
  }

  /**
   * Stage 3: Call Local Model (86M parameters)
   */
  private async callLocalModel(prompt: string): Promise<ThreatResult> {
    try {
      const response = await fetch(`${this.modelAPI}/detect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: prompt }),
      });

      if (!response.ok) {
        throw new Error(`Model API error: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.warn('⚠️ Model API unavailable, using regex-only mode');
      return {
        is_threat: false,
        threat_type: 'benign',
        confidence: 0.0,
        reasoning: 'Model unavailable - regex check only',
      };
    }
  }

  /**
   * Stage 4: Fusion Logic (Combine Regex + Model Results)
   */
  private fuseResults(
    regexResult: { threats: string[]; severity: number } | null,
    modelResult: ThreatResult
  ): ThreatResult {
    // High-severity regex: Block immediately
    if (regexResult && regexResult.severity >= 3) {
      return {
        is_threat: true,
        threat_type: regexResult.threats[0].toLowerCase(),
        confidence: 0.95,
        reasoning: `Regex high-severity: ${regexResult.threats.join(', ')}`,
      };
    }

    // Low-severity regex + benign model: Override to threat
    if (regexResult && regexResult.severity > 0 && !modelResult.is_threat) {
      return {
        is_threat: true,
        threat_type: regexResult.threats[0].toLowerCase(),
        confidence: 0.5,
        reasoning: `${modelResult.reasoning} (Overridden by regex: ${regexResult.threats.join(', ')})`,
      };
    }

    // Both detect threat: Boost confidence
    if (regexResult && modelResult.is_threat) {
      return {
        ...modelResult,
        confidence: Math.min(modelResult.confidence + 0.2, 1.0),
        reasoning: `${modelResult.reasoning} (Confirmed by regex)`,
      };
    }

    return modelResult;
  }

  /**
   * Main Entry Point: Full Hybrid Detection
   */
  public async detect(input: string): Promise<ThreatResult> {
    // Stage 1: Regex pre-filter
    const regexResult = this.checkRegex(input);

    // Stage 2: Build GEPA-optimized prompt
    const prompt = this.buildOptimizedPrompt(input);

    // Stage 3: Call local model
    const modelResult = await this.callLocalModel(prompt);

    // Stage 4: Fuse results
    return this.fuseResults(regexResult, modelResult);
  }

  /**
   * Get information about the loaded configuration
   */
  public getInfo() {
    return {
      model: this.config.model_integration.local_model,
      demos: this.config.demos.length,
      regex_categories: Object.keys(this.regexPatterns).length,
      high_severity_types: Array.from(this.highSeverityTypes),
    };
  }
}
