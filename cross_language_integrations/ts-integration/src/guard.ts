import * as fs from "fs";
import * as path from "path";

// Types matching the Python outputs
interface ThreatResult {
  is_threat: boolean;
  threat_type: string;
  confidence: number;
  reasoning: string;
}

interface RegexResult {
  threats: string[];
  severity: number;
  matches: string[];
}

interface GuardConfig {
  prompt_config: {
    instructions: string;
    fields: Array<{
      name: string;
      prefix: string;
      description: string;
    }>;
  };
  demos: Array<Record<string, any>>;
}

/**
 * TypeScript implementation of the Threat Detector Runtime.
 * Consumes artifacts exported from the Python optimization engine.
 */
export class ThreatDetector {
  private regexPatterns: Record<string, string[]> = {};
  private highSeverityTypes: Set<string> = new Set();
  private config!: GuardConfig;
  private systemPrompt: string = "";

  constructor(
    configPath: string = path.join(__dirname, "../guard-config.json"),
    regexPath: string = path.join(
      __dirname,
      "../regex_patterns.json",
    ),
  ) {
    this.loadRegexPatterns(regexPath);
    this.loadConfig(configPath);
  }

  private loadRegexPatterns(filePath: string) {
    try {
      const data = JSON.parse(fs.readFileSync(filePath, "utf-8"));
      this.regexPatterns = data.patterns || {};
      this.highSeverityTypes = new Set(data.high_severity_types || []);
    } catch (e) {
      console.warn(`⚠️ Failed to load regex patterns from ${filePath}:`, e);
    }
  }

  private loadConfig(filePath: string) {
    try {
      this.config = JSON.parse(fs.readFileSync(filePath, "utf-8"));
      this.systemPrompt = this.constructSystemPrompt();
    } catch (e) {
      console.error(`❌ Failed to load guard config from ${filePath}:`, e);
      throw e;
    }
  }

  /**
   * Reconstructs the optimized system prompt from the configuration.
   */
  private constructSystemPrompt(): string {
    const { instructions, fields } = this.config.prompt_config;
    let prompt = `${instructions}\n\n`;

    prompt += "Follow the following format.\n\n";
    fields.forEach((field) => {
      prompt += `${field.prefix} ${field.description}\n`;
    });

    return prompt;
  }

  /**
   * Fast-path regex detection (Stage 1)
   */
  private checkRegex(text: string): RegexResult | null {
    const foundThreats = new Set<string>();
    let maxSeverity = 0;
    const matches: string[] = [];

    for (const [type, patterns] of Object.entries(this.regexPatterns)) {
      for (const pattern of patterns) {
        try {
          // Python regex '(?i)' flag means case insensitive.
          // JS doesn't support inline flags like '(?i)', so we need to strip it
          // and use the 'i' flag in the RegExp constructor.
          const cleanPattern = pattern.replace(/^\(\?i\)/, "");
          const regex = new RegExp(cleanPattern, "i");

          if (regex.test(text)) {
            foundThreats.add(type);
            matches.push(pattern);

            // Determine severity
            const severity = this.highSeverityTypes.has(type) ? 3 : 1;
            maxSeverity = Math.max(maxSeverity, severity);
          }
        } catch (e) {
          // Ignore invalid regex
        }
      }
    }

    if (foundThreats.size === 0) return null;

    return {
      threats: Array.from(foundThreats),
      severity: maxSeverity,
      matches,
    };
  }

  /**
   * Mock LLM Call (Stage 2) - Now connecting to actual API
   */
  private async callLLM(input: string): Promise<ThreatResult> {
    try {
        const response = await fetch("http://localhost:8000/detect", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ text: input }),
        });

        if (!response.ok) {
            throw new Error(`API call failed: ${response.statusText}`);
        }

        return await response.json();
    } catch (error) {
        // Fallback to safe if API is unavailable
        return {
            is_threat: false,
            threat_type: "benign",
            confidence: 0.0,
            reasoning: "LLM Check Failed (API unavailable)",
        };
    }
  }

  /**
   * Main entry point: Hybrid Detection Logic
   */
  public async detect(input: string): Promise<ThreatResult> {
    // Stage 1: Regex Fast Path
    const regexResult = this.checkRegex(input);

    if (regexResult && regexResult.severity >= 3) {
      return {
        is_threat: true,
        threat_type: regexResult.threats[0].toLowerCase(),
        confidence: 0.95,
        reasoning: `Regex baseline high-severity match: ${regexResult.threats.join(", ")}`,
      };
    }

    // Stage 2: LLM Check (Optimized Prompts)
    const llmResult = await this.callLLM(input);

    // Stage 3: Fusion Logic
    if (regexResult && regexResult.severity > 0) {
      // If benign but regex found something, override
      if (!llmResult.is_threat) {
        return {
          is_threat: true,
          threat_type: regexResult.threats[0].toLowerCase(),
          confidence: 0.5,
          reasoning: `${llmResult.reasoning} (Overridden by Regex Baseline: ${regexResult.threats.join(", ")})`,
        };
      }
    }

    return llmResult;
  }
}
