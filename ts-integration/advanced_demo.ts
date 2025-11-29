import { ThreatDetector } from "./src/guard";
import * as fs from "fs";
import * as path from "path";
import * as readline from "readline";

interface AdvancedExamplesJson {
  prompt_injection_tests: Record<string, string[]>;
  metadata?: Record<string, any>;
}

function loadAdvancedExamples(
  relPath: string,
): Array<{ text: string; expected_type: string }> {
  const absPath = path.join(__dirname, relPath);
  try {
    const raw = fs.readFileSync(absPath, "utf-8");
    const data: AdvancedExamplesJson = JSON.parse(raw);
    const out: Array<{ text: string; expected_type: string }> = [];

    const tests = data.prompt_injection_tests || {};
    for (const [category, texts] of Object.entries(tests)) {
      // Extract expected_type from category, e.g., "1_direct_instruction_override" -> "DIRECT_INSTRUCTION_OVERRIDE"
      const parts = category.split("_");
      let expected_type = category.toUpperCase();
      if (parts.length > 1) {
        expected_type = parts.slice(1).join("_").toUpperCase();
      }
      for (const text of texts) {
        out.push({ text, expected_type });
      }
    }
    return out;
  } catch (e) {
    console.warn(`⚠️ Failed to load advanced examples from ${absPath}:`, e);
    return [];
  }
}

async function main() {
  console.log(
    "======================================================================",
  );
  console.log("🛡️  Threat Detection Runtime (TypeScript/Node.js)");
  console.log("   Advanced Demo - Prompt Injection Stress Tests");
  console.log(
    "======================================================================\n",
  );

  const detector = new ThreatDetector();

  // 1. Run Advanced Examples from JSON
  console.log("\n📊 Advanced Test Queries:\n");
  // From ts-integration to tests, relative is ../tests/advanced_examples.json
  const examples = loadAdvancedExamples("../tests/advanced_examples.json");

  for (const ex of examples) {
    console.log(`Input:     ${ex.text}`);
    const result = await detector.detect(ex.text);

    if (result.is_threat) {
      console.log(`Decision:  \x1b[31m[BLOCKED]\x1b[0m Threat detected`);
      console.log(`Type:      ${result.threat_type}`);
      console.log(`Reason:    ${result.reasoning}`);
    } else {
      console.log(`Decision:  \x1b[32m[ALLOWED]\x1b[0m Safe to process`);
      console.log(`Reason:    ${result.reasoning}`);
      // Optional: Simulate downstream response like Python demo
      // console.log(`[System Response] Proceeding with safe request.`);
    }
    console.log("-".repeat(70));
  }

  // 2. Interactive Mode
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  console.log("\n🎮 Interactive Mode (Type \u0027q\u0027 to quit)");
  console.log("-".repeat(70));

  const promptUser = () => {
    rl.question("\n> ", async (input) => {
      if (
        input.toLowerCase() === "q" ||
        input.toLowerCase() === "quit" ||
        input.toLowerCase() === "exit"
      ) {
        console.log("Exiting demo. Goodbye!");
        rl.close();
        return;
      }

      if (input.trim()) {
        const result = await detector.detect(input);
        if (result.is_threat) {
          console.log(`Decision:  \x1b[31m[BLOCKED]\x1b[0m Threat detected`);
          console.log(`Type:      ${result.threat_type}`);
          console.log(`Reason:    ${result.reasoning}`);
        } else {
          console.log(`Decision:  \x1b[32m[ALLOWED]\x1b[0m Safe to process`);
          console.log(`Reason:    ${result.reasoning}`);
        }
      }
      promptUser();
    });
  };

  promptUser();
}

main().catch((e) => {
  console.error("❌ Advanced demo failed:", e);
  process.exit(1);
});
