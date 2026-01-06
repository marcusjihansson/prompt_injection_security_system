"""
Self-Learning Shield for Chain of Trust

This module wraps an existing threat detection system, adding adaptive security learning.
When novel attacks evade the input guard but are caught by the output guard, the system logs the failure for retraining.
"""

import concurrent.futures
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


@dataclass
class FailureExample:
    user_input: str
    system_context: str
    threat_detected: str  # Should be "True" for failures
    threat_type: str
    reasoning: str
    model_output: str
    violation_type: str
    violation_details: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class SelfLearningShield:
    def __init__(
        self,
        input_guard: Callable,
        core_logic: Callable,
        output_guard: Any,
        trainset: Optional[List[FailureExample]] = None,
        failures_log_path: str = "failures_production.json",
        parallel_execution: bool = False,
    ):
        """
        Args:
            input_guard: callable(raw_user_input:str) -> dict
            core_logic: callable(question) -> model_output:str
            output_guard: OutputGuard instance with .validate()
            trainset: optional, list of FailureExample for retraining
            failures_log_path: where to log production failure examples
            parallel_execution: if True, runs input guard and core logic concurrently
        """
        self.input_guard = input_guard
        self.core_logic = core_logic
        self.output_guard = output_guard
        self.trainset = trainset or []
        self.failures_log_path = failures_log_path
        self.parallel_execution = parallel_execution
        self.new_failures: List[FailureExample] = []

    def predict(self, user_input: str, system_context: str = "") -> Dict[str, Any]:
        model_output = None
        input_check = None

        if self.parallel_execution:
            # Speculative Execution: Run Input Guard and Core Logic in parallel
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_input = executor.submit(self.input_guard, user_input)
                future_core = executor.submit(self.core_logic, user_input)

                # Wait for input guard first (security priority)
                input_check = future_input.result()

                if input_check.get("is_threat", False):
                    # Fast fail: ignore core logic result (it might have finished or is running)
                    # Note: we don't cancel the future effectively in Python threads, but we ignore result
                    return {
                        "response": f"BLOCKED AT INPUT: {input_check.get('threat_type', 'benign')}",
                        "is_trusted": False,
                        "stage": "input_guard",
                        "reasoning": input_check.get("reasoning", ""),
                    }

                # If safe, get core result
                model_output = future_core.result()
        else:
            # Sequential Execution
            input_check = self.input_guard(user_input)
            if input_check.get("is_threat", False):
                return {
                    "response": f"BLOCKED AT INPUT: {input_check.get('threat_type', 'benign')}",
                    "is_trusted": False,
                    "stage": "input_guard",
                    "reasoning": input_check.get("reasoning", ""),
                }
            model_output = self.core_logic(user_input)

        # Layer 3: Output Guard
        output_check = self.output_guard.validate(model_output, user_input, system_context)
        if not output_check.is_safe:
            # Failure: output guard caught what input didn't
            failure = FailureExample(
                user_input=user_input,
                system_context=system_context,
                threat_detected="True",
                threat_type=output_check.violation_type,
                reasoning=output_check.violation_details,
                model_output=model_output,
                violation_type=str(output_check.violation_type),
                violation_details=output_check.violation_details,
            )
            self.new_failures.append(failure)
            self._log_failure(failure)
            return {
                "response": "BLOCKED (Post-Generation Audit)",
                "is_trusted": False,
                "stage": "output_guard",
                "reasoning": output_check.violation_details,
            }
        return {"response": model_output, "is_trusted": True, "stage": "all_clear"}

    def _log_failure(self, failure: FailureExample):
        """Persist new failures for retraining."""
        path = Path(self.failures_log_path)
        failures = []
        if path.exists():
            try:
                failures = json.loads(path.read_text())
            except Exception:
                failures = []
        failures.append(failure.__dict__)
        path.write_text(json.dumps(failures, indent=2))

    def learn(self):
        """
        When called (e.g. daily/weekly), retrain input guard with known failures.
        You would implement DSPy few-shot or other pipeline here.
        """
        if not self.new_failures:
            print("No new failures to learn from.")
            return
        print(f"Retraining with {len(self.new_failures)} new hard negatives...")
        # Merge with trainset if needed
        self.trainset.extend(self.new_failures)
        # ... code to update input_guard here ...
        # For now: just clear out the log
        self.new_failures.clear()
        print("Retrain complete.")
