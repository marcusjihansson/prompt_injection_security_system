"""
Evaluation metric for GEPA optimization with feedback.
"""

import dspy


def threat_detection_metric_with_feedback(
    gold, pred, trace=None, pred_name=None, pred_trace=None, regex_result=None
):
    """
    Evaluation metric that provides feedback for GEPA optimization

    Returns:
        float: Score between 0 and 100
    """
    example = gold

    # Handle different prediction formats
    if isinstance(pred, dspy.Prediction):
        prediction = pred
    elif hasattr(pred, "__dict__"):
        prediction = pred
    else:
        # Prediction failed - return 0
        print(f"⚠️ Invalid prediction format: {type(pred)}")
        return 0.0

    # Safely extract prediction values with defaults
    try:
        pred_is_threat = getattr(prediction, "is_threat", None)
        pred_threat_type = getattr(prediction, "threat_type", None)

        # If attributes are missing, prediction failed
        if pred_is_threat is None or pred_threat_type is None:
            print(f"⚠️ Missing prediction attributes")
            return 0.0

        # Convert string booleans if needed
        if isinstance(pred_is_threat, str):
            pred_is_threat = pred_is_threat.lower() in ("true", "1", "yes")

    except Exception as e:
        print(f"⚠️ Error extracting predictions: {e}")
        return 0.0

    score = 0
    feedback_parts = []

    # Check threat detection accuracy (50 points)
    correct_threat = example.is_threat == pred_is_threat
    if correct_threat:
        score += 50
        feedback_parts.append("✓ Correctly identified threat presence")
    else:
        feedback_parts.append(f"✗ Expected is_threat={example.is_threat}, got {pred_is_threat}")

    # Check threat type classification (50 points)
    if example.is_threat and pred_is_threat:
        correct_type = example.threat_type.lower() == pred_threat_type.lower()
        if correct_type:
            score += 50
            feedback_parts.append("✓ Correctly classified threat type")
        else:
            feedback_parts.append(
                f"✗ Expected threat_type={example.threat_type}, got {pred_threat_type}"
            )
    elif not example.is_threat and not pred_is_threat:
        score += 50
        feedback_parts.append("✓ Both agree input is benign")

    # Incorporate regex signals: heavily penalize false negatives on high-severity regex matches
    if regex_result and regex_result.severity >= 3 and example.is_threat and not pred_is_threat:
        score = 0.0
        feedback_parts.append("✗ Critical: False negative on high-severity regex match")

    return float(score)  # Return just the score for DSPy
