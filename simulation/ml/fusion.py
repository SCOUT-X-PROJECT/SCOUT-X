"""Conservatively fuse ML alerts with deterministic response decisions."""

from typing import Any

from simulation.contracts import MlAssessment, ResponseDecision, ResponseLevel


_RESPONSE_LEVEL = {
    "NORMAL_OPERATION": 0,
    "MONITOR": 1,
    "LIMIT_MOVEMENT": 2,
    "ISOLATE_DRONE": 3,
    "FORCE_LAND": 4,
}
_LEVEL_RESPONSE = {value: key for key, value in _RESPONSE_LEVEL.items()}


def fuse_ml_signal(
    deterministic_response: str,
    ml_result: dict[str, Any],
) -> dict[str, str | bool]:
    """Allow a ready ML anomaly to raise one response level, never trigger PROTECT.

    The deterministic response remains authoritative for isolation and landing.
    A ready ML alert may raise routine monitoring to movement limitation, while
    invalid or untrained model results have no effect on enforcement.
    """
    level = _RESPONSE_LEVEL.get(deterministic_response, 0)
    if ml_result.get("ml_status") != "ready" or ml_result.get("ml_anomaly") is not True:
        return {
            "response": deterministic_response,
            "ml_escalated": False,
            "fusion_reason": "deterministic_only",
        }
    if level >= _RESPONSE_LEVEL["ISOLATE_DRONE"]:
        return {
            "response": deterministic_response,
            "ml_escalated": False,
            "fusion_reason": "deterministic_protection_preserved",
        }

    fused_level = min(level + 1, _RESPONSE_LEVEL["LIMIT_MOVEMENT"])
    return {
        "response": _LEVEL_RESPONSE[fused_level],
        "ml_escalated": fused_level > level,
        "fusion_reason": "ml_alert_capped_at_limit_movement",
    }


def fuse_assessment(
    decision: ResponseDecision,
    ml: MlAssessment,
) -> ResponseDecision:
    """Fuse typed assessments while preserving the legacy safety cap."""
    fused = fuse_ml_signal(
        decision.response.value,
        {
            "ml_status": ml.status,
            "ml_anomaly": ml.anomaly,
            "ml_score": ml.risk_score,
        },
    )
    return decision.model_copy(
        update={
            "response": ResponseLevel(str(fused["response"])),
            "reason": str(fused["fusion_reason"]),
            "ml_contributed": bool(fused["ml_escalated"]),
        }
    )
