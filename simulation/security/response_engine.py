from typing import Any

from simulation.config import settings
from simulation.security.trust_engine import TrustPolicy, TrustState


class ResponseEngine:
    def __init__(self, policy: TrustPolicy | None = None) -> None:
        self.attack_streak = 0
        self.policy = policy or TrustPolicy()

    def decide(self, data: dict[str, Any]) -> str:
        """Adapt legacy dictionaries to the pure response policy."""
        pattern = data.get("pattern")
        severity = data.get("severity")
        if pattern in ["PERSISTENT_ATTACK", "INTERMITTENT_ATTACK"]:
            self.attack_streak += 1
        else:
            self.attack_streak = max(0, self.attack_streak - 1)
        return decide_response(
            trust=float(data.get("trust_score", settings.trust.default_score)),
            state=str(data.get("trust_state", TrustState.STANDBY.value)),
            pattern=str(pattern or ""),
            severity=str(severity or ""),
            attack_streak=self.attack_streak,
            policy=self.policy,
        )


def decide_response(
    *,
    trust: float,
    state: str,
    pattern: str,
    severity: str,
    attack_streak: int,
    policy: TrustPolicy | None = None,
) -> str:
    """Choose a response purely from threat, trust state, and history."""
    trust_policy = policy or TrustPolicy()
    parsed_state = (
        TrustState(state)
        if state in {item.value for item in TrustState}
        else TrustState.PROTECT
    )
    if trust_policy.is_protect(trust, parsed_state):
        return "ISOLATE_DRONE"
    if attack_streak > trust_policy.force_land_attack_streak and severity == "HIGH":
        return "FORCE_LAND"
    if attack_streak > trust_policy.limit_movement_attack_streak:
        return "LIMIT_MOVEMENT"
    if pattern == "INTERMITTENT_ATTACK":
        return "MONITOR"
    return "NORMAL_OPERATION"
