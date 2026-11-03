from typing import Any

from simulation.config import settings
from simulation.security.trust_engine import TrustPolicy, TrustState


class DefenseLogic:
    def __init__(self) -> None:
        self.last_safe_altitude = None
        self.trust_policy = TrustPolicy()

    def apply_defense(self, data: dict[str, Any]) -> dict[str, Any]:
        """Apply the shared trust policy before telemetry leaves the pipeline."""

        # TRUST-BASED CONTROL
        state = data.get("trust_state")
        if state is None:
            state = self.trust_policy.state_for_score(
                float(data.get("trust_score", settings.trust.default_score))
            ).value

        if state in (
            TrustState.PREPARE.value,
            TrustState.EVACUATE.value,
            TrustState.PROTECT.value,
        ):
            data["action"] = "TRUST_LOW_MODE"

            if self.last_safe_altitude is not None:
                data["altitude"] = self.last_safe_altitude
            else:
                self.last_safe_altitude = data.get(
                    "altitude",
                    settings.validation.minimum_altitude,
                )

        else:
            # update safe altitude during normal operation
            if state == TrustState.STANDBY.value:
                self.last_safe_altitude = data.get(
                    "altitude",
                    settings.validation.minimum_altitude,
                )

        # DEFENSE LOGIC
        if data.get("flagged") and state == TrustState.STANDBY.value:
            print("[DEFENSE] Taking corrective action")

            if (
                "altitude" in data
                and data["altitude"] > settings.validation.max_altitude
            ):
                data["altitude"] = settings.validation.max_altitude

            data["action"] = "ALTITUDE_CLAMPED"

        return data
