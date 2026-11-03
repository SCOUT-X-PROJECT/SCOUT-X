import random

from simulation.config import settings

demo = settings.demo


def assess_threat(
    distance: float,
    speed: float,
    restricted_zone: bool,
) -> str:
    """Use shared weights so separate demo threat samples remain comparable."""

    score = 0

    if restricted_zone:
        score += demo.threat_zone_weight

    if distance < demo.threat_distance_limit:
        score += demo.threat_distance_weight

    if speed > demo.threat_speed_limit:
        score += demo.threat_speed_weight

    if score >= demo.threat_high_threshold:
        return "HIGH"

    if score >= demo.threat_medium_threshold:
        return "MEDIUM"

    return "LOW"


for _ in range(demo.threat_iterations):

    distance = random.uniform(
        demo.threat_distance_sample_minimum,
        demo.threat_distance_sample_maximum,
    )
    speed = random.uniform(
        demo.threat_speed_sample_minimum,
        demo.threat_speed_sample_maximum,
    )
    restricted_zone = random.choice([True, False])

    level = assess_threat(
        distance,
        speed,
        restricted_zone
    )

    print(
        f"Distance={distance:.1f} "
        f"Speed={speed:.1f} "
        f"Zone={restricted_zone} "
        f"Threat={level}"
    )
