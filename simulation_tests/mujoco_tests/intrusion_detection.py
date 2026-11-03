import random
import time

from simulation.config import settings

demo = settings.demo

RESTRICTED_ZONE = {
    "xmin": demo.intrusion_zone_minimum,
    "xmax": demo.intrusion_zone_maximum,
    "ymin": demo.intrusion_zone_minimum,
    "ymax": demo.intrusion_zone_maximum,
}

def is_intruder_in_zone(x: float, y: float) -> bool:
    """Keep zone checks consistent with the shared demo boundary settings."""
    return (
        RESTRICTED_ZONE["xmin"] <= x <= RESTRICTED_ZONE["xmax"]
        and
        RESTRICTED_ZONE["ymin"] <= y <= RESTRICTED_ZONE["ymax"]
    )

for step in range(demo.intrusion_iterations):

    intruder_x = random.randint(
        demo.intrusion_sample_minimum,
        demo.intrusion_sample_maximum,
    )
    intruder_y = random.randint(
        demo.intrusion_sample_minimum,
        demo.intrusion_sample_maximum,
    )

    print(
        f"Target Position: ({intruder_x}, {intruder_y})"
    )

    if is_intruder_in_zone(
        intruder_x,
        intruder_y
    ):
        print("[ALERT] Intruder detected!")

    time.sleep(demo.intrusion_interval_seconds)
