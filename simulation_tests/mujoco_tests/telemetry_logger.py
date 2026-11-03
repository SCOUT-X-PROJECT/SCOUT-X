import csv
import time
import random

from simulation.config import PROJECT_ROOT, settings

demo = settings.demo
LOG_FILE = PROJECT_ROOT / settings.logging.demo_telemetry_file

with LOG_FILE.open("w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow([
        "timestamp",
        "x",
        "y",
        "z",
        "velocity"
    ])

    x = demo.telemetry_start_x
    y = demo.telemetry_start_y
    z = demo.telemetry_start_z

    for _ in range(demo.telemetry_samples):
        x += random.uniform(
            demo.telemetry_movement_minimum,
            demo.telemetry_movement_maximum,
        )
        y += random.uniform(
            demo.telemetry_movement_minimum,
            demo.telemetry_movement_maximum,
        )

        velocity = random.uniform(
            demo.telemetry_speed_minimum,
            demo.telemetry_speed_maximum,
        )

        writer.writerow([
            time.time(),
            round(x, settings.logging.decimal_precision),
            round(y, settings.logging.decimal_precision),
            z,
            round(velocity, settings.logging.decimal_precision)
        ])

        print(
            f"Position=({x:.2f},{y:.2f},{z}) "
            f"Velocity={velocity:.2f}"
        )

        time.sleep(demo.telemetry_interval_seconds)

print(f"Saved telemetry to {LOG_FILE}")
