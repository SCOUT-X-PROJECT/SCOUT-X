import time

from simulation.config import settings

demo = settings.demo

waypoints = [
    "Waypoint A",
    "Waypoint B",
    "Waypoint C"
]

print("Starting surveillance patrol...\n")

for point in waypoints:
    print(f"Navigating to {point}")
    time.sleep(demo.surveillance_interval_seconds)

print("\nPatrol completed successfully.")
