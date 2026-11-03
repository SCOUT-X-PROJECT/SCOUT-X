import time
import math

from simulation.config import settings

demo = settings.demo
waypoints = demo.waypoint_coordinates

current_x = demo.camera_start_x
current_y = demo.camera_start_y

for waypoint_num, (target_x, target_y) in enumerate(waypoints, start=1):

    print(f"\nMoving to Waypoint {waypoint_num}: ({target_x}, {target_y})")

    while True:

        dx = target_x - current_x
        dy = target_y - current_y

        distance = math.sqrt(dx**2 + dy**2)

        if distance < demo.waypoint_tolerance:
            print(f"Reached Waypoint {waypoint_num}")
            break

        current_x += dx * demo.waypoint_interpolation
        current_y += dy * demo.waypoint_interpolation

        print(
            f"Position: ({current_x:.2f}, {current_y:.2f})"
        )

        time.sleep(demo.waypoint_interval_seconds)

print("\nPatrol Complete")
