import math
import time

from simulation.config import settings

demo = settings.demo

# Drone position
drone_x = demo.camera_start_x
drone_y = demo.camera_start_y

# Simulated moving target
target_x = demo.camera_target_x
target_y = demo.camera_target_y

current_yaw = demo.camera_initial_yaw

def calculate_target_angle(dx, dy, tx, ty):
    return math.degrees(math.atan2(ty - dy, tx - dx))

for step in range(demo.camera_steps):

    # Simulate target movement
    target_x += demo.camera_target_step

    desired_yaw = calculate_target_angle(
        drone_x,
        drone_y,
        target_x,
        target_y
    )

    error = desired_yaw - current_yaw

    # Simple proportional controller
    current_yaw += error * demo.camera_controller_gain

    print(
        f"Step {step} | "
        f"Target Angle: {desired_yaw:.2f}° | "
        f"Current Yaw: {current_yaw:.2f}° | "
        f"Error: {error:.2f}°"
    )

    time.sleep(demo.camera_interval_seconds)
