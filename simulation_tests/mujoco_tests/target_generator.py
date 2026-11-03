import math
import random

from simulation.config import settings


class TargetGenerator:

    @staticmethod
    def linear(step: float, speed: float | None = None) -> tuple[float, float]:
        """Keep target motion configurable so scenarios can reuse its trajectory."""
        speed = settings.demo.target_linear_speed if speed is None else speed
        x = step * speed
        y = settings.demo.target_linear_y
        return x, y

    @staticmethod
    def circular(
        step: float,
        radius: float | None = None,
    ) -> tuple[float, float]:
        """Use a stable orbit so tests can compare positions over time."""
        radius = (
            settings.demo.target_circular_radius
            if radius is None
            else radius
        )
        angle = step * settings.demo.target_angle_step

        x = radius * math.cos(angle)
        y = radius * math.sin(angle)

        return x, y

    @staticmethod
    def random_walk(
        x: float,
        y: float,
        step_size: float | None = None,
    ) -> tuple[float, float]:
        """Bound each random move so generated targets remain within the scenario scale."""
        step_size = (
            settings.demo.target_random_walk_step
            if step_size is None
            else step_size
        )

        x += random.uniform(-step_size, step_size)
        y += random.uniform(-step_size, step_size)

        return x, y

    @staticmethod
    def zigzag(step: int) -> tuple[float, float]:
        """Alternate target direction on configured intervals for repeatable patterns."""

        x = step * settings.demo.target_linear_speed

        if step % settings.demo.target_zigzag_period < settings.demo.target_zigzag_cutoff:
            y = settings.demo.target_linear_y
        else:
            y = -settings.demo.target_linear_y

        return x, y


if __name__ == "__main__":

    generator = TargetGenerator()

    for step in range(settings.demo.target_iterations):

        x, y = generator.circular(step)

        print(
            f"Step {step}: "
            f"Target Position = ({x:.2f}, {y:.2f})"
        )
