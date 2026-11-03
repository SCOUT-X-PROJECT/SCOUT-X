import random
import math
import time
from typing import Any

from simulation.config import settings


class TelemetryEngine:
    def __init__(self) -> None:
        self.lat = settings.dashboard.aircraft_center_latitude
        self.lon = settings.dashboard.aircraft_center_longitude
        self.altitude = settings.validation.initial_altitude
        self.speed = settings.validation.initial_speed
        self.battery = settings.validation.battery_maximum
        self.timestamp = time.time()
        self.heading = random.random() * 360.0
        self.sequence = 0

    def update(self) -> dict[str, Any]:
        """Advance the deterministic-shaped stream so validators see fresh telemetry."""
        self.sequence += 1
        now = max(time.time(), self.timestamp + 0.000001)
        elapsed = now - self.timestamp
        self.timestamp = now

        self.speed = max(
            settings.validation.minimum_speed,
            min(
                settings.validation.max_speed,
                self.speed
                + random.uniform(
                    -settings.validation.speed_jitter,
                    settings.validation.speed_jitter,
                ),
            ),
        )
        distance = self.speed * elapsed
        heading_radians = math.radians(self.heading)
        latitude_radians = math.radians(self.lat)
        self.lat += math.degrees(
            distance
            * math.cos(heading_radians)
            / settings.validation.earth_radius_meters
        )
        longitude_scale = max(abs(math.cos(latitude_radians)), 1e-6)
        self.lon += math.degrees(
            distance
            * math.sin(heading_radians)
            / (settings.validation.earth_radius_meters * longitude_scale)
        )

        self.altitude = max(
            settings.validation.minimum_altitude,
            min(
                settings.validation.max_altitude,
                self.altitude
                + random.uniform(
                    -settings.validation.altitude_jitter,
                    settings.validation.altitude_jitter,
                ),
            ),
        )

        self.battery = max(
            settings.validation.battery_minimum,
            self.battery
            - random.uniform(
                settings.validation.battery_drain_minimum,
                settings.validation.battery_drain_maximum,
            ),
        )

        return self.get_packet()

    def get_packet(self) -> dict[str, Any]:
        """Return the current fields in the wire format expected downstream."""
        return {
            "drone_id": settings.network.drone_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "lat": self.lat,
            "lon": self.lon,
            "altitude": round(
                self.altitude,
                settings.logging.decimal_precision,
            ),
            "speed": round(self.speed, settings.logging.decimal_precision),
            "battery": round(
                self.battery,
                settings.logging.decimal_precision,
            ),
            "heading": self.heading,
        }
