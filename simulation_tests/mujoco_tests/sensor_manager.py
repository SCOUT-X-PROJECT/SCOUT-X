from simulation.config import settings


class SensorManager:

    def get_gps(self) -> tuple[float, float]:
        """Return the configured sample coordinate used by sensor demos."""
        return (
            settings.demo.sensor_latitude,
            settings.demo.sensor_longitude,
        )

    def get_altitude(self) -> float:
        """Keep sample altitude aligned with the standalone telemetry scenario."""
        return settings.demo.sensor_altitude

    def get_battery(self) -> float:
        """Keep sample battery aligned with the standalone telemetry scenario."""
        return settings.demo.sensor_battery

    def get_camera_status(self) -> str:
        """Provide a status field so consumers can represent sensor availability."""
        return "ACTIVE"


if __name__ == "__main__":

    sensor = SensorManager()

    print(sensor.get_gps())
    print(sensor.get_altitude())
    print(sensor.get_battery())
