"""Centralized settings keep simulation policy consistent across runtime modules."""

import math
import secrets
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class NetworkConfig(BaseModel):
    """Network endpoints and datagram limits used by the local simulation."""

    host: str = "127.0.0.1"
    drone_id: str = Field(default="scout-x-01", min_length=1, max_length=64)
    telemetry_shared_secret: SecretStr = SecretStr("")
    udp_port: int = Field(default=9999, ge=1, le=65535)
    udp_buffer_size: int = Field(default=4096, gt=0)
    max_datagram_size_bytes: int = Field(default=4096, gt=0, le=65507)
    receiver_queue_capacity: int = Field(default=128, gt=0)
    receiver_rate_limit_per_second: float = Field(
        default=20.0,
        gt=0,
        allow_inf_nan=False,
    )
    receiver_burst_capacity: int = Field(default=40, gt=0)
    receiver_source_capacity: int = Field(default=1024, gt=0)
    receiver_event_capacity: int = Field(default=256, gt=0)
    replay_frame_cache_capacity: int = Field(default=4096, gt=0)
    replay_frame_cache_file: Path = Path("logs/replay_frames.sqlite3")
    receiver_poll_interval_seconds: float = Field(
        default=0.25,
        gt=0,
        allow_inf_nan=False,
    )
    tcp_port: int = Field(default=5000, ge=1, le=65535)
    tcp_buffer_size: int = Field(default=1024, gt=0)
    tcp_connect_wait_seconds: float = Field(default=1.0, ge=0)
    telemetry_interval_seconds: float = Field(default=1.0, gt=0)
    allowed_client_ips: list[str] = Field(default_factory=lambda: ["127.0.0.1"])
    attack_start_sequence: int = 5
    attack_end_sequence: int = 15
    dev_mode: bool = True


class TrustConfig(BaseModel):
    """Shared trust and attack-escalation thresholds."""

    protect_threshold: float = Field(default=0.20, ge=0, le=1)
    evacuate_threshold: float = Field(default=0.50, ge=0, le=1)
    prepare_threshold: float = Field(default=0.80, ge=0, le=1)
    standby_threshold: float = Field(default=0.80, ge=0, le=1)
    warning_threshold: float = Field(default=0.70, ge=0, le=1)
    hysteresis_margin: float = Field(default=0.10, ge=0, le=1)
    recovery_rate: float = Field(default=0.02, ge=0)
    recovery_clean_packets: int = Field(default=3, gt=0)
    default_score: float = Field(default=1.0, ge=0, le=1)
    reset_token: SecretStr = SecretStr("")
    classifier_history_window: int = Field(default=10, gt=0)
    classifier_flood_threshold: int = Field(default=5, gt=0)
    classifier_flood_window_seconds: float = Field(default=1.0, gt=0)
    penalty_gps_spoofing: float = Field(default=0.20, ge=0, le=1)
    penalty_gps_jump: float = Field(default=0.18, ge=0, le=1)
    penalty_altitude_manipulation: float = Field(default=0.20, ge=0, le=1)
    penalty_speed_anomaly: float = Field(default=0.12, ge=0, le=1)
    penalty_battery_anomaly: float = Field(default=0.10, ge=0, le=1)
    penalty_replay: float = Field(default=0.25, ge=0, le=1)
    penalty_telemetry_flooding: float = Field(default=0.30, ge=0, le=1)
    penalty_multi_vector: float = Field(default=0.40, ge=0, le=1)
    penalty_unknown: float = Field(default=0.10, ge=0, le=1)
    force_land_attack_streak: int = Field(default=5, ge=0)
    limit_movement_attack_streak: int = Field(default=3, ge=0)
    attack_history_window: int = Field(default=10, gt=0)
    persistent_attack_ratio: float = Field(default=0.70, ge=0, le=1)
    intermittent_attack_ratio: float = Field(default=0.40, ge=0, le=1)

    @field_validator("recovery_rate")
    @classmethod
    def recovery_is_bounded(cls, value: float) -> float:
        """Prevent configuration from making clean packets restore trust too quickly."""
        if value > 0.10:
            raise ValueError("recovery_rate must not exceed 0.10 per clean packet")
        return value

    @model_validator(mode="after")
    def classifier_window_can_detect_floods(self) -> "TrustConfig":
        """Ensure the bounded classifier history can reach its flood threshold."""
        if self.classifier_flood_threshold > self.classifier_history_window:
            raise ValueError(
                "classifier_flood_threshold must not exceed classifier_history_window"
            )
        return self


class ValidationConfig(BaseModel):
    """Physical telemetry limits and deterministic validator tolerances."""

    max_telemetry_payload_bytes: int = Field(default=2048, gt=0, le=65507)
    stale_timestamp_skew_seconds: float = Field(default=60.0, gt=0)
    replay_window_size: int = Field(default=64, gt=0)
    replay_cache_capacity: int = Field(default=1024, gt=0)
    max_drone_id_length: int = Field(default=64, gt=0)
    max_sequence_number: int = Field(default=9223372036854775807, ge=0)
    comparison_tolerance: float = Field(default=1e-9, ge=0)
    altitude_rate_limit_mps: float = Field(default=5.0, ge=0)
    battery_increase_tolerance: float = Field(default=0.25, ge=0)
    earth_radius_meters: float = Field(default=6371000.0, gt=0)
    gps_max_latitude: float = Field(default=90.0, gt=0, le=90)
    gps_max_longitude: float = Field(default=180.0, gt=0, le=180)
    gps_jump_limit_m: float = Field(default=20.0, ge=0)
    gps_degrees_to_meters: float = Field(default=111000.0, gt=0)
    speed_mismatch_limit: float = Field(default=4.0, ge=0)
    max_speed: float = Field(default=120.0, gt=0)
    minimum_speed: float = Field(default=0.0, ge=0)
    max_altitude: float = Field(default=100.0, ge=0)
    minimum_altitude: float = Field(default=0.0, ge=0)
    initial_altitude: float = Field(default=10.0, ge=0)
    initial_speed: float = Field(default=5.0, ge=0)
    gps_jitter: float = Field(default=0.0001, ge=0)
    altitude_jitter: float = Field(default=0.5, ge=0)
    speed_jitter: float = Field(default=0.2, ge=0)
    altitude_attack_offset: float = Field(default=500.0, ge=0)
    latitude_attack_offset: float = Field(default=1.5, ge=0)
    legacy_altitude_step: float = Field(default=1.0, ge=0)
    legacy_battery_drain: float = Field(default=0.1, ge=0)
    altitude_delta_limit: float = Field(default=5.0, ge=0)
    altitude_spoof_delta_limit: float = Field(default=50.0, ge=0)
    battery_minimum: float = Field(default=0.0, ge=0)
    battery_maximum: float = Field(default=100.0, gt=0)
    battery_drain_minimum: float = Field(default=0.05, ge=0)
    battery_drain_maximum: float = Field(default=0.20, ge=0)
    noise_limit: float = Field(default=0.80, ge=0, le=1)
    max_time_delta_seconds: float = Field(default=2.0, gt=0)
    reset_time_delta_seconds: float = Field(default=1.0, gt=0)
    speed_mismatch_penalty: float = Field(default=0.40, ge=0, le=1)
    gps_jump_penalty: float = Field(default=0.40, ge=0, le=1)
    altitude_spike_penalty: float = Field(default=0.30, ge=0, le=1)
    raw_motion_distance_factor: float = Field(default=0.001, ge=0)
    minimum_score: float = Field(default=0.0, ge=0, le=1)
    maximum_score: float = Field(default=1.0, ge=0, le=1)

    @model_validator(mode="after")
    def validate_physical_ranges(self) -> "ValidationConfig":
        """Reject contradictory limits so sanitization cannot invert valid ranges."""
        if self.battery_drain_minimum > self.battery_drain_maximum:
            raise ValueError(
                "battery_drain_minimum must not exceed battery_drain_maximum"
            )
        if self.battery_minimum >= self.battery_maximum:
            raise ValueError("battery_minimum must be less than battery_maximum")
        if self.minimum_speed > self.max_speed:
            raise ValueError("minimum_speed must not exceed max_speed")
        if self.minimum_altitude > self.max_altitude:
            raise ValueError("minimum_altitude must not exceed max_altitude")
        if self.minimum_score >= self.maximum_score:
            raise ValueError("minimum_score must be less than maximum_score")
        return self


class HEMConfig(BaseModel):
    """Handoff, peer eligibility, transfer, and cryptographic parameters."""

    chunk_size: int = Field(default=1024, gt=0)
    retry_limit: int = Field(default=3, ge=0)
    retry_backoff_base_seconds: float = Field(default=0.01, ge=0)
    retry_backoff_max_seconds: float = Field(default=1.0, gt=0)
    retry_jitter_fraction: float = Field(default=0.25, ge=0, le=1)
    transfer_budget: int = Field(default=20000, gt=0)
    peer_distance_limit: float = Field(default=2000.0, gt=0)
    packet_loss_rate: float = Field(default=0.0, ge=0, le=1)
    tamper_rate: float = Field(default=0.0, ge=0, le=1)
    transport_random_seed: int = 7
    peer_minimum_trust: float = Field(default=0.70, ge=0, le=1)
    peer_minimum_link: float = Field(default=0.40, ge=0, le=1)
    peer_stale_limit_seconds: float = Field(default=10.0, ge=0)
    peer_weight_trust: float = Field(default=0.30, ge=0, le=1)
    peer_weight_link: float = Field(default=0.25, ge=0, le=1)
    peer_weight_distance: float = Field(default=0.15, ge=0, le=1)
    peer_weight_recency: float = Field(default=0.15, ge=0, le=1)
    peer_weight_totp: float = Field(default=0.15, ge=0, le=1)
    peer_capacity_bytes: int = Field(default=5000000, gt=0)
    earth_radius_meters: float = Field(default=6371000.0, gt=0)
    totp_step_seconds: int = Field(default=30, gt=0)
    totp_digits: int = Field(default=6, ge=1, le=10)
    totp_window: int = Field(default=1, ge=0, le=10)
    totp_timestamp_freshness_seconds: int = Field(default=10, gt=0)
    totp_demo_secret: SecretStr = SecretStr("")
    mission_id: str = Field(default="mission-sim-01", min_length=1, max_length=128)
    protocol_version: Literal[1] = 1
    aes_key_bits: Literal[256] = 256
    nonce_size_bytes: Literal[12] = 12
    session_challenge_size_bytes: Literal[32] = 32
    hkdf_key_size_bytes: Literal[32] = 32
    hkdf_salt_size_bytes: Literal[16] = 16
    critical_priority: int = 0
    sensitive_priority: int = 1
    routine_priority: int = 2
    base_secret: SecretStr = SecretStr("")

    @model_validator(mode="after")
    def peer_score_weights_sum_to_one(self) -> "HEMConfig":
        """Keep peer score contributions comparable and bounded to 0..1."""
        weights = (
            self.peer_weight_trust,
            self.peer_weight_link,
            self.peer_weight_distance,
            self.peer_weight_recency,
            self.peer_weight_totp,
        )
        if not math.isclose(sum(weights), 1.0, abs_tol=1e-9):
            raise ValueError("HEM peer score weights must sum to 1.0")
        if self.retry_backoff_base_seconds > self.retry_backoff_max_seconds:
            raise ValueError(
                "retry_backoff_base_seconds must not exceed retry_backoff_max_seconds"
            )
        if not (
            self.critical_priority < self.sensitive_priority < self.routine_priority
        ):
            raise ValueError(
                "HEM priorities must be ordered CRITICAL < SENSITIVE < ROUTINE"
            )
        return self


class MLConfig(BaseModel):
    """Isolation Forest parameters and clean-sample requirements."""

    contamination: float = Field(default=0.10, gt=0, le=0.5)
    n_estimators: int = Field(default=200, gt=0)
    training_window: int = Field(default=8, gt=0)
    minimum_training_samples: int = Field(default=5, gt=0)
    feature_window_size: int = Field(default=5, gt=0)
    calibration_fraction: float = Field(
        default=0.20,
        gt=0,
        lt=0.5,
        allow_inf_nan=False,
    )
    risk_threshold: float = Field(default=0.90, ge=0, le=1)
    random_seed: int = 42
    model_path: Path = Path("models/telemetry_iforest.joblib")
    trusted_model_directory: Path = Path("models")
    allow_external_model_paths: bool = True

    @model_validator(mode="after")
    def training_window_is_sufficient(self) -> "MLConfig":
        """Ensure the receiver cannot attempt model fitting before its minimum."""
        if self.training_window < self.minimum_training_samples:
            raise ValueError(
                "training_window must be at least minimum_training_samples"
            )
        return self


class DashboardConfig(BaseModel):
    """Dashboard endpoints, scenario pacing, and browser presentation limits."""

    host: str = "127.0.0.1"
    drone_id: str = Field(default="dashboard-sim", min_length=1, max_length=64)
    port: int = Field(default=8000, ge=1, le=65535)
    reload: bool = False
    public_bind: bool = False
    receiver_host: str | None = None
    packet_delay_seconds: float = Field(default=0.7, ge=0)
    reset_wait_seconds: float = Field(default=0.2, ge=0)
    aircraft_center_latitude: float = 12.9716
    aircraft_center_longitude: float = 77.5946
    aircraft_range: int = Field(default=100, gt=0)
    aircraft_request_timeout_seconds: float = Field(default=8.0, gt=0)
    normal_scenario_packet_count: int = Field(default=8, gt=0)
    demo_attack_stage_one_count: int = Field(default=3, gt=0)
    demo_attack_stage_two_count: int = Field(default=3, gt=0)
    event_limit: int = Field(default=100, gt=0)
    map_zoom: int = Field(default=8, gt=0)
    map_focus_zoom: int = Field(default=10, gt=0)
    initial_target_count: int = Field(default=3, ge=0)
    trail_limit: int = Field(default=250, gt=0)
    timeline_event_limit: int = Field(default=40, gt=0)
    map_refresh_delay_ms: int = Field(default=100, ge=0)
    event_refresh_delay_ms: int = Field(default=250, ge=0)
    scenario_feedback_delay_ms: int = Field(default=1200, ge=0)
    events_poll_interval_ms: int = Field(default=1000, gt=0)
    aircraft_poll_interval_ms: int = Field(default=30000, gt=0)
    simulated_target_refresh_interval_ms: int = Field(default=1500, gt=0)
    simulated_target_motion_period_ms: int = Field(default=12000, gt=0)
    simulated_target_motion_amplitude: float = Field(default=0.12, ge=0)
    simulated_target_motion_baseline: float = Field(default=0.88, ge=0)
    simulated_target_position_jitter: float = Field(default=0.0015, ge=0)
    simulated_target_longitude_frequency: float = Field(default=0.8, gt=0)
    timestamp_milliseconds_cutoff: int = Field(default=1000000000000, gt=0)
    milliseconds_per_second: int = Field(default=1000, gt=0)
    scenario_coordinate_latitude: float = 13.5
    scenario_coordinate_longitude: float = 77.9
    scenario_gps_sequence_increment: float = Field(default=0.0004, ge=0)
    scenario_altitude_base: float = Field(default=100.0, ge=0)
    scenario_altitude_sequence_modulus: int = Field(default=3, gt=0)
    scenario_speed_base: float = Field(default=11.0, ge=0)
    scenario_speed_sequence_modulus: int = Field(default=3, gt=0)
    scenario_battery_base: float = Field(default=95.0, ge=0)
    scenario_battery_modulus: int = Field(default=70, gt=0)
    scenario_battery_floor: float = Field(default=20.0, ge=0)
    scenario_attack_altitude: float = Field(default=250.0, ge=0)
    scenario_attack_speed: float = Field(default=45.0, ge=0)
    scenario_attack_battery: float = Field(default=88.0, ge=0)
    demo_attack_trust_sequence: list[float] = Field(
        default_factory=lambda: [
            0.70,
            0.60,
            0.50,
            0.40,
            0.30,
            0.20,
            0.15,
            0.10,
        ]
    )
    adsb_api_template: str = (
        "https://api.adsb.lol/v2/lat/{latitude}/lon/{longitude}/dist/{range}"
    )
    secondary_targets: list[dict[str, object]] = Field(
        default_factory=lambda: [
            {
                "id": "SIM-02",
                "latOffset": 0.012,
                "lonOffset": 0.018,
                "altitude": 145,
                "speed": 8.5,
                "phase": 0.2,
                "threat": "NORMAL",
            },
            {
                "id": "SIM-03",
                "latOffset": -0.016,
                "lonOffset": 0.010,
                "altitude": 180,
                "speed": 12,
                "phase": 2.1,
                "threat": "WARNING",
            },
            {
                "id": "SIM-04",
                "latOffset": 0.008,
                "lonOffset": -0.022,
                "altitude": 220,
                "speed": 15,
                "phase": 4,
                "threat": "NORMAL",
            },
            {
                "id": "SIM-05",
                "latOffset": -0.024,
                "lonOffset": -0.014,
                "altitude": 110,
                "speed": 6.5,
                "phase": 5.2,
                "threat": "CRITICAL",
            },
            {
                "id": "SIM-06",
                "latOffset": 0.027,
                "lonOffset": -0.006,
                "altitude": 160,
                "speed": 10,
                "phase": 3.2,
                "threat": "NORMAL",
            },
        ]
    )
    normal_scenario_trust: list[float] = Field(
        default_factory=lambda: [0.70, 0.60, 0.50, 0.40, 0.30]
    )
    command_scenario_trust: list[float] = Field(
        default_factory=lambda: [0.60, 0.50, 0.40, 0.30, 0.20]
    )
    critical_scenario_trust: list[float] = Field(
        default_factory=lambda: [0.30, 0.25, 0.20, 0.15, 0.10, 0.05]
    )
    api_key: SecretStr = SecretStr("")
    allowed_origins: list[str] = Field(
        default_factory=lambda: [
            "http://127.0.0.1:8000",
            "http://localhost:8000",
        ]
    )
    request_rate_limit_per_minute: int = Field(default=120, gt=0)
    request_rate_limit_sources: int = Field(default=1024, gt=0)
    max_request_size_bytes: int = Field(default=65536, gt=0)
    event_tail_limit: int = Field(default=1000, gt=0)
    event_tail_bytes: int = Field(default=2097152, gt=0)
    event_page_limit: int = Field(default=100, gt=0)
    event_stream_queue_size: int = Field(default=64, gt=0)
    event_stream_client_limit: int = Field(default=128, gt=0)
    event_stream_heartbeat_seconds: float = Field(default=15.0, gt=0)
    event_stream_poll_seconds: float = Field(default=0.5, gt=0)
    stale_data_seconds: float = Field(default=10.0, gt=0)
    session_cookie_max_age_seconds: int = Field(default=3600, gt=0)
    scenario_ack_timeout_seconds: float = Field(default=2.0, gt=0)


class LoggingConfig(BaseModel):
    """Paths and retention limits for bounded, auditable simulation records."""

    directory: Path = Path("logs")
    attack_log: str = "attack_log.jsonl"
    hem_log: str = "hem_log.jsonl"
    trust_log: str = "trust_events.jsonl"
    hem_test_log: str = "hem_test_log.jsonl"
    demo_telemetry_file: str = "telemetry.csv"
    report_directory: Path = Path("reports")
    max_file_bytes: int = Field(default=5 * 1024 * 1024, gt=0)
    max_total_bytes: int = Field(default=30 * 1024 * 1024, gt=0)
    backup_count: int = Field(default=5, ge=0)
    rotate_interval_seconds: float = Field(default=86400.0, gt=0)
    decimal_precision: int = Field(default=2, ge=0)

    @model_validator(mode="after")
    def total_capacity_includes_active_file(self) -> "LoggingConfig":
        """Reserve room for the integrity anchor alongside one active log."""
        if self.max_total_bytes < self.max_file_bytes + 256:
            raise ValueError(
                "max_total_bytes must exceed max_file_bytes by at least 256 bytes "
                "for the integrity anchor"
            )
        return self


class DemoConfig(BaseModel):
    """Controls isolated motion and sensor demos outside the telemetry pipeline."""

    camera_steps: int = Field(default=20, gt=0)
    camera_interval_seconds: float = Field(default=0.1, ge=0)
    camera_start_x: float = 0.0
    camera_start_y: float = 0.0
    camera_target_x: float = 10.0
    camera_target_y: float = 5.0
    camera_initial_yaw: float = 0.0
    camera_target_step: float = 0.5
    camera_controller_gain: float = Field(default=0.2, ge=0)
    waypoint_coordinates: list[tuple[float, float]] = Field(
        default_factory=lambda: [
            (0.0, 0.0),
            (10.0, 0.0),
            (10.0, 10.0),
            (0.0, 10.0),
        ]
    )
    waypoint_tolerance: float = Field(default=0.5, ge=0)
    waypoint_interpolation: float = Field(default=0.2, ge=0, le=1)
    waypoint_interval_seconds: float = Field(default=0.2, ge=0)
    intrusion_zone_minimum: float = 5.0
    intrusion_zone_maximum: float = 15.0
    intrusion_sample_minimum: int = 0
    intrusion_sample_maximum: int = 20
    intrusion_iterations: int = Field(default=20, gt=0)
    intrusion_interval_seconds: float = Field(default=1.0, ge=0)
    threat_distance_limit: float = Field(default=5.0, ge=0)
    threat_speed_limit: float = Field(default=8.0, ge=0)
    threat_zone_weight: int = Field(default=50, ge=0)
    threat_distance_weight: int = Field(default=30, ge=0)
    threat_speed_weight: int = Field(default=20, ge=0)
    threat_high_threshold: int = Field(default=70, ge=0)
    threat_medium_threshold: int = Field(default=40, ge=0)
    threat_iterations: int = Field(default=10, gt=0)
    threat_distance_sample_minimum: float = Field(default=1.0, ge=0)
    threat_distance_sample_maximum: float = Field(default=20.0, gt=0)
    threat_speed_sample_minimum: float = Field(default=0.0, ge=0)
    threat_speed_sample_maximum: float = Field(default=15.0, gt=0)
    target_linear_speed: float = Field(default=0.5, ge=0)
    target_linear_y: float = 5.0
    target_circular_radius: float = Field(default=10.0, gt=0)
    target_angle_step: float = Field(default=0.1, gt=0)
    target_random_walk_step: float = Field(default=1.0, ge=0)
    target_zigzag_period: int = Field(default=20, gt=0)
    target_zigzag_cutoff: int = Field(default=10, gt=0)
    target_iterations: int = Field(default=20, gt=0)
    telemetry_samples: int = Field(default=50, gt=0)
    telemetry_movement_minimum: float = Field(default=0.1, ge=0)
    telemetry_movement_maximum: float = Field(default=1.0, gt=0)
    telemetry_speed_minimum: float = Field(default=5.0, ge=0)
    telemetry_speed_maximum: float = Field(default=15.0, gt=0)
    telemetry_interval_seconds: float = Field(default=0.1, ge=0)
    telemetry_start_x: float = 0.0
    telemetry_start_y: float = 0.0
    telemetry_start_z: float = 10.0
    sensor_latitude: float = 10.2
    sensor_longitude: float = 5.1
    sensor_altitude: float = 25.4
    sensor_battery: float = 87.0
    surveillance_interval_seconds: float = Field(default=2.0, ge=0)
    telemetry_monitor_interval_seconds: float = Field(default=1.0, ge=0)


class Settings(BaseSettings):
    """Settings are loaded once so invalid policy fails before services start."""

    model_config = SettingsConfigDict(
        env_prefix="SCOUTX_",
        env_nested_delimiter="__",
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    network: NetworkConfig = Field(default_factory=NetworkConfig)
    trust: TrustConfig = Field(default_factory=TrustConfig)
    validation: ValidationConfig = Field(default_factory=ValidationConfig)
    hem: HEMConfig = Field(default_factory=HEMConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    demo: DemoConfig = Field(default_factory=DemoConfig)

    def initialize_runtime_secrets(self) -> None:
        """Generate development-only credentials or fail closed for deployments."""
        secret_fields = (
            (
                "network.telemetry_shared_secret",
                self.network.telemetry_shared_secret,
                32,
            ),
            ("dashboard.api_key", self.dashboard.api_key, 24),
            ("trust.reset_token", self.trust.reset_token, 24),
            ("hem.base_secret", self.hem.base_secret, 32),
            ("hem.totp_demo_secret", self.hem.totp_demo_secret, 20),
        )
        missing = [
            name for name, value, _ in secret_fields if not value.get_secret_value()
        ]
        if missing and not self.network.dev_mode:
            raise ValueError(
                "Required secrets are missing in non-development mode: "
                + ", ".join(missing)
            )
        if not self.network.dev_mode:
            return
        if not self.network.telemetry_shared_secret.get_secret_value():
            self.network.telemetry_shared_secret = SecretStr(secrets.token_urlsafe(32))
        if not self.dashboard.api_key.get_secret_value():
            self.dashboard.api_key = SecretStr(secrets.token_urlsafe(24))
        if not self.trust.reset_token.get_secret_value():
            self.trust.reset_token = SecretStr(secrets.token_urlsafe(24))
        if not self.hem.base_secret.get_secret_value():
            self.hem.base_secret = SecretStr(secrets.token_urlsafe(32))
        if not self.hem.totp_demo_secret.get_secret_value():
            self.hem.totp_demo_secret = SecretStr(secrets.token_urlsafe(20))

    @model_validator(mode="after")
    def validate_trust_thresholds(self) -> "Settings":
        """Fail early because inconsistent thresholds could skip protection phases."""
        trust = self.trust
        if not (
            0
            <= trust.protect_threshold
            < trust.evacuate_threshold
            < trust.prepare_threshold
            <= trust.standby_threshold
            <= 1
        ):
            raise ValueError(
                "trust thresholds must satisfy "
                "0 <= protect < evacuate < prepare <= standby <= 1"
            )
        if trust.prepare_threshold != trust.standby_threshold:
            raise ValueError(
                "prepare_threshold and standby_threshold must match the "
                "single PREPARE/STANDBY boundary"
            )
        if not (
            trust.protect_threshold < trust.warning_threshold < trust.prepare_threshold
        ):
            raise ValueError(
                "warning_threshold must be between protect and prepare thresholds"
            )
        if trust.force_land_attack_streak < trust.limit_movement_attack_streak:
            raise ValueError(
                "force_land_attack_streak must be greater than or equal to "
                "limit_movement_attack_streak"
            )

        distinct_thresholds = sorted(
            {
                trust.protect_threshold,
                trust.evacuate_threshold,
                trust.prepare_threshold,
                trust.standby_threshold,
            }
        )
        minimum_gap = min(
            right - left
            for left, right in zip(distinct_thresholds, distinct_thresholds[1:])
        )
        if trust.hysteresis_margin >= minimum_gap:
            raise ValueError(
                "hysteresis_margin must be smaller than the gap between "
                "distinct trust thresholds"
            )
        return self


try:
    settings = Settings()
except ValidationError as exc:
    raise ValueError(f"Invalid SCOUT-X configuration: {exc}") from exc
