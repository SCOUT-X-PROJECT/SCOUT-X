# SCOUT-X: Secure Command and Operations for UAV Telemetry — eXtended

> A behavioral trust-based cyber defense and autonomous response framework for UAV systems operating in contested environments.

---

## 1. Project Overview & Problem Statement

Unmanned Aerial Vehicles (UAVs) deployed in sensitive surveillance and defense missions frequently encounter contested network conditions where command-and-control links are vulnerable to GPS spoofing, command injection, and data exfiltration.

Most existing UAV security models focus solely on channel encryption or raise alarms without specifying actions. **SCOUT-X** addresses this critical research gap by introducing an **onboard behavioral trust-based cyber defense framework**.

Instead of relying on a compromised Ground Control Station (GCS), SCOUT-X continuously cross-validates incoming telemetry streams, dynamically calculates trust scores, classifies threats, and executes tiered autonomous responses, such as altitude clamping and data exfiltration defense, within a single telemetry cycle.

---

## 2. System Architecture

SCOUT-X operates through an end-to-end unidirectional pipeline that processes telemetry, inspects consistency, evaluates trust decay, and enforces autonomous mitigation:

```text
[ UAV Telemetry Engine / Simulators ]
               │
               ▼ (UDP / MAVLink Stream)
[ 1. Ingestion & Sanitization Layer ] ──► Validates bounds, battery, & timestamps
               │
               ▼
[ 2. Multi-Sensor Validation Layer ] ──► ConsistencyValidator & MotionValidator
                                           (Checks GPS distance jumps, alt spikes, speed deltas)
               │
               ▼
[ 3. Dynamic Trust-Score Engine ] ──► Computes T(t) [0.0 to 1.0]
                                      (Decays on flag, recovers on clean)
               │
               ▼
[ 4. Threat Classification Logic ] ──► Categorizes threat:
                                      ALT_SPOOF, GPS_HIJACK, SENSOR_DESYNC
               │
               ▼
[ 5. Autonomous Response Enforcer ] ──► Executes mitigation:
                                      ALTITUDE_CLAMPED, TRUST_LOW_MODE, ISOLATED
               │
               ▼
[ 6. Persistent Logging & Dashboard ] ──► attack_log.json & Threat Console Dashboard
```

---

## 3. Multi-Platform Simulation Rigor

SCOUT-X has been cross-tested across three robotics simulation environments to verify physical dynamics, sensor noise models, and edge-compute visual tracking.

| Simulation Engine                        | Focus & Verification Objective                                                                                     | Key Test Directories / Files                                  |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------- |
| **MuJoCo** (`/tests/mujoco_tests/`)      | High-speed rigid-body physics, kinematic bounding, and rapid trust-decay tracking under forced state manipulation. | `model.xml`, `test_mujoco_suite.py`, `intrusion_detection.py` |
| **Gazebo** (`/tests/gazebo_tests/`)      | Realistic environmental modeling, wind disturbance vectors, sensor noise profiles, and MAVLink UDP streams.        | `basic_test.world`, `/scenarios/`, `/scripts/`                |
| **NVIDIA Isaac** (`/tests/isaac_tests/`) | High-fidelity 3D optical rendering, camera feeds, and edge-compute visual tracking specifications.                 | `sample_scene.usd`, `dataset_notes.txt`                       |

---

## 4. Quick Start & Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/SCOUT-X-PROJECT/SCOUT-X.git
cd SCOUT-X
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Run the Core Simulation Pipeline

To execute the live telemetry simulation, security middleware, attack injection, and automated response enforcer:

```bash
python simulation/runner/simulation_runner.py
```

### Step 4: Run Threat Analytics & Dashboard

To inspect attack logs and generate summary reports:

```bash
python simulation/analysis/threat_dashboard.py
python simulation/analysis/report_generator.py
```

---

## 5. Research Baseline & Literature Survey

As part of the Phase 1 requirements, a comprehensive literature survey comprising **45 open-access papers** across five thematic areas was conducted:

1. UAV & Drone Telemetry Security
2. GPS Spoofing Detection Methods
3. MAVLink Protocol Vulnerabilities
4. Anomaly Detection & Machine Learning in UAVs
5. Trust-Based Security Systems & Autonomous Defense

Refer to `SCOUTX_LitSurvey_FinalList(Sheet5).csv` in the repository for the complete structured dataset and direct paper links.

---

## 6. Tech Stack

* **Languages:** Python 3.10+
* **Simulation Engines:** Gazebo, MuJoCo, NVIDIA Isaac SDK / Omniverse USD
* **Protocols:** MAVLink, UDP / TCP Sockets
* **Core Libraries:** NumPy, OpenPyXL, Matplotlib, Custom Security Middleware & Trust Engines

---



