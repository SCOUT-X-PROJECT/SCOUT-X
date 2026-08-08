# SCOUT-X: Secure Command and Operations for UAV Telemetry — Exfiltration Defense

<p align="center">
  <b>A behavioral trust-based cyber defense and autonomous response framework for UAV systems operating in contested environments.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/VTU-BIC685%20Major%20Project-blue.svg" alt="VTU Course">
  <img src="https://img.shields.io/badge/Python-3.10%2B-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/Simulators-Gazebo%20%7C%20MuJoCo%20%7C%20Isaac-orange.svg" alt="Simulators">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

---

## 📌 1. Project Overview & Problem Statement

Unmanned Aerial Vehicles (UAVs) deployed in sensitive surveillance and defense missions frequently encounter contested network conditions where command-and-control links are vulnerable to GPS spoofing, command injection, and data exfiltration. 

Most existing UAV security models focus solely on channel encryption or raise alarms without specifying actions. **SCOUT-X** addresses this critical research gap by introducing an **onboard behavioral trust-based cyber defense framework**. Instead of relying on a compromised Ground Control Station (GCS), SCOUT-X continuously cross-validates incoming telemetry streams, dynamically calculates trust scores, classifies threats, and executes tiered autonomous responses—such as altitude clamping and data exfiltration defense—within a single telemetry cycle.

---

## 🏗️ 2. System Architecture

SCOUT-X operates through an end-to-end unidirectional pipeline that processes telemetry, inspects consistency, evaluates trust decay, and enforces autonomous mitigation:

```text
[ UAV Telemetry Engine / Simulators ]
               │
               ▼ (UDP / MAVLink Stream)
[ 1. Ingestion & Sanitization Layer ] ──► Validates bounds, battery, & timestamps
               │
               ▼
[ 2. Multi-Sensor Validation Layer ]  ──► ConsistencyValidator & MotionValidator
                                           (Checks GPS distance jumps, alt spikes, speed deltas)
               │
               ▼
[ 3. Dynamic Trust-Score Engine ]     ──► Computes T(t) [0.0 to 1.0] (Decays on flag, recovers on clean)
               │
               ▼
[ 4. Threat Classification Logic ]    ──► Categorizes threat: ALT_SPOOF, GPS_HIJACK, SENSOR_DESYNC
               │
               ▼
[ 5. Autonomous Response Enforcer ]   ──► Executes mitigation: ALTITUDE_CLAMPED, TRUST_LOW_MODE, ISOLATED
               │
               ▼
[ 6. Persistent Logging & Dashboard ] ──► attack_log.json & Threat Console Dashboard
