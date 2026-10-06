# SCOUT-X

## Secure Command and Operations for UAV Telemetry — Exfiltration Defense

SCOUT-X is a simulation-based UAV telemetry security system designed to detect suspicious telemetry behavior, evaluate drone trust, enforce defensive responses, and protect mission data during a simulated compromise.

The system combines deterministic telemetry validation, behavioral trust scoring, attack classification, autonomous response, mission-data protection, and ML-based anomaly detection into one security pipeline.

---

## Key Features

* UAV telemetry simulation over UDP
* GPS, altitude, speed, and battery monitoring
* Telemetry consistency and anomaly validation
* Dynamic trust-score calculation
* Attack pattern classification
* Autonomous response escalation
* Movement restriction and drone isolation
* Handoff and Exfiltration Module (HEM)
* AES-GCM protected mission data
* Trusted-peer selection for simulated data transfer
* Packet-loss and tampering simulation
* Best-effort emergency data zeroization
* Isolation Forest-based telemetry anomaly detection
* FastAPI security dashboard
* JSON security event logging
* Automated security report generation

---

## System Architecture

```text
                    UAV Telemetry Simulator
                              |
                              v
                  +------------------------+
                  | Security Middleware    |
                  | Validation / Sanitizer |
                  +-----------+------------+
                              |
                              v
                  +------------------------+
                  | Threat Analysis        |
                  | Attack Classification   |
                  +-----------+------------+
                              |
                 +------------+------------+
                 |                         |
                 v                         v
        Trust Score Engine          ML Anomaly Detector
                 |                         |
                 +------------+------------+
                              |
                              v
                    Response Engine
                              |
                              v
                    Response Enforcer
                              |
                +-------------+-------------+
                |                           |
                v                           v
        HEM Data Protection          Security Logger
                |                           |
                v                           |
       Base / Trusted Peer                 |
                |                           |
                +-------------+-------------+
                              |
                              v
                     FastAPI Dashboard
```

---

## Security Pipeline

SCOUT-X processes telemetry through the following stages:

1. Telemetry generation
2. Telemetry validation
3. Attack-pattern analysis
4. Trust-score evaluation
5. ML anomaly detection
6. Response decision
7. Defensive enforcement
8. Mission-data protection
9. Security event logging
10. Dashboard visualization

---

## Trust-Based Defense

The system maintains a dynamic trust score between `0.0` and `1.0`.

```text
Trust >= 0.80       STANDBY
Trust < 0.80        PREPARE
Trust < 0.50        EVACUATE
Trust <= 0.20       PROTECT
```

Trust decreases when suspicious telemetry behavior is detected and can recover during clean operation.

The response system uses hysteresis to reduce unnecessary state flapping during borderline conditions.

---

## Autonomous Response

SCOUT-X supports escalating responses:

```text
MONITOR
   |
   v
LIMIT_MOVEMENT
   |
   v
ISOLATE_DRONE
   |
   v
FORCE_LAND
```

The selected response depends on the detected threat and current trust level.

---

## HEM: Handoff and Exfiltration Module

The HEM protects mission data when the drone becomes increasingly untrusted.

### Protection phases

```text
STANDBY
   |
   v
PREPARE
   |
   v
EVACUATE
   |
   v
PROTECT
```

### Data protection behavior

* Mission data is divided into priority classes:

  * CRITICAL
  * SENSITIVE
  * ROUTINE
* Data is sealed using AES-256-GCM.
* Base communication is preferred when available.
* Trusted peers can be used as a fallback.
* Peer eligibility considers:

  * Trust score
  * Link availability
  * Distance
  * Recent communication
  * TOTP authentication
* Transfers use chunking and retransmission.
* Simulated packet loss and tampering are supported.
* Critical compromise can trigger best-effort zeroization.

HEM is designed as a **simulation module** and does not represent a real UAV radio or flight-control implementation.

---

## ML Anomaly Detection

SCOUT-X includes a lightweight unsupervised anomaly detector using Isolation Forest.

The model learns telemetry characteristics from clean observations and produces:

```text
ML anomaly classification
ML risk score
```

The ML detector acts as a second analytical signal alongside the deterministic telemetry-validation pipeline.

The primary security response remains based on the validated telemetry and trust-management pipeline.

---

## Attack Scenarios

The demonstration includes four stages:

### Scenario 1: Normal Flight

The drone sends normal telemetry while maintaining a high trust score.

Expected state:

```text
STANDBY
```

### Scenario 2: Telemetry Attack

Suspicious GPS and altitude behavior is introduced.

Expected behavior:

```text
Trust decreases
        |
        v
PREPARE
```

### Scenario 3: Continued Compromise

Suspicious telemetry continues and trust decreases further.

Expected behavior:

```text
EVACUATE
    |
    v
Mission data transferred
```

### Scenario 4: Critical Compromise

Trust reaches the protection threshold.

Expected behavior:

```text
PROTECT
   |
   +--> Data protection
   |
   +--> Zeroization when required
   |
   +--> Drone isolation / landing response
```

---

## Dashboard

The SCOUT-X dashboard provides a live security command interface.

It displays:

* Connection status
* Current trust score
* Security phase
* HEM destination
* Data transferred
* Zeroization status
* Attack severity
* Attack pattern
* Response decision
* Enforcement action
* Telemetry values
* ML anomaly status
* ML risk score
* Security event timeline

### Screenshots

Add project screenshots below:

```text
screenshots/
├── dashboard-normal.png
├── dashboard-attack.png
├── dashboard-protect.png
└── terminal-demo.png
```

Example:

```markdown
![SCOUT-X Dashboard](screenshots/dashboard-normal.png)

![Attack Detection](screenshots/dashboard-attack.png)

![Critical Protection](screenshots/dashboard-protect.png)

![Security Demo](screenshots/terminal-demo.png)
```

---

## Project Structure

```text
SCOUT-X/
│
├── dashboard/
│   ├── app.js
│   ├── index.html
│   ├── server.py
│   └── style.css
│
├── simulation/
│   ├── analysis/
│   ├── demo/
│   ├── ground_control/
│   ├── hem/
│   ├── logging/
│   ├── ml/
│   ├── security/
│   └── ...
│
├── data/
├── tests/
├── attack_log.json
├── hem_log.json
├── requirements.txt
└── README.md
```

---

## Running the Project

### 1. Start the security receiver

From the project root:

```bash
python -m simulation.ground_control.receiver
```

### 2. Start the dashboard

In another terminal:

```bash
python -m uvicorn dashboard.server:app --reload --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000/
```

### 3. Run the security demonstration

In another terminal:

```bash
python -m simulation.demo.run_scenarios
```

The dashboard and receiver will update as the simulated telemetry scenarios are processed.

---

## Testing

The HEM module includes tests covering:

* Standby behavior
* Prepare state
* Evacuation
* Priority-based transfer
* Transfer budget
* Base failure
* Trusted-peer validation
* Distance restrictions
* Packet loss
* Packet tampering
* Zeroization
* Hysteresis
* One-way protection state

The ML module also includes a standalone anomaly-detection test.

---

## Technologies

* Python
* FastAPI
* UDP sockets
* NumPy
* scikit-learn
* Isolation Forest
* AES-GCM
* HKDF
* TOTP
* JSON logging
* HTML
* CSS
* JavaScript

---

## Limitations

SCOUT-X is currently a simulation and research prototype.

It does not currently provide:

* Real UAV flight-control integration
* Real radio hardware integration
* Real swarm-scale communication
* Hardware-backed key storage
* Forensic-grade memory/data destruction
* Hardware-in-the-loop flight testing
* Gazebo-based flight visualization

The HEM transport and UAV communication environment are simulated.

---

## Future Work

Possible future extensions include:

* Hardware-in-the-loop testing
* Real UAV telemetry interfaces
* Secure radio integration
* Hardware-backed cryptographic storage
* More advanced anomaly-detection models
* Multi-drone coordination
* Larger-scale swarm simulations
* Gazebo/ROS integration
* Extended adversarial telemetry datasets

---

## Project Objective

The objective of SCOUT-X is to demonstrate how a UAV security system can move beyond simple attack detection toward **behavior-aware autonomous defense and mission-data protection**.

Instead of only identifying compromised telemetry, the system continuously evaluates trust, escalates defensive responses, and protects mission data as the compromise becomes more severe.

---

## Team

**SCOUT-X Project Team**

Secure Command and Operations for UAV Telemetry — Exfiltration Defense

Developed as an academic cybersecurity and UAV security project.
