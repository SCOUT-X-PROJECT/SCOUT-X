
from datetime import datetime
from pathlib import Path
import json
import socket
import threading
import time

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel


BASE_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = BASE_DIR / "dashboard"
LOG_FILE = BASE_DIR / "attack_log.json"

RECEIVER_HOST = "127.0.0.1"
RECEIVER_PORT = 9999
PACKET_DELAY = 0.7

app = FastAPI(title="SCOUT-X Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scenario_lock = threading.Lock()
scenario_state = {
    "running": False,
    "name": None,
    "last_error": None,
}


class ScenarioRequest(BaseModel):
    scenario: str


def read_events():
    if not LOG_FILE.exists():
        return []

    events = []

    try:
        with LOG_FILE.open("r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []

    return events


def next_sequence():
    highest = 0

    for event in read_events():
        try:
            highest = max(highest, int(event.get("seq", 0)))
        except (TypeError, ValueError):
            continue

    return highest + 1


def normal_packet(seq):
    return {
        "timestamp": datetime.now().isoformat(),
        "seq": seq,
        "gps": [
            12.9716 + (seq * 0.0004),
            77.5946 + (seq * 0.0004),
        ],
        "altitude": 100 + (seq % 3),
        "speed": 11 + (seq % 3),
        "battery": max(20, 95 - (seq % 70)),
        "trust_score": 1.0,
        "validation": {
            "is_anomalous": False,
            "flags": [],
        },
    }


def attack_packet(seq, trust, scenario):
    packet = {
        "timestamp": datetime.now().isoformat(),
        "seq": seq,
        "gps": [13.5000, 77.9000],
        "altitude": 250,
        "speed": 45,
        "battery": 88,
        "trust_score": trust,
        "validation": {
            "is_anomalous": True,
            "flags": [],
        },
    }

    if scenario in ("gps_spoofing", "critical"):
        packet["validation"]["flags"] = [
            "GPS_POSITION_JUMP",
            "ALTITUDE_ANOMALY",
        ]
    elif scenario == "command_injection":
        packet["command"] = {
            "type": "CHANGE_WAYPOINT",
            "target": [13.5000, 77.9000],
            "authorized": False,
        }
        packet["validation"]["flags"] = ["COMMAND_INJECTION"]

    return packet


def build_scenario(scenario, start_seq):
    if scenario == "normal":
        return [
            normal_packet(start_seq + i)
            for i in range(1, 9)
        ]

    if scenario == "gps_spoofing":
        trust_values = [0.70, 0.60, 0.50, 0.40, 0.30]
    elif scenario == "command_injection":
        trust_values = [0.60, 0.50, 0.40, 0.30, 0.20]
    elif scenario == "critical":
        trust_values = [0.30, 0.25, 0.20, 0.15, 0.10, 0.05]
    else:
        raise ValueError("Unsupported scenario")

    return [
        attack_packet(start_seq + i, trust, scenario)
        for i, trust in enumerate(trust_values, start=1)
    ]


def send_scenario(scenario):
    try:
        packets = build_scenario(scenario, next_sequence())

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            control_message = {
                "_scoutx_control": "scenario_start",
                "scenario": scenario,
            }
            sock.sendto(
                json.dumps(control_message).encode("utf-8"),
                (RECEIVER_HOST, RECEIVER_PORT),
            )

            # Ensure the receiver processes the reset first.
            time.sleep(0.2)

            for packet in packets:
                sock.sendto(
                    json.dumps(packet).encode("utf-8"),
                    (RECEIVER_HOST, RECEIVER_PORT),
                )
                time.sleep(PACKET_DELAY)

    except Exception as exc:
        with scenario_lock:
            scenario_state["last_error"] = str(exc)
    finally:
        with scenario_lock:
            scenario_state["running"] = False
            scenario_state["name"] = None


@app.get("/")
def dashboard():
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.get("/api/events")
def get_events():
    events = read_events()
    return {
        "count": len(events),
        "events": events[-100:],
    }


@app.get("/api/latest")
def get_latest():
    events = read_events()

    if not events:
        return {"connected": False, "event": None}

    return {"connected": True, "event": events[-1]}


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "log_file": str(LOG_FILE),
        "log_exists": LOG_FILE.exists(),
    }


@app.get("/api/scenario/status")
def get_scenario_status():
    with scenario_lock:
        return dict(scenario_state)


@app.post("/api/scenario")
def launch_scenario(
    request: ScenarioRequest,
    background_tasks: BackgroundTasks,
):
    allowed_scenarios = {
        "normal",
        "gps_spoofing",
        "command_injection",
        "critical",
    }

    if request.scenario not in allowed_scenarios:
        raise HTTPException(
            status_code=400,
            detail="Unknown scenario",
        )

    with scenario_lock:
        if scenario_state["running"]:
            raise HTTPException(
                status_code=409,
                detail="A scenario is already running",
            )

        scenario_state["running"] = True
        scenario_state["name"] = request.scenario
        scenario_state["last_error"] = None

    background_tasks.add_task(send_scenario, request.scenario)

    return {
        "accepted": True,
        "scenario": request.scenario,
        "message": "Simulated telemetry sent to the SCOUT-X receiver.",
    }


app.mount(
    "/dashboard",
    StaticFiles(directory=DASHBOARD_DIR),
    name="dashboard",
)
