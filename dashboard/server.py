from pathlib import Path
import json

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse


BASE_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = BASE_DIR / "dashboard"
LOG_FILE = BASE_DIR / "attack_log.json"


app = FastAPI(title="SCOUT-X Dashboard")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def read_events():
    if not LOG_FILE.exists():
        return []

    events = []

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
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


@app.get("/")
def dashboard():
    return FileResponse(DASHBOARD_DIR / "index.html")


@app.get("/api/events")
def get_events():
    events = read_events()

    return {
        "count": len(events),
        "events": events[-100:]
    }


@app.get("/api/latest")
def get_latest():
    events = read_events()

    if not events:
        return {
            "connected": False,
            "event": None
        }

    return {
        "connected": True,
        "event": events[-1]
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "log_file": str(LOG_FILE),
        "log_exists": LOG_FILE.exists()
    }


app.mount(
    "/dashboard",
    StaticFiles(directory=DASHBOARD_DIR),
    name="dashboard"
)