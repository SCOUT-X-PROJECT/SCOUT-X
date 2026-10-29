
const $ = (id) => document.getElementById(id);

const API = {
    events: "/api/events",
    scenario: "/api/scenario",
};

const MAP = {
    minLat: 12.90,
    maxLat: 13.55,
    minLon: 77.55,
    maxLon: 77.95,
    width: 1000,
    height: 540,
    padding: 35,
};

let previousEventKey = null;
let flightTrailPoints = [];
let latestEvents = [];
let requestInProgress = false;

const SCENARIO_NAMES = {
    normal: "Normal Flight",
    gps_spoofing: "GPS Spoofing",
    command_injection: "Command Injection",
    critical: "Critical Compromise",
};

function valueOf(object, paths, fallback = null) {
    for (const path of paths) {
        let value = object;

        for (const part of path.split(".")) {
            value = value?.[part];
        }

        if (value !== undefined && value !== null) {
            return value;
        }
    }

    return fallback;
}

function formatNumber(value, decimals = 2) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toFixed(decimals) : "--";
}

function display(value, fallback = "--") {
    if (value === undefined || value === null || value === "") {
        return fallback;
    }

    if (typeof value === "boolean") {
        return value ? "YES" : "NO";
    }

    return String(value);
}

function normalizeEvent(event) {
    const telemetry = event.telemetry || event.packet || event.data || event;

    let gps = valueOf(event, [
        "gps",
        "position",
        "telemetry.gps",
        "telemetry.position",
        "packet.gps",
        "data.gps",
    ]);

    let latitude = valueOf(event, [
        "latitude",
        "lat",
        "telemetry.latitude",
        "telemetry.lat",
        "packet.latitude",
        "data.latitude",
    ]);

    let longitude = valueOf(event, [
        "longitude",
        "lon",
        "lng",
        "telemetry.longitude",
        "telemetry.lon",
        "packet.longitude",
        "data.longitude",
    ]);

    if (Array.isArray(gps) && gps.length >= 2) {
        latitude ??= gps[0];
        longitude ??= gps[1];
    } else if (gps && typeof gps === "object") {
        latitude ??= gps.latitude ?? gps.lat;
        longitude ??= gps.longitude ?? gps.lon ?? gps.lng;
    }

    const flags = valueOf(event, [
        "flags",
        "validation_flags",
        "anomaly_flags",
        "telemetry.flags",
    ], []);

    const normalizedFlags = Array.isArray(flags)
        ? flags
        : typeof flags === "string"
            ? [flags]
            : [];

    const trust = valueOf(event, [
        "trust_score",
        "trust",
        "trustScore",
        "telemetry.trust_score",
    ]);

    const mlAnomaly = valueOf(event, [
        "ml_anomaly",
        "anomaly_detected",
        "ml.is_anomaly",
        "ml.anomaly",
    ]);

    const mlScore = valueOf(event, [
        "ml_score",
        "anomaly_score",
        "ml.score",
    ]);

    return {
        raw: event,
        seq: valueOf(event, ["seq", "sequence", "telemetry.seq"], "--"),
        timestamp: valueOf(event, ["timestamp", "time", "created_at"], null),
        latitude: Number(latitude),
        longitude: Number(longitude),
        altitude: valueOf(event, [
            "altitude",
            "alt",
            "telemetry.altitude",
        ]),
        speed: valueOf(event, [
            "speed",
            "ground_speed",
            "telemetry.speed",
        ]),
        battery: valueOf(event, [
            "battery",
            "battery_percent",
            "telemetry.battery",
        ]),
        trust: trust === null ? null : Number(trust),
        severity: valueOf(event, ["severity", "threat_severity"], "--"),
        pattern: valueOf(event, [
            "pattern",
            "attack_pattern",
            "detected_pattern",
        ], "UNKNOWN"),
        threatLevel: valueOf(event, [
            "threat_level",
            "risk_level",
            "level",
        ], "--"),
        response: valueOf(event, [
            "response",
            "response_action",
            "decision",
        ], "--"),
        enforced: valueOf(event, [
            "enforced",
            "enforcement",
            "enforcement_status",
        ], "--"),
        hemPhase: valueOf(event, [
            "hem_phase",
            "hem.phase",
            "hem.phase_name",
        ], null),
        hemState: valueOf(event, [
            "hem_state",
            "hem.status",
            "hem.current_phase",
        ], null),
        hemDestination: valueOf(event, [
            "hem_destination",
            "hem.destination",
            "destination",
        ], null),
        hemMoved: valueOf(event, [
            "hem_moved",
            "hem.data_moved",
            "data_moved",
        ], null),
        hemZeroized: valueOf(event, [
            "hem_zeroized",
            "hem.zeroized",
        ], null),
        hemVault: valueOf(event, [
            "hem.vault",
            "vault",
        ], null),
        mlAnomaly,
        mlScore,
        flags: normalizedFlags,
        telemetry,
    };
}

function projectGps(latitude, longitude) {
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
        return null;
    }

    const x = MAP.padding +
        ((longitude - MAP.minLon) / (MAP.maxLon - MAP.minLon)) *
        (MAP.width - MAP.padding * 2);

    const y = MAP.height - MAP.padding -
        ((latitude - MAP.minLat) / (MAP.maxLat - MAP.minLat)) *
        (MAP.height - MAP.padding * 2);

    return {
        x: Math.max(MAP.padding, Math.min(MAP.width - MAP.padding, x)),
        y: Math.max(MAP.padding, Math.min(MAP.height - MAP.padding, y)),
    };
}

function setText(id, text) {
    const element = $(id);
    if (element) element.textContent = text;
}

function setClass(element, className) {
    if (element) element.className = className;
}

function updateConnection(connected, message) {
    const dot = $("connection-dot");

    setText("connection-status", message);

    if (dot) {
        dot.classList.toggle("connected", connected);
        dot.classList.toggle("disconnected", !connected);
    }
}

function updateFlightMap(event) {
    const position = projectGps(event.latitude, event.longitude);
    const marker = $("drone-marker");
    const trail = $("flight-trail");
    const alert = $("map-alert");

    if (!position || !marker) {
        setText("flight-status", "WAITING FOR GPS");
        setText("map-telemetry-state", "NO POSITION");
        return;
    }

    const eventKey = `${event.seq}-${event.latitude}-${event.longitude}`;

    if (eventKey !== previousEventKey) {
        flightTrailPoints.push(`${position.x.toFixed(1)},${position.y.toFixed(1)}`);

        if (flightTrailPoints.length > 120) {
            flightTrailPoints.shift();
        }

        previousEventKey = eventKey;
    }

    marker.setAttribute(
        "transform",
        `translate(${position.x.toFixed(1)} ${position.y.toFixed(1)})`
    );

    if (trail) {
        trail.setAttribute("points", flightTrailPoints.join(" "));
    }

    const suspicious =
        event.flags.length > 0 ||
        (event.trust !== null && event.trust < 0.5) ||
        String(event.severity).toUpperCase() === "HIGH" ||
        String(event.severity).toUpperCase() === "CRITICAL";

    if (alert) {
        alert.setAttribute(
            "transform",
            `translate(${position.x - 500} ${position.y - 270})`
        );
        alert.setAttribute("opacity", suspicious ? "1" : "0");
    }

    setText("flight-status", suspicious ? "THREAT INDICATED" : "TRACKING");
    setText("map-telemetry-state", "TELEMETRY RECEIVED");
    setText("map-altitude", `${formatNumber(event.altitude, 1)} m`);
    setText("map-speed", `${formatNumber(event.speed, 1)} m/s`);
    setText(
        "map-coordinates",
        `${formatNumber(event.latitude, 5)}, ${formatNumber(event.longitude, 5)}`
    );
}

function updateRadar(event) {
    const screen = $("radar-screen");
    const targets = $("radar-targets");

    if (!screen || !targets) return;

    const position = projectGps(event.latitude, event.longitude);

    if (!position) {
        setText("radar-state", "NO POSITION");
        setText("radar-count", "0");
        setText("radar-last-event", "No GPS data");
        setText("radar-threat", "NO DATA");
        targets.replaceChildren();
        return;
    }

    const normalizedX = (position.x - MAP.padding) /
        (MAP.width - MAP.padding * 2);

    const normalizedY = (position.y - MAP.padding) /
        (MAP.height - MAP.padding * 2);

    const left = 15 + normalizedX * 70;
    const top = 15 + normalizedY * 70;

    targets.replaceChildren();

    const target = document.createElement("div");
    target.className = "radar-target";

    const suspicious =
        event.flags.length > 0 ||
        (event.trust !== null && event.trust < 0.5) ||
        ["HIGH", "CRITICAL"].includes(String(event.severity).toUpperCase());

    if (suspicious) {
        target.classList.add(
            String(event.severity).toUpperCase() === "CRITICAL"
                ? "critical"
                : "warning"
        );
    }

    target.style.left = `${left}%`;
    target.style.top = `${top}%`;
    target.title = "UAV-01 · Simulated telemetry target";
    targets.appendChild(target);

    setText("radar-count", "1");
    setText("radar-state", suspicious ? "THREAT INDICATED" : "TRACKING");
    setText("radar-last-event", `SEQ ${display(event.seq)}`);
    setText(
        "radar-threat",
        suspicious
            ? display(event.severity, "SUSPICIOUS").toUpperCase()
            : "NO FLAGGED THREAT"
    );
}

function updateTrust(event) {
    const score = event.trust;
    const fill = $("trust-fill");

    if (score === null || !Number.isFinite(score)) {
        setText("trust-label", "Awaiting trust score");
        setText("trust-value", "--");
        if (fill) fill.style.width = "0%";
        return;
    }

    const percentage = Math.max(0, Math.min(100, score * 100));

    setText(
        "trust-label",
        score >= 0.7 ? "TRUSTED" : score >= 0.3 ? "DEGRADED" : "LOW TRUST"
    );
    setText("trust-value", score.toFixed(2));

    if (fill) {
        fill.style.width = `${percentage}%`;
        fill.style.background =
            score >= 0.7 ? "#55e6a4" :
            score >= 0.3 ? "#e8c45c" :
            "#ff625c";
    }
}

function updateTelemetry(event) {
    setText("telemetry-seq", display(event.seq));
    setText("telemetry-altitude", `${formatNumber(event.altitude, 1)} m`);
    setText("telemetry-speed", `${formatNumber(event.speed, 1)} m/s`);
    setText("telemetry-battery", `${formatNumber(event.battery, 1)}%`);
    setText("telemetry-latitude", formatNumber(event.latitude, 5));
    setText("telemetry-longitude", formatNumber(event.longitude, 5));
}

function updateThreat(event) {
    setText("threat-severity", display(event.severity).toUpperCase());
    setText("threat-pattern", display(event.pattern));
    setText("threat-level", display(event.threatLevel));
    setText("threat-response", display(event.response));
    setText("threat-enforced", display(event.enforced));
}

/*
 * Find the current HEM episode rather than mixing transfers from
 * earlier scenarios into the current scenario's displayed totals.
 *
 * The receiver starts each scenario with a fresh vault. A new
 * PREPARE transition marks the beginning of that scenario's HEM run.
 */
function getCurrentHemEpisode() {
    const events = latestEvents.map(normalizeEvent);

    if (events.length === 0) {
        return [];
    }

    let startIndex = -1;

    for (let i = events.length - 1; i >= 0; i--) {
        if (String(events[i].hemPhase).toUpperCase() !== "PREPARE") {
            continue;
        }

        const previousPhase = i > 0
            ? String(events[i - 1].hemPhase).toUpperCase()
            : "";

        if (previousPhase !== "PREPARE") {
            startIndex = i;
            break;
        }
    }

    if (startIndex >= 0) {
        return events.slice(startIndex);
    }

    // Fallback for logs where the start of the current episode
    // is outside the available event window.
    return events.slice(-30);
}

function getVaultStatus(vault) {
    if (!vault || typeof vault !== "object" || Array.isArray(vault)) {
        return null;
    }

    const statuses = Object.entries(vault)
        .filter(([, count]) => Number(count) > 0)
        .map(([status]) => status.toUpperCase());

    if (statuses.includes("PURGED")) return "PURGED";
    if (statuses.includes("TRANSFERRED")) return "TRANSFERRED";
    if (statuses.includes("SEALED")) return "SEALED";

    return statuses[0] || null;
}

function updateHem(event) {
    const episode = getCurrentHemEpisode();
    const hemEvents = episode.length > 0 ? episode : [event];

    // Keep the highest transfer count reached during this scenario.
    // A later packet with moved: 0 must not erase a prior transfer.
    const movedValues = hemEvents
        .map((item) => Number(item.hemMoved))
        .filter((value) => Number.isFinite(value) && value >= 0);

    const totalMoved = movedValues.length > 0
        ? Math.max(...movedValues)
        : null;

    // Prefer the latest known destination in the current HEM episode.
    let destination = null;

    for (let i = hemEvents.length - 1; i >= 0; i--) {
        const value = hemEvents[i].hemDestination;

        if (value !== null && value !== undefined && value !== "") {
            destination = value;
            break;
        }
    }

    // Read the vault status from the actual latest HEM state.
    const latestHemEvent = hemEvents[hemEvents.length - 1];
    const vaultStatus = getVaultStatus(latestHemEvent.hemVault);

    const zeroizationEvents = hemEvents
        .map((item) => item.hemZeroized)
        .filter((value) => value !== null && value !== undefined);

    const zeroized = zeroizationEvents.some(
        (value) => value === true || value === 1 ||
            String(value).toLowerCase() === "true"
    );

    setText(
        "hem-phase",
        display(event.hemPhase, "NO PHASE DATA").toUpperCase()
    );

    setText(
        "hem-current-phase",
        display(event.hemState, "Not reported")
    );

    setText(
        "hem-destination",
        destination ? String(destination).toUpperCase() : "--"
    );

    setText(
        "hem-moved",
        totalMoved === null ? "--" : String(totalMoved)
    );

    // Show zeroization and vault status together in the existing
    // Vault / zeroization field. Do not claim zeroization occurred
    // when the receiver has not reported it.
    let vaultDisplay;

    if (zeroized) {
        vaultDisplay = "YES · ZEROIZED";
    } else if (vaultStatus) {
        vaultDisplay = `NO · ${vaultStatus}`;
    } else {
        vaultDisplay = "NO";
    }

    setText("hem-zeroized", vaultDisplay);
}

function updateMachineLearning(event) {
    const anomaly = event.mlAnomaly;
    const score = event.mlScore;

    setText(
        "ml-anomaly-status",
        anomaly === null
            ? "Not reported"
            : anomaly === true || anomaly === 1
                ? "ANOMALY"
                : anomaly === false || anomaly === 0
                    ? "NO ANOMALY"
                    : display(anomaly)
    );

    setText("ml-anomaly", display(anomaly));
    setText(
        "ml-score",
        score === null ? "--" : formatNumber(score, 4)
    );
}

function formatTimestamp(timestamp) {
    if (!timestamp) return "TIME UNKNOWN";

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return String(timestamp);
    }

    return date.toLocaleTimeString();
}

function renderTimeline(events) {
    const timeline = $("event-timeline");
    if (!timeline) return;

    setText("event-count", `${events.length} EVENTS`);

    if (events.length === 0) {
        timeline.innerHTML = `
            <div class="empty-state">
                Waiting for telemetry events from the receiver...
            </div>
        `;
        return;
    }

    timeline.replaceChildren();

    events.slice(-30).reverse().forEach((rawEvent) => {
        const event = normalizeEvent(rawEvent);
        const item = document.createElement("div");
        item.className = "event-item";

        const suspicious =
            event.flags.length > 0 ||
            (event.trust !== null && event.trust < 0.5) ||
            ["HIGH", "CRITICAL"].includes(String(event.severity).toUpperCase());

        const marker = document.createElement("span");
        marker.className = `event-marker ${suspicious ? "danger" : "safe"}`;

        const content = document.createElement("div");
        content.className = "event-content";

        const heading = document.createElement("strong");
        heading.textContent = `SEQ ${display(event.seq)} · ${
            display(event.pattern, "TELEMETRY").toUpperCase()
        }`;

        const details = document.createElement("p");
        const flagsText = event.flags.length
            ? ` · Flags: ${event.flags.join(", ")}`
            : "";

        details.textContent =
            `Trust: ${event.trust === null ? "--" : event.trust.toFixed(2)}` +
            ` · Response: ${display(event.response)}` +
            flagsText;

        const time = document.createElement("time");
        time.textContent = formatTimestamp(event.timestamp);

        content.append(heading, details);
        item.append(marker, content, time);
        timeline.appendChild(item);
    });
}

function renderLatestEvent(event) {
    const normalized = normalizeEvent(event);

    updateFlightMap(normalized);
    updateRadar(normalized);
    updateTrust(normalized);
    updateTelemetry(normalized);
    updateThreat(normalized);
    updateHem(normalized);
    updateMachineLearning(normalized);
}

async function refreshEvents() {
    if (requestInProgress) return;
    requestInProgress = true;

    try {
        const response = await fetch(API.events, {
            cache: "no-store",
        });

        if (!response.ok) {
            throw new Error(`Events API returned ${response.status}`);
        }

        const data = await response.json();

        const events = Array.isArray(data)
            ? data
            : Array.isArray(data.events)
                ? data.events
                : [];

        latestEvents = events;
        updateConnection(true, "CONNECTED");
        renderTimeline(events);

        if (events.length > 0) {
            renderLatestEvent(events[events.length - 1]);
        }
    } catch (error) {
        updateConnection(false, "DISCONNECTED");
        console.error("Telemetry refresh failed:", error);
    } finally {
        requestInProgress = false;
    }
}

async function launchScenario(scenario) {
    const feedback = $("scenario-feedback");
    const buttons = document.querySelectorAll("[data-scenario]");

    buttons.forEach((button) => {
        button.disabled = true;
    });

    if (feedback) {
        feedback.textContent =
            `Transmitting ${SCENARIO_NAMES[scenario] || scenario} scenario...`;
    }

    try {
        const response = await fetch(API.scenario, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ scenario }),
        });

        const result = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(
                result.detail || `Request failed: ${response.status}`
            );
        }

        if (feedback) {
            feedback.textContent =
                `${SCENARIO_NAMES[scenario] || scenario}: scenario request accepted. ` +
                "Waiting for receiver events...";
        }

        await refreshEvents();
    } catch (error) {
        if (feedback) {
            feedback.textContent = `Scenario failed: ${error.message}`;
        }

        console.error("Scenario launch failed:", error);
    } finally {
        buttons.forEach((button) => {
            button.disabled = false;
        });
    }
}

document.querySelectorAll("[data-scenario]").forEach((button) => {
    button.addEventListener("click", () => {
        launchScenario(button.dataset.scenario);
    });
});

refreshEvents();
setInterval(refreshEvents, 1000);
