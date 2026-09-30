const API_BASE = "";

const elements = {
    connectionDot: document.getElementById("connection-dot"),
    connectionText: document.getElementById("connection-text"),

    trustValue: document.getElementById("trust-value"),
    trustFill: document.getElementById("trust-fill"),
    trustLabel: document.getElementById("trust-label"),

    hemPhase: document.getElementById("hem-phase"),
    hemDestination: document.getElementById("hem-destination"),
    hemMoved: document.getElementById("hem-moved"),
    hemZeroized: document.getElementById("hem-zeroized"),
    hemLost: document.getElementById("hem-lost"),

    severity: document.getElementById("severity"),
    pattern: document.getElementById("pattern"),
    response: document.getElementById("response"),
    enforced: document.getElementById("enforced"),
    flags: document.getElementById("flags"),

    sequence: document.getElementById("sequence"),
    gps: document.getElementById("gps"),
    altitude: document.getElementById("altitude"),
    speed: document.getElementById("speed"),
    battery: document.getElementById("battery"),

    eventCount: document.getElementById("event-count"),
    timeline: document.getElementById("timeline")
};


function setConnection(connected) {
    elements.connectionDot.className =
        connected
            ? "status-dot online"
            : "status-dot offline";

    elements.connectionText.textContent =
        connected
            ? "LIVE"
            : "DISCONNECTED";
}


function updateTrust(trust) {
    const value = Number.isFinite(Number(trust))
        ? Number(trust)
        : 1.0;

    const percentage = Math.max(0, Math.min(100, value * 100));

    elements.trustValue.textContent = value.toFixed(2);
    elements.trustFill.style.width = `${percentage}%`;

    let label = "NORMAL";

    if (value <= 0.2) {
        label = "PROTECT";
    } else if (value < 0.5) {
        label = "EVACUATE";
    } else if (value < 0.8) {
        label = "PREPARE";
    }

    elements.trustLabel.textContent = label;
}


function updateHem(event) {
    elements.hemPhase.textContent =
        event.hem_phase || "STANDBY";

    elements.hemDestination.textContent =
        event.hem_destination || "None";

    elements.hemMoved.textContent =
        event.hem_moved ?? 0;

    elements.hemZeroized.textContent =
        event.hem_zeroized ? "YES" : "NO";

    elements.hemLost.textContent =
        event.items_lost_to_zeroize ?? 0;
}


function updateThreat(event) {
    elements.severity.textContent =
        event.severity || "NORMAL";

    elements.pattern.textContent =
        event.pattern || "Unknown";

    elements.response.textContent =
        event.response || "NORMAL_OPERATION";

    elements.enforced.textContent =
        event.enforced || "NONE";

    const flags = event.flags || [];

    elements.flags.textContent =
        flags.length > 0
            ? flags.join(", ")
            : "None";
}


function updateTelemetry(event) {
    elements.sequence.textContent =
        `SEQ ${event.seq ?? "--"}`;

    elements.gps.textContent =
        event.gps ?? "--";

    elements.altitude.textContent =
        event.altitude ?? "--";

    elements.speed.textContent =
        event.speed ?? "--";

    elements.battery.textContent =
        event.battery ?? "--";
}


function formatTime(timestamp) {
    if (!timestamp) {
        return "--";
    }

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }

    return date.toLocaleTimeString();
}


function renderTimeline(events) {
    elements.eventCount.textContent =
        `${events.length} events`;

    if (!events.length) {
        elements.timeline.innerHTML = `
            <div class="empty-state">
                Waiting for telemetry events...
            </div>
        `;
        return;
    }

    const recentEvents = [...events]
        .reverse()
        .slice(0, 25);

    elements.timeline.innerHTML = recentEvents
        .map(event => `
            <div class="timeline-entry">

                <span class="timeline-time">
                    ${formatTime(event.timestamp)}
                </span>

                <span class="timeline-seq">
                    SEQ ${event.seq ?? "--"}
                </span>

                <span class="timeline-pattern">
                    ${event.pattern || "UNKNOWN"}
                </span>

                <span class="timeline-response">
                    ${event.response || "NONE"}
                </span>

            </div>
        `)
        .join("");
}


async function loadDashboard() {
    try {
        const response = await fetch(
            `${API_BASE}/api/events`,
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("Dashboard API unavailable");
        }

        const data = await response.json();

        setConnection(true);

        const events = data.events || [];

        renderTimeline(events);

        if (events.length > 0) {
            const latest = events[events.length - 1];

            updateTrust(latest.trust_score);
            updateHem(latest);
            updateThreat(latest);
            updateTelemetry(latest);
        }

    } catch (error) {
        setConnection(false);
    }
}


loadDashboard();

setInterval(loadDashboard, 1000);