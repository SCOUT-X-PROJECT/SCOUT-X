
"use strict";

const API = {
    events: "/api/events",
    scenario: "/api/scenario",
    health: "/api/health",
    aircraft: "/api/aircraft"
};

const $ = (id) => document.getElementById(id);

const state = {
    events: [],
    latest: null,
    map: null,
    primaryMarker: null,
    primaryTrail: null,
    trailPoints: [],
    secondaryMarkers: new Map(),
    secondaryTrails: new Map(),
    aircraftMarkers: new Map(),
    aircraft: [],
    targetCount: 3,
    selectedTarget: "SCOUT-X",
    lastEventKey: null,
    lastScenario: null,
    mapReady: false,
    fetchBusy: false,
    aircraftFetchBusy: false,
    aircraftLastUpdated: null
};

const SECONDARY_TARGETS = [
    { id: "SIM-02", latOffset: 0.012, lonOffset: 0.018, altitude: 145, speed: 8.5, phase: 0.2, threat: "NORMAL" },
    { id: "SIM-03", latOffset: -0.016, lonOffset: 0.010, altitude: 180, speed: 12, phase: 2.1, threat: "WARNING" },
    { id: "SIM-04", latOffset: 0.008, lonOffset: -0.022, altitude: 220, speed: 15, phase: 4, threat: "NORMAL" },
    { id: "SIM-05", latOffset: -0.024, lonOffset: -0.014, altitude: 110, speed: 6.5, phase: 5.2, threat: "CRITICAL" },
    { id: "SIM-06", latOffset: 0.027, lonOffset: -0.006, altitude: 160, speed: 10, phase: 3.2, threat: "NORMAL" }
];

const PAGE_TITLES = {
    overview: "Mission Overview",
    tracking: "Live Tracking",
    radar: "Telemetry Radar",
    threats: "Threat Intelligence",
    defense: "Autonomous Defense",
    telemetry: "Telemetry & Logs",
    aircraft: "Live Aircraft"
};

/* UTILITIES */

function firstValue(object, keys, fallback = null) {
    for (const key of keys) {
        const value = object?.[key];
        if (value !== undefined && value !== null && value !== "") return value;
    }
    return fallback;
}

function asNumber(value, fallback = null) {
    if (value === null || value === undefined || value === "") return fallback;
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
}

function asText(value, fallback = "--") {
    if (value === null || value === undefined || value === "") return fallback;
    return typeof value === "object" ? JSON.stringify(value) : String(value);
}

function setText(id, value, fallback = "--") {
    const element = $(id);
    if (element) {
        element.textContent =
            value === null || value === undefined || value === ""
                ? fallback
                : String(value);
    }
}

function formatNumber(value, digits = 2) {
    return Number.isFinite(value) ? value.toFixed(digits) : "--";
}

function formatSpeed(speed) {
    return Number.isFinite(speed) ? `${formatNumber(speed, 1)} m/s` : "--";
}

function formatAircraftSpeed(speed) {
    return Number.isFinite(Number(speed))
        ? `${Number(speed).toFixed(1)} kt`
        : "--";
}

function formatAltitude(altitude) {
    if (altitude === null || altitude === undefined || altitude === "") return "--";
    if (typeof altitude === "string" && altitude.toLowerCase() === "ground") {
        return "Ground";
    }

    const number = Number(altitude);
    return Number.isFinite(number)
        ? `${number.toLocaleString()} ft`
        : String(altitude);
}

function formatTime(value) {
    if (!value) return new Date().toLocaleTimeString();

    const date = typeof value === "number"
        ? new Date(value < 1e12 ? value * 1000 : value)
        : new Date(value);

    return Number.isNaN(date.getTime())
        ? String(value)
        : date.toLocaleTimeString();
}

function validCoordinates(event) {
    return event &&
        Number.isFinite(event.latitude) &&
        Number.isFinite(event.longitude) &&
        Math.abs(event.latitude) <= 90 &&
        Math.abs(event.longitude) <= 180;
}

function validAircraftCoordinates(aircraft) {
    return aircraft &&
        Number.isFinite(Number(aircraft.lat)) &&
        Number.isFinite(Number(aircraft.lon)) &&
        Math.abs(Number(aircraft.lat)) <= 90 &&
        Math.abs(Number(aircraft.lon)) <= 180;
}

function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[character]);
}

/* TELEMETRY NORMALIZATION */

function normalizeEvent(event = {}) {
    const telemetry = event.telemetry || event.data || event.packet || {};
    const hem = event.hem || event.hem_status || {};
    const threat = event.threat || event.detection || {};
    const ml = event.ml || event.machine_learning || event.classifier || {};

    let latitude = asNumber(firstValue(event,
        ["latitude", "lat", "gps_latitude", "gps_lat"],
        firstValue(telemetry, ["latitude", "lat", "gps_latitude", "gps_lat"])
    ));

    let longitude = asNumber(firstValue(event,
        ["longitude", "lon", "lng", "gps_longitude", "gps_lon"],
        firstValue(telemetry, ["longitude", "lon", "lng", "gps_longitude", "gps_lon"])
    ));

    const gps = firstValue(event, ["gps"], firstValue(telemetry, ["gps"]));

    if (Array.isArray(gps)) {
        latitude = latitude ?? asNumber(gps[0]);
        longitude = longitude ?? asNumber(gps[1]);
    }

    const flags = firstValue(event,
        ["flags", "validation_flags", "anomaly_flags", "detected_flags"],
        firstValue(telemetry, ["flags", "validation_flags"], [])
    );

    const trust = asNumber(firstValue(event,
        ["trust", "trust_score", "behavioral_trust", "behavioural_trust"],
        firstValue(telemetry, ["trust", "trust_score"])
    ));

    const anomalyScore = asNumber(firstValue(event,
        ["ml_anomaly_score", "anomaly_score", "ml_score"],
        firstValue(ml, ["anomaly_score", "score"])
    ));

    const pattern = firstValue(event,
        ["pattern", "attack_pattern", "attack_type", "detected_pattern"],
        firstValue(threat, ["pattern", "attack_type"], "NORMAL")
    );

    const severity = firstValue(event,
        ["severity", "threat_severity"],
        firstValue(threat, ["severity"], "LOW")
    );

    const response = firstValue(event,
        ["response", "response_action", "defense_action", "defence_action"],
        firstValue(threat, ["response", "action"])
    );

    const hemPhase = firstValue(event,
        ["hem_phase", "phase", "current_phase"],
        firstValue(hem, ["phase", "current_phase"])
    );

    const moved = firstValue(event,
        ["data_moved", "moved", "transferred", "transfer_count"],
        firstValue(hem, ["data_moved", "moved", "transferred"])
    );

    const zeroized = firstValue(event,
        ["zeroized", "zeroisation", "zeroization", "vault_status"],
        firstValue(hem, ["zeroized", "zeroization", "vault_status"])
    );

    return {
        raw: event,
        seq: firstValue(event, ["seq", "sequence", "sequence_number", "id"]),
        timestamp: firstValue(event, ["timestamp", "time", "created_at", "datetime"]),
        latitude,
        longitude,
        altitude: asNumber(firstValue(event,
            ["altitude", "alt", "altitude_m"],
            firstValue(telemetry, ["altitude", "alt", "altitude_m"])
        )),
        speed: asNumber(firstValue(event,
            ["speed", "velocity", "ground_speed", "speed_mps"],
            firstValue(telemetry, ["speed", "velocity", "ground_speed", "speed_mps"])
        )),
        battery: asNumber(firstValue(event,
            ["battery", "battery_level", "battery_percent"],
            firstValue(telemetry, ["battery", "battery_level", "battery_percent"])
        )),
        trust,
        pattern: asText(pattern, "UNKNOWN").toUpperCase(),
        severity: asText(severity, "UNKNOWN").toUpperCase(),
        threatLevel: asText(firstValue(event,
            ["threat_level", "risk_level"],
            firstValue(threat, ["level", "threat_level"], severity)
        ), "UNKNOWN").toUpperCase(),
        response: asText(response),
        enforced: asText(firstValue(event,
            ["enforced", "enforcement", "enforcement_status"],
            firstValue(threat, ["enforced", "enforcement"])
        )),
        hemPhase: asText(hemPhase, "STANDBY").toUpperCase(),
        destination: asText(firstValue(event,
            ["destination", "hem_destination"],
            firstValue(hem, ["destination"])
        )),
        moved,
        zeroized,
        vault: asText(firstValue(event,
            ["vault", "vault_status"],
            firstValue(hem, ["vault", "vault_status"])
        )),
        anomaly: firstValue(event,
            ["ml_anomaly", "anomaly_detected", "is_anomaly"],
            firstValue(ml, ["anomaly", "is_anomaly", "detected"])
        ),
        anomalyScore,
        flags: Array.isArray(flags) ? flags : flags ? [flags] : [],
        eventType: asText(firstValue(event, ["event_type", "type", "event"], "TELEMETRY")).toUpperCase()
    };
}

function threatClass(event) {
    if (!event) return "normal";

    if (
        event.severity.includes("CRITICAL") ||
        event.severity.includes("HIGH") ||
        event.threatLevel.includes("CRITICAL") ||
        (event.trust !== null && event.trust < 0.2)
    ) return "critical";

    if (
        event.flags.length > 0 ||
        event.severity.includes("MEDIUM") ||
        event.severity.includes("WARNING") ||
        (event.trust !== null && event.trust < 0.7)
    ) return "warning";

    return "normal";
}

/* NAVIGATION */

function showView(view) {
    if (!PAGE_TITLES[view]) return;

    document.querySelectorAll("[data-page]").forEach((page) => {
        const active = page.dataset.page === view;
        page.hidden = !active;
        page.classList.toggle("active", active);
    });

    document.querySelectorAll(".nav-link").forEach((button) => {
        button.classList.toggle("active", button.dataset.view === view);
    });

    setText("page-title", PAGE_TITLES[view]);

    if ((view === "tracking" || view === "overview") &&
        state.mapReady && state.map) {
        window.setTimeout(() => state.map.invalidateSize(), 100);
    }

    if (view === "aircraft") refreshAircraft();
}

document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => showView(button.dataset.view));
});

/* SUBTLE DRONE ICON */

function createDroneIcon(threat = "normal") {
    const color = threat === "critical" ? "#ff687a"
        : threat === "warning" ? "#e6b85c"
        : "#55c8eb";

    // Compact quadcopter silhouette. No large badge or heavy glow.
    const svg = `
        <svg xmlns="http://www.w3.org/2000/svg"
             width="32" height="32" viewBox="0 0 32 32"
             aria-label="Simulated drone" role="img">
            <g stroke="${color}" stroke-width="1.8"
               fill="none" stroke-linecap="round" stroke-linejoin="round">
                <path d="M11 11 L14 14 M21 11 L18 14
                         M11 21 L14 18 M21 21 L18 18"/>
                <ellipse cx="8" cy="8" rx="4.5" ry="2.1"/>
                <ellipse cx="24" cy="8" rx="4.5" ry="2.1"/>
                <ellipse cx="8" cy="24" rx="4.5" ry="2.1"/>
                <ellipse cx="24" cy="24" rx="4.5" ry="2.1"/>
            </g>
            <rect x="12.5" y="12.5" width="7" height="7"
                  rx="1.8" fill="${color}" stroke="#eaf7ff"
                  stroke-width=".8"/>
            <circle cx="16" cy="16" r="1.2" fill="#10202b"/>
        </svg>`;

    return L.divIcon({
        className: "scout-drone-marker",
        html: svg,
        iconSize: [32, 32],
        iconAnchor: [16, 16],
        tooltipAnchor: [0, -13]
    });
}

/* GEOGRAPHIC MAP */

function initMap() {
    const container = $("live-map");

    if (!container || !window.L) {
        if (container) {
            container.innerHTML =
                '<div class="map-loading">Map library unavailable. Check internet access.</div>';
        }
        return;
    }

    try {
        state.map = L.map(container, {
            zoomControl: true,
            preferCanvas: true
        }).setView([12.9716, 77.5946], 8);

        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            maxZoom: 19,
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        }).addTo(state.map);

        state.primaryTrail = L.polyline([], {
            color: "#39c7ff",
            weight: 2,
            opacity: 0.65
        }).addTo(state.map);

        state.primaryMarker = L.marker([12.9716, 77.5946], {
            icon: createDroneIcon(),
            title: "SCOUT-X simulated UAV",
            keyboard: true,
            zIndexOffset: 500
        }).addTo(state.map);

        state.primaryMarker.bindPopup(`
            <div class="aircraft-popup">
                <strong>SCOUT-X UAV-01</strong>
                <div>Source: SIMULATED TELEMETRY</div>
                <div>Platform: Quadcopter</div>
                <small>Research demonstration only</small>
            </div>
        `);

        state.primaryMarker.bindTooltip("SCOUT-X · SIMULATED UAV", {
            direction: "top",
            offset: [0, -12]
        });

        state.mapReady = true;

        updateMapFromLatest();
        updateSecondaryTargets();
        updateAircraftMarkers();
    } catch (error) {
        console.error("Map initialization failed:", error);
        container.innerHTML =
            '<div class="map-loading">Unable to initialize map. Check browser console and network access.</div>';
    }
}

function updateMapFromLatest() {
    const event = state.latest;
    if (!event || !validCoordinates(event)) return;

    setText("map-coordinates",
        `${event.latitude.toFixed(5)}, ${event.longitude.toFixed(5)}`);
    setText("map-altitude",
        event.altitude === null ? "-- m" : `${event.altitude.toFixed(1)} m`);
    setText("map-speed", formatSpeed(event.speed));
    setText("map-telemetry-state", "SIMULATION · RECEIVING");

    const preview = $("overview-map-preview");

    if (preview) {
        preview.innerHTML = `
            <div class="mini-map-grid"></div>
            <div class="mini-map-coordinate">
                ${event.latitude.toFixed(5)}<br>${event.longitude.toFixed(5)}
            </div>
            <div class="mini-map-center">SCOUT-X SIMULATED POSITION</div>
        `;
    }

    if (!state.mapReady || !state.map || !state.primaryMarker) return;

    const position = [event.latitude, event.longitude];

    state.primaryMarker.setLatLng(position);
    state.primaryMarker.setIcon(createDroneIcon(threatClass(event)));

    const last = state.trailPoints[state.trailPoints.length - 1];

    if (!last || last[0] !== position[0] || last[1] !== position[1]) {
        state.trailPoints.push(position);
        if (state.trailPoints.length > 250) state.trailPoints.shift();
        state.primaryTrail.setLatLngs(state.trailPoints);
    }

    updateSecondaryTargets();
}

/* SIMULATED SECONDARY TARGETS */

function getSecondaryPosition(target) {
    const primary = state.latest && validCoordinates(state.latest)
        ? state.latest
        : { latitude: 12.9716, longitude: 77.5946 };

    const time = Date.now() / 12000 + target.phase;

    return [
        primary.latitude +
            target.latOffset * (0.88 + 0.12 * Math.sin(time)) +
            Math.sin(time) * 0.0015,
        primary.longitude +
            target.lonOffset * (0.88 + 0.12 * Math.cos(time * 0.8)) +
            Math.cos(time) * 0.0015
    ];
}

function createTargetIcon(threat) {
    const color = threat === "critical" ? "#ff5c73"
        : threat === "warning" ? "#f2bd55"
        : "#48d49b";

    return L.divIcon({
        className: "scout-target-icon",
        html: `<span style="--target-color:${color}">◆</span>`,
        iconSize: [22, 22],
        iconAnchor: [11, 11]
    });
}

function updateSecondaryTargets() {
    if (!state.mapReady || !state.map || !window.L) return;

    const activeTargets = SECONDARY_TARGETS.slice(0, state.targetCount);
    const activeIds = new Set(activeTargets.map((target) => target.id));

    for (const [id, marker] of state.secondaryMarkers) {
        if (!activeIds.has(id)) {
            state.map.removeLayer(marker);
            state.secondaryMarkers.delete(id);

            const trail = state.secondaryTrails.get(id);
            if (trail) state.map.removeLayer(trail);
            state.secondaryTrails.delete(id);
        }
    }

    activeTargets.forEach((target) => {
        const position = getSecondaryPosition(target);
        const threat = target.threat === "CRITICAL" ? "critical"
            : target.threat === "WARNING" ? "warning"
            : "normal";

        let marker = state.secondaryMarkers.get(target.id);

        if (!marker) {
            marker = L.marker(position, {
                icon: createTargetIcon(threat)
            }).addTo(state.map);

            marker.bindTooltip(`${target.id} · SIMULATED`, {
                direction: "top"
            });

            marker.bindPopup(`
                <div class="aircraft-popup">
                    <strong>${escapeHTML(target.id)}</strong>
                    <div>Source: SCOUT-X SIMULATION</div>
                    <div>Threat state: ${escapeHTML(target.threat)}</div>
                    <div>Altitude: ${target.altitude} m</div>
                    <div>Speed: ${target.speed} m/s</div>
                </div>
            `);

            marker.on("click", () => {
                state.selectedTarget = target.id;
                setText("target-control-feedback",
                    `${target.id} selected. Simulated target only.`);
                updateRadar();
            });

            state.secondaryMarkers.set(target.id, marker);

            const trail = L.polyline([], {
                color: threat === "critical" ? "#ff5c73"
                    : threat === "warning" ? "#f2bd55"
                    : "#48d49b",
                weight: 1.5,
                opacity: 0.45,
                dashArray: "5 7"
            }).addTo(state.map);

            state.secondaryTrails.set(target.id, trail);
        } else {
            marker.setLatLng(position);
        }

        const trail = state.secondaryTrails.get(target.id);

        if (trail) {
            const points = trail.getLatLngs();
            points.push(position);
            if (points.length > 35) points.shift();
            trail.setLatLngs(points);
        }
    });
}

/* LIVE ADS-B AIRCRAFT */

function createAircraftIcon() {
    return L.divIcon({
        className: "adsb-aircraft-icon",
        html: '<span aria-hidden="true">✈</span>',
        iconSize: [24, 24],
        iconAnchor: [12, 12]
    });
}

function aircraftDisplayName(aircraft) {
    return aircraft.flight || aircraft.hex || "Unknown aircraft";
}

function aircraftPopup(aircraft) {
    const flight = escapeHTML(aircraftDisplayName(aircraft));
    const hex = escapeHTML(aircraft.hex || "--");
    const altitude = escapeHTML(formatAltitude(aircraft.altitude));
    const speed = escapeHTML(formatAircraftSpeed(aircraft.speed));
    const heading = Number.isFinite(Number(aircraft.track))
        ? `${Math.round(Number(aircraft.track))}°`
        : "--";

    return `
        <div class="aircraft-popup">
            <strong>${flight}</strong>
            <div>Source: LIVE ADS-B</div>
            <div>ICAO: ${hex}</div>
            <div>Altitude: ${altitude}</div>
            <div>Ground speed: ${speed}</div>
            <div>Heading: ${heading}</div>
            <small>Tracking data only · Not a threat assessment</small>
        </div>
    `;
}

function updateAircraftMarkers() {
    const validAircraft = state.aircraft.filter(validAircraftCoordinates);

    if (!state.mapReady || !state.map || !window.L) {
        renderAircraftList(validAircraft);
        return;
    }

    const activeIds = new Set();

    validAircraft.forEach((aircraft) => {
        const id = String(aircraft.hex || `${aircraft.lat}-${aircraft.lon}`);
        const position = [Number(aircraft.lat), Number(aircraft.lon)];

        activeIds.add(id);

        let marker = state.aircraftMarkers.get(id);

        if (!marker) {
            marker = L.marker(position, {
                icon: createAircraftIcon(),
                keyboard: true,
                title: `${aircraftDisplayName(aircraft)} · LIVE ADS-B`
            }).addTo(state.map);

            marker.bindPopup(aircraftPopup(aircraft));
            state.aircraftMarkers.set(id, marker);
        } else {
            marker.setLatLng(position);
            marker.setPopupContent(aircraftPopup(aircraft));
        }

        marker.bindTooltip(`${aircraftDisplayName(aircraft)} · LIVE ADS-B`, {
            direction: "top"
        });
    });

    for (const [id, marker] of state.aircraftMarkers) {
        if (!activeIds.has(id)) {
            state.map.removeLayer(marker);
            state.aircraftMarkers.delete(id);
        }
    }

    setText("aircraft-count", validAircraft.length);
    setText("live-aircraft-count", validAircraft.length);
    setText("aircraft-updated", state.aircraftLastUpdated
        ? formatTime(state.aircraftLastUpdated)
        : "Waiting for feed");

    renderAircraftList(validAircraft);
}

function focusAircraft(aircraft) {
    if (!state.mapReady || !state.map) {
        showView("tracking");
        return;
    }

    state.selectedTarget = String(
        aircraft.hex || aircraftDisplayName(aircraft)
    );

    showView("tracking");
    state.map.setView(
        [Number(aircraft.lat), Number(aircraft.lon)],
        10
    );

    const id = String(aircraft.hex || `${aircraft.lat}-${aircraft.lon}`);
    const marker = state.aircraftMarkers.get(id);

    if (marker) marker.openPopup();
}

function renderAircraftList(aircraft) {
    const tableBody = $("aircraft-table-body");
    const containers = [
        $("aircraft-list"),
        $("live-aircraft-list")
    ].filter(Boolean);

    if (!aircraft.length) {
        if (tableBody) {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="empty-state">
                        No aircraft with usable coordinates in the latest feed.
                    </td>
                </tr>
            `;
        }

        containers.forEach((container) => {
            container.innerHTML =
                '<div class="empty-state">No aircraft with usable coordinates in the latest feed.</div>';
        });

        return;
    }

    if (tableBody) {
        const rows = aircraft.map((item) => {
            const row = document.createElement("tr");

            const values = [
                aircraftDisplayName(item),
                item.hex || "--",
                formatAltitude(item.altitude),
                formatAircraftSpeed(item.speed),
                Number.isFinite(Number(item.track))
                    ? `${Math.round(Number(item.track))}°`
                    : "--",
                "LIVE ADS-B"
            ];

            values.forEach((value) => {
                const cell = document.createElement("td");
                cell.textContent = String(value);
                row.appendChild(cell);
            });

            row.title =
                "Live aircraft tracking. Presence does not indicate a threat.";
            row.tabIndex = 0;
            row.style.cursor = "pointer";

            row.addEventListener("click", () => focusAircraft(item));
            row.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    focusAircraft(item);
                }
            });

            return row;
        });

        tableBody.replaceChildren(...rows);
    }

    containers.forEach((container) => {
        const fragment = document.createDocumentFragment();

        aircraft.forEach((item) => {
            const row = document.createElement("div");
            row.className = "aircraft-row";
            row.tabIndex = 0;
            row.style.cursor = "pointer";

            [
                aircraftDisplayName(item),
                formatAltitude(item.altitude),
                formatAircraftSpeed(item.speed),
                Number.isFinite(Number(item.track))
                    ? `${Math.round(Number(item.track))}°`
                    : "--",
                "LIVE ADS-B"
            ].forEach((value) => {
                const cell = document.createElement("span");
                cell.textContent = String(value);
                row.appendChild(cell);
            });

            row.addEventListener("click", () => focusAircraft(item));
            row.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    focusAircraft(item);
                }
            });

            fragment.appendChild(row);
        });

        container.replaceChildren(fragment);
    });
}

async function refreshAircraft() {
    if (state.aircraftFetchBusy) return;

    state.aircraftFetchBusy = true;

    try {
        const response = await fetch(API.aircraft, { cache: "no-store" });

        if (!response.ok) {
            throw new Error(`Aircraft endpoint returned HTTP ${response.status}`);
        }

        const payload = await response.json();

        state.aircraft = Array.isArray(payload.aircraft)
            ? payload.aircraft
            : [];

        state.aircraftLastUpdated = new Date();

        setText("aircraft-source", payload.source || "adsb.lol");
        setText("aircraft-status", "LIVE FEED");
        setText("aircraft-feed-status", "LIVE FEED");
        setText("aircraft-feed-time", formatTime(state.aircraftLastUpdated));

        ["aircraft-status", "aircraft-feed-status"].forEach((id) => {
            const element = $(id);
            if (element) {
                element.classList.remove("disconnected", "warning");
                element.classList.add("connected");
            }
        });

        updateAircraftMarkers();
        updateRadar();
    } catch (error) {
        console.error("Live aircraft refresh failed:", error);

        setText("aircraft-status", "FEED UNAVAILABLE");
        setText("aircraft-feed-status", `Feed unavailable: ${error.message}`);

        ["aircraft-status", "aircraft-feed-status"].forEach((id) => {
            const element = $(id);
            if (element) {
                element.classList.remove("connected");
                element.classList.add("disconnected");
            }
        });

        // Retain the last successful data if the provider is temporarily down.
        updateAircraftMarkers();
    } finally {
        state.aircraftFetchBusy = false;
    }
}

/* RELATIVE-POSITION RADAR */

function updateRadar() {
    const layer = $("radar-targets");
    if (!layer) return;

    layer.replaceChildren();

    const items = [];

    if (state.latest) {
        items.push({
            id: "SCOUT-X",
            label: "PRIMARY",
            threat: threatClass(state.latest),
            angle: 0,
            distance: 0
        });
    }

    SECONDARY_TARGETS.slice(0, state.targetCount).forEach((target, index) => {
        const time = Date.now() / 12000 + target.phase;

        items.push({
            id: target.id,
            label: "SIMULATED",
            threat: target.threat === "CRITICAL" ? "critical"
                : target.threat === "WARNING" ? "warning"
                : "normal",
            angle: (time * 36 + index * 79) % 360,
            distance: 18 + index * 10
        });
    });

    const primary = state.latest && validCoordinates(state.latest)
        ? state.latest
        : { latitude: 12.9716, longitude: 77.5946 };

    state.aircraft.filter(validAircraftCoordinates).forEach((aircraft) => {
        const deltaLat = Number(aircraft.lat) - primary.latitude;
        const deltaLon = Number(aircraft.lon) - primary.longitude;

        const angle = Math.atan2(deltaLon, deltaLat) * 180 / Math.PI;
        const distanceKm = Math.sqrt(
            (deltaLat * 111) ** 2 +
            (deltaLon * 111 *
                Math.cos(primary.latitude * Math.PI / 180)) ** 2
        );

        items.push({
            id: aircraft.hex || aircraftDisplayName(aircraft),
            label: "LIVE ADS-B",
            threat: "aircraft",
            angle: (angle + 360) % 360,
            distance: Math.min(43, Math.max(5, distanceKm / 2))
        });
    });

    items.forEach((target) => {
        const marker = document.createElement("button");
        marker.type = "button";

        if (target.id === "SCOUT-X") {
            marker.className = `radar-target primary ${target.threat}`;
            marker.style.left = "50%";
            marker.style.top = "50%";
            marker.title = "SCOUT-X simulated quadcopter";
            marker.setAttribute("aria-label",
                "SCOUT-X simulated primary target");
        } else {
            marker.className = `radar-target ${target.threat}`;

            const angle = target.angle * Math.PI / 180;
            const radius = Math.min(43, target.distance);

            marker.style.left = `${50 + Math.sin(angle) * radius}%`;
            marker.style.top = `${50 - Math.cos(angle) * radius}%`;
            marker.title = target.label === "LIVE ADS-B"
                ? `${target.id} · LIVE ADS-B · Tracking only`
                : `${target.id} · SIMULATED`;

            marker.setAttribute("aria-label",
                `${target.id}, ${target.label}`);

            marker.addEventListener("click", () => {
                state.selectedTarget = target.id;

                setText("target-control-feedback",
                    target.label === "LIVE ADS-B"
                        ? `${target.id} selected. Live aircraft tracking data, not a threat assessment.`
                        : `${target.id} selected. Simulated target only.`);
            });
        }

        layer.appendChild(marker);
    });

    setText("radar-count", items.length);
    setText("radar-last-event",
        state.latest ? state.latest.pattern : "Awaiting telemetry");
    setText("radar-threat",
        state.latest ? state.latest.severity : "NO DATA");
    setText("radar-state",
        state.latest ? "TRACKING" : "STANDBY");
    setText("radar-aircraft-count", state.aircraft.length);
}

/* TRUST AND THREAT PANELS */

function updateTrust(event) {
    if (!event) return;

    const trust = event.trust;
    const value = trust === null ? "--" : trust.toFixed(2);
    const percent = trust === null
        ? 0
        : Math.max(0, Math.min(1, trust)) * 100;

    const tone = trust === null || trust >= 0.7 ? "normal"
        : trust >= 0.2 ? "warning"
        : "critical";

    setText("overview-trust", value);
    setText("overview-trust-label", trust === null ? "No trust value"
        : tone === "normal" ? "TRUST ACCEPTABLE"
        : tone === "warning" ? "TRUST DEGRADED"
        : "TRUST CRITICAL");

    setText("trust-value", value);
    setText("trust-label", tone.toUpperCase());

    const trustFill = $("trust-fill");

    if (trustFill) {
        trustFill.style.width = `${percent}%`;
        trustFill.style.background = tone === "critical" ? "#ff5c73"
            : tone === "warning" ? "#f2bd55"
            : "#48d49b";
    }

    setText("defense-trust", value);
}

function updateThreat(event) {
    if (!event) return;

    setText("threat-severity", event.severity);
    setText("threat-pattern", event.pattern);
    setText("threat-level", event.threatLevel);
    setText("threat-response", event.response);
    setText("threat-enforced", event.enforced);
    setText("overview-severity", event.severity);
    setText("overview-pattern", event.pattern);
    setText("overview-response", event.response);
    setText("overview-enforcement", event.enforced);
    setText("defense-response", event.response);
    setText("defense-enforced", event.enforced);
    setText("defense-severity", event.severity);
    setText("defense-pattern", event.pattern);
    setText("threat-ml-anomaly", asText(event.anomaly, "--"));
    setText("threat-ml-score",
        event.anomalyScore === null ? "--" : event.anomalyScore.toFixed(4));
    setText("threat-flags",
        event.flags.length ? event.flags.join(", ") : "None reported");

    const status = $("flight-status");

    if (status) {
        const tone = threatClass(event);

        status.textContent = tone === "critical" ? "CRITICAL THREAT"
            : tone === "warning" ? "THREAT DETECTED"
            : "NORMAL FLIGHT";

        status.className = `status-pill ${tone}`;
    }
}

function updateTelemetry(event) {
    if (!event) return;

    const values = {
        "telemetry-seq": event.seq,
        "telemetry-altitude": event.altitude === null ? "--" : `${event.altitude} m`,
        "telemetry-speed": formatSpeed(event.speed),
        "telemetry-battery": event.battery === null ? "--" : `${event.battery}%`,
        "telemetry-latitude": event.latitude === null ? "--" : event.latitude.toFixed(6),
        "telemetry-longitude": event.longitude === null ? "--" : event.longitude.toFixed(6),
        "log-seq": event.seq,
        "log-altitude": event.altitude === null ? "--" : `${event.altitude} m`,
        "log-speed": formatSpeed(event.speed),
        "log-battery": event.battery === null ? "--" : `${event.battery}%`,
        "log-latitude": event.latitude === null ? "--" : event.latitude.toFixed(6),
        "log-longitude": event.longitude === null ? "--" : event.longitude.toFixed(6)
    };

    Object.entries(values).forEach(([id, value]) => setText(id, value));
}

function updateHem(event) {
    if (!event) return;

    setText("hem-phase", event.hemPhase);
    setText("hem-current-phase", event.hemPhase);
    setText("overview-hem", event.hemPhase);
    setText("hem-destination", event.destination);
    setText("defense-destination", event.destination);
    setText("hem-moved", event.moved);
    setText("defense-moved", event.moved);
    setText("defense-moved-detail", event.moved);
    setText("hem-zeroized", event.zeroized ?? event.vault);
    setText("defense-zeroized", event.zeroized ?? event.vault);
    setText("overview-zeroized",
        event.zeroized ?? event.vault, "Vault status unavailable");
}

function updateMachineLearning(event) {
    if (!event) return;

    const anomaly = event.anomaly;

    const anomalyText = anomaly === null ? "Not reported"
        : anomaly === true || anomaly === 1 ||
            String(anomaly).toLowerCase() === "true"
            ? "ANOMALY"
            : "NORMAL";

    setText("ml-anomaly-status", anomalyText);
    setText("ml-anomaly", anomalyText);
    setText("ml-score",
        event.anomalyScore === null ? "--" : event.anomalyScore.toFixed(4));
    setText("threat-ml-anomaly", anomalyText);
    setText("threat-ml-score",
        event.anomalyScore === null ? "--" : event.anomalyScore.toFixed(4));
    setText("threat-ml-status", anomalyText);
}

/* EVENT TIMELINE */

function renderTimeline(events) {
    const containers = [
        $("event-timeline"),
        $("threat-event-list")
    ].filter(Boolean);

    if (!events.length) {
        containers.forEach((container) => {
            container.innerHTML =
                '<div class="empty-state">No telemetry events received yet.</div>';
        });

        setText("event-count", "0 EVENTS");
        return;
    }

    const rows = events.slice(-40).reverse().map((raw) => {
        const event = normalizeEvent(raw);
        const row = document.createElement("div");

        row.className = `event-row ${threatClass(event)}`;

        [
            [formatTime(event.timestamp), "event-time"],
            [`#${asText(event.seq, "?")}`, "event-seq"],
            [event.pattern, "event-pattern"],
            [event.severity, "event-severity"],
            [event.response, "event-response"]
        ].forEach(([value, className]) => {
            const cell = document.createElement("span");
            cell.className = className;
            cell.textContent = value;
            row.appendChild(cell);
        });

        return row;
    });

    containers.forEach((container) => {
        container.replaceChildren(
            ...rows.map((row) => row.cloneNode(true))
        );
    });

    setText("event-count", `${events.length} EVENTS`);
}

/* BACKEND COMMUNICATION */

async function refreshEvents() {
    if (state.fetchBusy) return;

    state.fetchBusy = true;

    try {
        const response = await fetch(API.events, { cache: "no-store" });

        if (!response.ok) {
            throw new Error(`Events endpoint returned HTTP ${response.status}`);
        }

        const payload = await response.json();
        const events = Array.isArray(payload)
            ? payload
            : payload.events || [];

        state.events = events;

        const rawLatest = events.length ? events[events.length - 1] : null;
        state.latest = rawLatest ? normalizeEvent(rawLatest) : null;

        setConnection(true);
        renderTimeline(events);

        if (state.latest) {
            updateTrust(state.latest);
            updateThreat(state.latest);
            updateTelemetry(state.latest);
            updateHem(state.latest);
            updateMachineLearning(state.latest);
            updateMapFromLatest();
            updateRadar();

            const eventKey =
                `${state.latest.seq}-${state.latest.timestamp}-${state.latest.pattern}`;

            if (eventKey !== state.lastEventKey) {
                state.lastEventKey = eventKey;
                setText("radar-last-event", state.latest.pattern);
            }
        } else {
            setText("map-telemetry-state", "NO EVENTS");
        }
    } catch (error) {
        console.error("Telemetry refresh failed:", error);
        setConnection(false);
    } finally {
        state.fetchBusy = false;
    }
}

function setConnection(connected) {
    setText("connection-status",
        connected ? "CONNECTED" : "DISCONNECTED");
    setText("header-connection",
        connected ? "SYSTEM ONLINE" : "API OFFLINE");

    ["connection-dot", "header-status-dot"].forEach((id) => {
        const element = $(id);
        if (element) {
            element.classList.toggle("connected", connected);
            element.classList.toggle("disconnected", !connected);
        }
    });
}

async function launchScenario(scenario) {
    const buttons = document.querySelectorAll("[data-scenario]");
    buttons.forEach((button) => { button.disabled = true; });

    setText("scenario-feedback",
        `Starting ${scenario.replaceAll("_", " ").toUpperCase()} scenario…`);

    try {
        const response = await fetch(API.scenario, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario })
        });

        const payload = await response.json().catch(() => ({}));

        if (!response.ok) {
            throw new Error(
                payload.detail || payload.message || `HTTP ${response.status}`
            );
        }

        state.lastScenario = scenario;

        setText("scenario-feedback", payload.message ||
            `${scenario.replaceAll("_", " ").toUpperCase()} scenario submitted to the receiver.`);

        window.setTimeout(refreshEvents, 250);
    } catch (error) {
        console.error("Scenario launch failed:", error);
        setText("scenario-feedback", `Scenario failed: ${error.message}`);
    } finally {
        window.setTimeout(() => {
            buttons.forEach((button) => { button.disabled = false; });
        }, 1200);
    }
}

document.querySelectorAll("[data-scenario]").forEach((button) => {
    button.addEventListener("click", () => {
        launchScenario(button.dataset.scenario);
    });
});

const refreshButton = $("refresh-events");
if (refreshButton) {
    refreshButton.addEventListener("click", refreshEvents);
}

const applyTargetsButton = $("apply-target-count");

if (applyTargetsButton) {
    applyTargetsButton.addEventListener("click", () => {
        const select = $("sim-target-count");

        state.targetCount = Math.max(
            0,
            Math.min(SECONDARY_TARGETS.length, Number(select?.value ?? 3))
        );

        updateSecondaryTargets();
        updateRadar();

        setText("target-control-feedback",
            `${state.targetCount} additional simulated target(s) active.`);
    });
}

const refreshAircraftButton = $("refresh-aircraft");
if (refreshAircraftButton) {
    refreshAircraftButton.addEventListener("click", refreshAircraft);
}

/* START DASHBOARD */

initMap();
refreshEvents();
refreshAircraft();

window.setInterval(refreshEvents, 1000);
window.setInterval(refreshAircraft, 30000);

window.setInterval(() => {
    updateSecondaryTargets();
    updateRadar();
}, 1500);
