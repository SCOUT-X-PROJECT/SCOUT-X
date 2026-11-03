
"use strict";

const configElement = document.getElementById("scoutx-config");
const CONFIG = configElement ? JSON.parse(configElement.content || "{}") : {};

const API = {
    events: "/api/events",
    stream: "/api/stream",
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
    targetCount: CONFIG.initial_target_count,
    selectedTarget: "SCOUT-X",
    lastEventKey: null,
    lastScenario: null,
    mapReady: false,
    fetchBusy: false,
    aircraftFetchBusy: false,
    aircraftLastUpdated: null,
    suspiciousMarkers: [],
    trustPhase: null,
    lastTelemetryAt: null,
    streamStartedAt: null,
    transportConnected: false
};

const SECONDARY_TARGETS = CONFIG.secondary_targets;

const PAGE_TITLES = {
    overview: "Mission Overview",
    tracking: "Live Tracking",
    radar: "Telemetry Radar",
    threats: "Threat Intelligence",
    defense: "Simulated Defense",
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
        ? new Date(value < CONFIG.timestamp_milliseconds_cutoff
            ? value * CONFIG.milliseconds_per_second
            : value)
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

function showMessage(container, message, className = "empty-state") {
    const element = document.createElement("div");
    element.className = className;
    element.textContent = message;
    container.replaceChildren(element);
}

function textNode(value, className = "") {
    const node = document.createElement("span");
    node.className = className;
    node.textContent = String(value ?? "");
    return node;
}

function popupContent(title, rows) {
    const root = document.createElement("div");
    root.className = "aircraft-popup";
    const heading = document.createElement("strong");
    heading.textContent = title;
    root.appendChild(heading);
    rows.forEach(([label, value]) => {
        const row = document.createElement("div");
        row.textContent = `${label}: ${value}`;
        root.appendChild(row);
    });
    return root;
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
        (event.trust !== null && event.trust <= CONFIG.critical_trust_threshold)
    ) return "critical";

    if (
        event.flags.length > 0 ||
        event.severity.includes("MEDIUM") ||
        event.severity.includes("WARNING") ||
        (event.trust !== null && event.trust < CONFIG.warning_trust_threshold)
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
        window.setTimeout(
            () => state.map.invalidateSize(),
            CONFIG.map_refresh_delay_ms
        );
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
            container.textContent = "Map library unavailable. Check internet access.";
            container.classList.add("map-loading");
        }
        return;
    }

    try {
        state.map = L.map(container, {
            zoomControl: true,
            preferCanvas: true
        }).setView(
            [CONFIG.aircraft_center_latitude, CONFIG.aircraft_center_longitude],
            CONFIG.map_zoom
        );

        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            maxZoom: 19,
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        }).addTo(state.map);

        state.primaryTrail = L.polyline([], {
            color: "#39c7ff",
            weight: 2,
            opacity: 0.65
        }).addTo(state.map);

        state.primaryMarker = L.marker([
            CONFIG.aircraft_center_latitude,
            CONFIG.aircraft_center_longitude
        ], {
            icon: createDroneIcon(),
            title: "SCOUT-X simulated UAV",
            keyboard: true,
            zIndexOffset: 500
        }).addTo(state.map);

        state.primaryMarker.bindPopup(popupContent("SCOUT-X UAV-01", [
            ["Source", "SIMULATED TELEMETRY"],
            ["Platform", "Quadcopter"],
            ["Notice", "Research demonstration only"]
        ]));

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
        container.textContent =
            "Unable to initialize map. Check browser console and network access.";
        container.classList.add("map-loading");
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
        const grid = document.createElement("div");
        grid.className = "mini-map-grid";
        const coordinate = document.createElement("div");
        coordinate.className = "mini-map-coordinate";
        coordinate.textContent =
            `${event.latitude.toFixed(5)}, ${event.longitude.toFixed(5)}`;
        const label = document.createElement("div");
        label.className = "mini-map-center";
        label.textContent = "SCOUT-X SIMULATED POSITION";
        preview.replaceChildren(grid, coordinate, label);
    }

    if (!state.mapReady || !state.map || !state.primaryMarker) return;

    const position = [event.latitude, event.longitude];

    state.primaryMarker.setLatLng(position);
    state.primaryMarker.setIcon(createDroneIcon(threatClass(event)));
    addSuspiciousMarker(event, position);

    const last = state.trailPoints[state.trailPoints.length - 1];

    if (!last || last[0] !== position[0] || last[1] !== position[1]) {
        state.trailPoints.push(position);
        if (state.trailPoints.length > CONFIG.trail_limit) {
            state.trailPoints.shift();
        }
        state.primaryTrail.setLatLngs(state.trailPoints);
    }

    updateSecondaryTargets();
}

function addSuspiciousMarker(event, position) {
    if (!state.mapReady || threatClass(event) === "normal") return;
    const sequence = Number(event.seq);
    const key = `${sequence}:${position[0]}:${position[1]}`;
    if (state.suspiciousMarkers.some((item) => item.key === key)) return;
    const marker = L.circleMarker(position, {
        radius: 8,
        color: threatClass(event) === "critical" ? "#ff5c73" : "#f2bd55",
        fillOpacity: 0.35,
        weight: 2
    }).addTo(state.map);
    marker.bindTooltip(textNode(
        `Suspicious packet ${Number.isFinite(sequence) ? sequence : ""}`
    ));
    state.suspiciousMarkers.push({ key, marker });
    while (state.suspiciousMarkers.length > CONFIG.trail_limit) {
        const removed = state.suspiciousMarkers.shift();
        state.map.removeLayer(removed.marker);
    }
}

function renderTrackHistory() {
    if (!state.mapReady || !state.map || !state.primaryTrail) return;
    state.trailPoints = state.events
        .map(normalizeEvent)
        .filter(validCoordinates)
        .slice(-CONFIG.trail_limit)
        .map((event) => [event.latitude, event.longitude]);
    state.primaryTrail.setLatLngs(state.trailPoints);
    state.suspiciousMarkers.forEach(({ marker }) => state.map.removeLayer(marker));
    state.suspiciousMarkers = [];
    state.events.map(normalizeEvent)
        .filter((event) => validCoordinates(event) && threatClass(event) !== "normal")
        .slice(-CONFIG.trail_limit)
        .forEach((event) => addSuspiciousMarker(
            event,
            [event.latitude, event.longitude]
        ));
}

/* SIMULATED SECONDARY TARGETS */

function getSecondaryPosition(target) {
    const primary = state.latest && validCoordinates(state.latest)
        ? state.latest
        : {
            latitude: CONFIG.aircraft_center_latitude,
            longitude: CONFIG.aircraft_center_longitude
        };

    const time = Date.now() / CONFIG.simulated_target_motion_period_ms
        + target.phase;

    return [
        primary.latitude +
            target.latOffset * (
                CONFIG.simulated_target_motion_baseline
                + CONFIG.simulated_target_motion_amplitude * Math.sin(time)
            ) +
            Math.sin(time) * CONFIG.simulated_target_position_jitter,
        primary.longitude +
            target.lonOffset * (
                CONFIG.simulated_target_motion_baseline
                + CONFIG.simulated_target_motion_amplitude
                * Math.cos(time * CONFIG.simulated_target_longitude_frequency)
            ) +
            Math.cos(time) * CONFIG.simulated_target_position_jitter
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

            marker.bindTooltip(textNode(`${target.id} · SIMULATED`), {
                direction: "top"
            });

            marker.bindPopup(popupContent(target.id, [
                ["Source", "SCOUT-X SIMULATION"],
                ["Threat state", target.threat],
                ["Altitude", `${target.altitude} m`],
                ["Speed", `${target.speed} m/s`]
            ]));

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
    const heading = Number.isFinite(Number(aircraft.track))
        ? `${Math.round(Number(aircraft.track))}°`
        : "--";
    return popupContent(aircraftDisplayName(aircraft), [
        ["Source", "LIVE ADS-B"],
        ["ICAO", aircraft.hex || "--"],
        ["Altitude", formatAltitude(aircraft.altitude)],
        ["Ground speed", formatAircraftSpeed(aircraft.speed)],
        ["Heading", heading],
        ["Notice", "Tracking data only · Not a threat assessment"]
    ]);
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

        marker.bindTooltip(textNode(
            `${aircraftDisplayName(aircraft)} · LIVE ADS-B`
        ), {
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
        CONFIG.map_focus_zoom
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
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 6;
            cell.className = "empty-state";
            cell.textContent = "No aircraft with usable coordinates in the latest feed.";
            row.appendChild(cell);
            tableBody.replaceChildren(row);
        }

        containers.forEach((container) => {
            showMessage(container, "No aircraft with usable coordinates in the latest feed.");
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
        const time = Date.now() / CONFIG.simulated_target_motion_period_ms
            + target.phase;

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
        : {
            latitude: CONFIG.aircraft_center_latitude,
            longitude: CONFIG.aircraft_center_longitude
        };

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

    const tone = trust === null || trust >= CONFIG.warning_trust_threshold
        ? "normal"
        : trust <= CONFIG.critical_trust_threshold ? "critical"
        : "warning";

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
    updateTrustPhase(trust, event);
    renderTrustChart();
}

function trustPhase(trust, event) {
    const authoritative = event?.raw?.trust_state || event?.trust_state || event?.state;
    return typeof authoritative === "string" && authoritative
        ? authoritative
        : state.trustPhase || "STANDBY";
}

function updateTrustPhase(trust, event) {
    const phase = trustPhase(trust, event);
    const indicator = $("trust-phase-indicator");
    const flightStatus = $("flight-status");
    const previous = state.trustPhase;
    state.trustPhase = phase;

    if (indicator) {
        indicator.textContent = phase;
        indicator.className = `phase-indicator phase-${phase.toLowerCase()}`;
        if (previous && previous !== phase) {
            indicator.classList.remove("phase-transition");
            void indicator.offsetWidth;
            indicator.classList.add("phase-transition");
        }
        indicator.setAttribute("aria-label", `Current trust phase: ${phase}`);
    }

    if (flightStatus) {
        flightStatus.textContent = phase;
        flightStatus.className = `status-pill phase-${phase.toLowerCase()}`;
    }
}

function renderTrustChart() {
    const canvas = $("trust-chart");
    if (!canvas) return;
    const context = canvas.getContext("2d");
    if (!context) return;

    const bounds = canvas.getBoundingClientRect();
    const ratio = window.devicePixelRatio || 1;
    const width = Math.max(320, bounds.width);
    const height = Math.max(120, bounds.height);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(height * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, width, height);

    const left = 34;
    const right = width - 8;
    const top = 8;
    const bottom = height - 23;
    const y = (score) => bottom - Math.max(0, Math.min(1, score)) * (bottom - top);
    const thresholdBands = [
        [CONFIG.standby_threshold, 1, "rgba(39, 174, 116, .14)"],
        [CONFIG.evacuate_threshold, CONFIG.standby_threshold, "rgba(196, 143, 39, .13)"],
        [CONFIG.protect_threshold, CONFIG.evacuate_threshold, "rgba(224, 112, 42, .13)"],
        [0, CONFIG.protect_threshold, "rgba(204, 58, 76, .15)"]
    ];
    thresholdBands.forEach(([low, high, color]) => {
        context.fillStyle = color;
        context.fillRect(left, y(high), right - left, y(low) - y(high));
    });

    [0, 0.2, 0.5, 0.8, 1].forEach((tick) => {
        const yy = y(tick);
        context.strokeStyle = "rgba(130, 155, 175, .18)";
        context.beginPath();
        context.moveTo(left, yy);
        context.lineTo(right, yy);
        context.stroke();
        context.fillStyle = getComputedStyle(document.documentElement)
            .getPropertyValue("--muted");
        context.font = "10px Consolas, monospace";
        context.textAlign = "right";
        context.fillText(tick.toFixed(1), left - 6, yy + 3);
    });

    const points = state.events.map((raw) => normalizeEvent(raw).trust)
        .filter((score) => score !== null);
    if (points.length) {
        context.strokeStyle = getComputedStyle(document.documentElement)
            .getPropertyValue("--blue");
        context.lineWidth = 2;
        context.lineJoin = "round";
        context.beginPath();
        points.forEach((score, index) => {
            const x = points.length === 1
                ? (left + right) / 2
                : left + index / (points.length - 1) * (right - left);
            if (index === 0) context.moveTo(x, y(score));
            else context.lineTo(x, y(score));
        });
        context.stroke();
    }
    context.fillStyle = getComputedStyle(document.documentElement)
        .getPropertyValue("--muted");
    context.font = "10px Consolas, monospace";
    context.textAlign = "left";
    context.fillText("OLDER", left, height - 5);
    context.textAlign = "right";
    context.fillText("LATEST", right, height - 5);
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

    const hem = event.raw?.hem || {};
    const statuses = hem.transfer_status || {};
    const destination = String(event.destination || "").toLowerCase();
    const destinationLabel = destination.includes("peer")
        ? "Peer"
        : destination.includes("base") ? "Base" : event.destination;
    setText("hem-destination", destinationLabel);
    ["CRITICAL", "SENSITIVE", "ROUTINE"].forEach((priority) => {
        const row = document.querySelector(
            `.hem-priority-row[data-priority="${priority}"]`
        );
        if (!row) return;
        const status = String(statuses[priority] || "NOT STARTED").toUpperCase();
        const bar = row.querySelector("progress");
        const stateLabel = row.querySelector(".priority-state");
        if (status === "DELIVERED") {
            bar.value = 100;
        } else if (status === "FAILED") {
            bar.value = 0;
        } else {
            bar.removeAttribute("value");
        }
        bar.setAttribute("aria-valuetext", status);
        stateLabel.textContent = status;
        row.dataset.status = status.toLowerCase();
    });
    const lossCount = firstValue(
        hem,
        ["chunk_loss_count", "lost_chunks", "chunk_loss", "lost_packets"],
        firstValue(event.raw, ["chunk_loss_count", "hem_loss_count", "chunk_loss"])
    );
    const retries = firstValue(
        hem,
        ["retries", "retransmissions"],
        firstValue(event.raw, ["hem_retries", "retransmissions"])
    );
    setText("hem-loss-count", lossCount ?? "Not reported");
    setText("hem-retry-count", retries ?? "Not reported");
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

    const severity = $("severity-filter")?.value || "";
    const attackType = $("attack-filter")?.value || "";
    const filteredEvents = events.filter((raw) => {
        const event = normalizeEvent(raw);
        return (!severity || event.severity === severity) &&
            (!attackType || event.pattern === attackType);
    });

    updateAttackFilterOptions(events);

    if (!filteredEvents.length) {
        containers.forEach((container) => {
            showMessage(
                container,
                events.length ? "No events match the selected filters."
                    : "No telemetry events received yet."
            );
        });

        setText("event-count", "0 EVENTS");
        return;
    }

    const visibleEvents = filteredEvents.slice(-CONFIG.timeline_event_limit);
    const rows = visibleEvents.slice().reverse().map((raw) => {
        const event = normalizeEvent(raw);
        const row = document.createElement("details");

        row.className = `event-row ${threatClass(event)}`;
        row.dataset.eventIndex = String(visibleEvents.indexOf(raw));
        const summary = document.createElement("summary");
        summary.className = "event-summary";

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
            summary.appendChild(cell);
        });

        const scoreCell = document.createElement("span");
        scoreCell.className = "event-scores";
        const scoreText = document.createElement("span");
        scoreText.textContent = `T ${event.trust === null ? "--" : event.trust.toFixed(2)} / ML ${event.anomalyScore === null ? "--" : event.anomalyScore.toFixed(2)}`;
        const sparkline = document.createElement("canvas");
        sparkline.className = "event-sparkline";
        sparkline.width = 100;
        sparkline.height = 24;
        sparkline.setAttribute("role", "img");
        sparkline.setAttribute("aria-label", "Trust and machine-learning risk score trend");
        scoreCell.append(scoreText, sparkline);
        summary.appendChild(scoreCell);
        row.appendChild(summary);

        const details = document.createElement("pre");
        details.className = "event-details";
        const detailData = {
            sequence: event.seq,
            timestamp: event.timestamp,
            position: validCoordinates(event)
                ? { latitude: event.latitude, longitude: event.longitude }
                : null,
            trust: event.trust,
            severity: event.severity,
            attack_type: event.pattern,
            validation_flags: event.flags,
            ml_anomaly: event.anomaly,
            ml_risk_score: event.anomalyScore,
            response: event.response,
            hem_phase: event.hemPhase,
            destination: event.destination
        };
        details.textContent = JSON.stringify(detailData, null, 2).slice(0, 4096);
        row.appendChild(details);
        return row;
    });

    containers.forEach((container) => {
        const copies = rows.map((row) => row.cloneNode(true));
        container.replaceChildren(...copies);
        container.querySelectorAll(".event-row").forEach((row) => {
            const eventIndex = Number(row.dataset.eventIndex);
            const raw = visibleEvents[eventIndex];
            const event = raw ? normalizeEvent(raw) : null;
            const canvas = row.querySelector(".event-sparkline");
            if (canvas && event) {
                const index = visibleEvents.indexOf(raw);
                const windowEvents = visibleEvents
                    .slice(Math.max(0, index - 9), index + 1)
                    .map(normalizeEvent);
                drawSparkline(
                    canvas,
                    windowEvents.map((item) => item.trust),
                    windowEvents.map((item) => item.anomalyScore)
                );
            }
        });
    });

    setText("event-count", `${filteredEvents.length} / ${events.length} EVENTS`);
}

function updateAttackFilterOptions(events) {
    const select = $("attack-filter");
    if (!select) return;
    const selected = select.value;
    const attackTypes = [...new Set(events.map((raw) => normalizeEvent(raw).pattern))]
        .filter((type) => type && type !== "NORMAL")
        .sort()
        .slice(0, 50);
    const options = [new Option("All attack types", "")];
    attackTypes.forEach((type) => options.push(new Option(type, type)));
    select.replaceChildren(...options);
    if (attackTypes.includes(selected)) select.value = selected;
}

function drawSparkline(canvas, trustValues, riskValues) {
    const context = canvas.getContext("2d");
    if (!context) return;
    const width = canvas.width;
    const height = canvas.height;
    context.clearRect(0, 0, width, height);
    const series = [
        [trustValues, "#45c8ff"],
        [riskValues, "#f2bd55"]
    ];
    series.forEach(([values, color]) => {
        const valid = values.filter((value) => Number.isFinite(value));
        if (!valid.length) return;
        context.strokeStyle = color;
        context.lineWidth = 1.5;
        context.beginPath();
        valid.forEach((value, index) => {
            const x = valid.length === 1
                ? width / 2
                : index / (valid.length - 1) * width;
            const y = height - Math.max(0, Math.min(1, value)) * height;
            if (index === 0) context.moveTo(x, y);
            else context.lineTo(x, y);
        });
        context.stroke();
    });
}

/* BACKEND COMMUNICATION */

async function refreshEvents() {
    if (state.fetchBusy) return;

    state.fetchBusy = true;

    try {
        const response = await fetch(
            `${API.events}?limit=${Math.min(
                CONFIG.event_page_limit || CONFIG.timeline_event_limit,
                Math.max(CONFIG.trail_limit, CONFIG.timeline_event_limit)
            )}`,
            { cache: "no-store" }
        );

        if (!response.ok) {
            throw new Error(`Events endpoint returned HTTP ${response.status}`);
        }

        const payload = await response.json();
        consumeEvents(payload.events || []);
    } catch (error) {
        console.error("Telemetry refresh failed:", error);
        setConnection(false);
    } finally {
        state.fetchBusy = false;
    }
}

function consumeEvents(events, append = false) {
    if (append) {
        const known = new Set(state.events.map((event) =>
            `${event.seq}-${event.timestamp}-${event.pattern}`));
        const fresh = events.filter((event) =>
            !known.has(`${event.seq}-${event.timestamp}-${event.pattern}`));
        state.events = [...state.events, ...fresh]
            .slice(-Math.max(CONFIG.trail_limit, CONFIG.timeline_event_limit));
    } else {
        state.events = events.slice(-Math.max(
            CONFIG.trail_limit,
            CONFIG.timeline_event_limit
        ));
    }

    const rawLatest = state.events.length
        ? state.events[state.events.length - 1]
        : null;
    state.latest = rawLatest ? normalizeEvent(rawLatest) : null;
    if (append && events.length) {
        state.lastTelemetryAt = Date.now();
    } else if (state.latest) {
        const eventTime = Date.parse(String(state.latest.timestamp));
        state.lastTelemetryAt = Number.isFinite(eventTime) ? eventTime : null;
    }
    setConnection(true);
    renderTimeline(state.events);

    if (state.latest) {
        updateTrust(state.latest);
        updateThreat(state.latest);
        updateTelemetry(state.latest);
        updateHem(state.latest);
        updateMachineLearning(state.latest);
        updateMapFromLatest();
        if (!append) renderTrackHistory();
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
}

function connectEventStream() {
    state.streamStartedAt = Date.now();
    const stream = new EventSource(API.stream);
    stream.addEventListener("telemetry", (message) => {
        try {
            consumeEvents([JSON.parse(message.data)], true);
        } catch (error) {
            console.error("Invalid event stream message:", error);
        }
    });
    stream.onopen = () => setConnection(true);
    stream.onerror = () => setConnection(false);
}

async function establishDashboardSession() {
    let apiKey = sessionStorage.getItem("scoutx-api-key");
    if (!apiKey) {
        apiKey = window.prompt("Dashboard API key");
    }
    if (!apiKey) return false;

    sessionStorage.setItem("scoutx-api-key", apiKey);
    const response = await fetch("/api/session", {
        method: "POST",
        headers: { "X-API-Key": apiKey },
        cache: "no-store"
    });
    if (!response.ok) {
        throw new Error(`Dashboard authentication failed (HTTP ${response.status})`);
    }
    return true;
}

function setConnection(connected) {
    state.transportConnected = connected;
    setText("connection-status",
        connected ? "CONNECTED" : "DISCONNECTED");
    setText("header-connection",
        connected ? "LIVE STREAM" : "RECONNECTING");

    ["connection-dot", "header-status-dot"].forEach((id) => {
        const element = $(id);
        if (element) {
            element.classList.toggle("connected", connected);
            element.classList.toggle("disconnected", !connected);
        }
    });
}

function updateFreshness() {
    const banner = $("freshness-banner");
    if (!banner) return;
    const now = Date.now();
    const last = state.lastTelemetryAt || state.streamStartedAt || now;
    const ageSeconds = Math.max(0, Math.floor((now - last) / 1000));
    const stale = ageSeconds >= CONFIG.stale_data_seconds;
    banner.hidden = !stale;
    banner.classList.toggle("stale", stale);
    setText(
        "freshness-message",
        stale ? "STALE TELEMETRY" : "Telemetry current"
    );
    setText(
        "freshness-age",
        stale ? `No update for ${ageSeconds}s` : ""
    );
    banner.setAttribute(
        "aria-label",
        stale
            ? `Telemetry is stale. No update for ${ageSeconds} seconds.`
            : "Telemetry is current."
    );
}

function applyTheme(theme) {
    const selected = theme === "light" ? "light" : "dark";
    document.documentElement.dataset.theme = selected;
    const button = $("theme-toggle");
    if (button) {
        const next = selected === "dark" ? "light" : "dark";
        button.textContent = `${next[0].toUpperCase()}${next.slice(1)} theme`;
        button.setAttribute("aria-label", `Switch to ${next} theme`);
        button.setAttribute("aria-pressed", String(selected === "light"));
    }
    renderTrustChart();
}

function initializeTheme() {
    let saved = "dark";
    try {
        saved = localStorage.getItem("scoutx-theme") || "dark";
    } catch (error) {
        console.warn("Theme preference is unavailable:", error);
    }
    applyTheme(saved);
    $("theme-toggle")?.addEventListener("click", () => {
        const next = document.documentElement.dataset.theme === "dark"
            ? "light"
            : "dark";
        applyTheme(next);
        try {
            localStorage.setItem("scoutx-theme", next);
        } catch (error) {
            console.warn("Theme preference could not be saved:", error);
        }
    });
}

async function launchScenario(scenario) {
    const buttons = document.querySelectorAll("[data-scenario]");
    buttons.forEach((button) => { button.disabled = true; });

    setText("scenario-feedback",
        `Starting ${scenario.replaceAll("_", " ").toUpperCase()} scenario…`);

    try {
        let apiKey = sessionStorage.getItem("scoutx-api-key");
        if (!apiKey) {
            apiKey = window.prompt("Dashboard API key");
            if (!apiKey) throw new Error("An API key is required.");
            sessionStorage.setItem("scoutx-api-key", apiKey);
        }
        const response = await fetch(API.scenario, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-Key": apiKey
            },
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

        window.setTimeout(
            refreshEvents,
            CONFIG.event_refresh_delay_ms
        );
    } catch (error) {
        console.error("Scenario launch failed:", error);
        setText("scenario-feedback", `Scenario failed: ${error.message}`);
    } finally {
        window.setTimeout(() => {
            buttons.forEach((button) => { button.disabled = false; });
        }, CONFIG.scenario_feedback_delay_ms);
    }
}

document.querySelectorAll("[data-scenario]").forEach((button) => {
    button.addEventListener("click", () => {
        launchScenario(button.dataset.scenario);
    });
});

const severityFilter = $("severity-filter");
const attackFilter = $("attack-filter");
[severityFilter, attackFilter].forEach((filter) => {
    filter?.addEventListener("change", () => renderTimeline(state.events));
});

const refreshButton = $("refresh-events");
if (refreshButton) {
    refreshButton.addEventListener("click", refreshEvents);
}

const exportButton = $("export-report");
if (exportButton) {
    exportButton.addEventListener("click", async () => {
        try {
            const response = await fetch("/api/report?format=markdown", {
                cache: "no-store"
            });
            if (!response.ok) {
                throw new Error(`Report endpoint returned HTTP ${response.status}`);
            }
            const payload = await response.json();
            const download = document.createElement("a");
            const blob = new Blob([payload.content], { type: "text/markdown" });
            download.href = URL.createObjectURL(blob);
            download.download = "scout-x-event-report.md";
            download.click();
            URL.revokeObjectURL(download.href);
            setText("scenario-feedback", "Markdown report exported.");
        } catch (error) {
            console.error("Report export failed:", error);
            setText("scenario-feedback", `Report export failed: ${error.message}`);
        }
    });
}

const applyTargetsButton = $("apply-target-count");

if (applyTargetsButton) {
    applyTargetsButton.addEventListener("click", () => {
        const select = $("sim-target-count");

        state.targetCount = Math.max(
            0,
            Math.min(
                SECONDARY_TARGETS.length,
                Number(select?.value ?? CONFIG.initial_target_count)
            )
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
initializeTheme();
setText("threshold-standby", Number(CONFIG.standby_threshold).toFixed(2));
setText("threshold-prepare", Number(CONFIG.evacuate_threshold).toFixed(2));
setText("threshold-protect", Number(CONFIG.protect_threshold).toFixed(2));
setText("threshold-protect-value", Number(CONFIG.protect_threshold).toFixed(2));
(async () => {
    try {
        if (await establishDashboardSession()) {
            refreshEvents();
            connectEventStream();
            refreshAircraft();
        } else {
            setConnection(false);
            setText("scenario-feedback", "Enter the dashboard API key to view protected data.");
        }
    } catch (error) {
        console.error("Dashboard authentication failed:", error);
        setConnection(false);
        setText("scenario-feedback", error.message);
    }
})();
window.addEventListener("resize", renderTrustChart);
window.setInterval(updateFreshness, 1000);
updateFreshness();

window.setInterval(() => {
    if (state.transportConnected) refreshAircraft();
}, CONFIG.aircraft_poll_interval_ms);

window.setInterval(() => {
    updateSecondaryTargets();
    updateRadar();
}, CONFIG.simulated_target_refresh_interval_ms);
