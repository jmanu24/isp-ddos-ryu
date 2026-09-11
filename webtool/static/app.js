// webtool/static/app.js -- frontend for the standalone attack-launcher
// app. Talks only to THIS app's own API (port 5050) -- never to web/'s
// dashboard (port 5000); the two are wired together server-side (see
// webtool/app.py's _poll_dashboard_events), not from the browser.

const socket = io();

const DOMAIN_TO_PREFIX = { enterprise: "ent", mobile: "gnb", broadband: "fixed" };
const DOMAIN_LABELS = { enterprise: "Enterprise", mobile: "Mobile", broadband: "Broadband", bgp: "External Peering" };

const el = (id) => document.getElementById(id);

// ---------------------------------------------------------------------
// Topology graph (fixed star layout, no physics -- shape never changes)
// ---------------------------------------------------------------------

const topologyNodes = new vis.DataSet([]);
const topologyEdges = new vis.DataSet([]);

const topologyNetwork = new vis.Network(
    el("topology"),
    { nodes: topologyNodes, edges: topologyEdges },
    {
        physics: false,
        interaction: { dragNodes: false, zoomView: true, dragView: true },
        edges: { color: "#aaa", width: 1.5 },
        nodes: { font: { size: 13 } },
    }
);

const DOMAIN_COLORS = {
    core: { background: "#eeeeee", border: "#999999" },
    enterprise: { background: "#dbe9ff", border: "#5b8def" },
    mobile: { background: "#ffe6d5", border: "#e8823c" },
    broadband: { background: "#dcf5df", border: "#4caf6b" },
    bgp: { background: "#ead6fd", border: "#8e44ad" },
};
const ATTACKING_COLOR = { background: "#ffb3b3", border: "#c0392b" };
const TARGET_COLOR = { background: "#fff3b0", border: "#e6b800" };

function renderTopologyGraph(nodes, activeAttacks) {
    const nodesData = [];
    const edgesData = [];

    const attackingIds = new Set();
    const targetIds = new Set();
    for (const a of activeAttacks || []) {
        if (a.domain === "bgp") {
            // peer_ext is bgp's only possible source (see
            // orchestrator.py's start_peering_attack) -- no
            // switch_indices/DOMAIN_TO_PREFIX scheme applies to it.
            attackingIds.add("peer_ext");
        } else {
            const prefix = DOMAIN_TO_PREFIX[a.domain];
            if (prefix) {
                for (const i of a.switch_indices || []) attackingIds.add(`${prefix}_${i}`);
            }
        }
        const targetNode = (nodes || []).find((n) => n.ip === a.target_ip);
        if (targetNode) targetIds.add(targetNode.id);
    }

    nodesData.push({
        id: "r1", label: "r1", shape: "box", x: 0, y: 0, fixed: true,
        color: { background: "#333333", border: "#000000" }, font: { color: "#ffffff", size: 14 },
    });

    const switchIndices = [...new Set((nodes || [])
        .filter((n) => n.switch_index != null)
        .map((n) => n.switch_index))].sort((a, b) => a - b);

    const R_SWITCH = 220;
    const R_HOST = 400;
    const R_SERVER = 140;

    // Switches sit at evenly-spaced angles starting from north (see the
    // loop below) -- with 4 of them that's exactly N/E/S/W, so a fixed
    // "south" position for the central server collides with whichever
    // switch lands there. Placing it half a step off the first switch's
    // angle instead keeps it in the gap between two switches regardless
    // of how many there are.
    const serverAngle = -Math.PI / 2 + Math.PI / Math.max(switchIndices.length, 1);
    nodesData.push({
        id: "central_server", label: "servidor central\n10.99.0.1", shape: "database",
        x: R_SERVER * Math.cos(serverAngle), y: R_SERVER * Math.sin(serverAngle), fixed: true,
        color: DOMAIN_COLORS.core,
    });
    edgesData.push({ from: "r1", to: "central_server" });

    // peer_ext (external/upstream peer, docs/peering-plan.md §5) links
    // directly to r1 like central_server -- no switch in between, so it
    // never matches the switchIndices-driven loop below. Opposite angle
    // from the central server so the two don't collide.
    const peerExtNode = (nodes || []).find((n) => n.id === "peer_ext");
    if (peerExtNode) {
        const peerExtAngle = serverAngle + Math.PI;
        const isAttacking = attackingIds.has("peer_ext");
        nodesData.push({
            id: "peer_ext", label: `peer_ext\n${peerExtNode.ip}`, shape: "ellipse",
            x: R_SERVER * Math.cos(peerExtAngle), y: R_SERVER * Math.sin(peerExtAngle), fixed: true,
            color: isAttacking ? ATTACKING_COLOR : DOMAIN_COLORS.bgp,
            borderWidth: isAttacking ? 3 : 1,
        });
        edgesData.push({ from: "r1", to: "peer_ext" });
    }

    switchIndices.forEach((si, idx) => {
        const angle = (idx / switchIndices.length) * 2 * Math.PI - Math.PI / 2;
        const sx = R_SWITCH * Math.cos(angle);
        const sy = R_SWITCH * Math.sin(angle);
        const switchId = `s${si}`;

        nodesData.push({
            id: switchId, label: switchId, shape: "box", x: sx, y: sy, fixed: true,
            color: { background: "#f5f5f5", border: "#888888" },
        });
        edgesData.push({ from: "r1", to: switchId });

        const hostsForSwitch = (nodes || []).filter((n) => n.switch_index === si);
        const spread = 0.75;
        hostsForSwitch.forEach((h, hi) => {
            const hAngle = angle + (hi - (hostsForSwitch.length - 1) / 2) * (spread / hostsForSwitch.length);
            const hx = R_HOST * Math.cos(hAngle);
            const hy = R_HOST * Math.sin(hAngle);
            const isAttacking = attackingIds.has(h.id);
            const isTarget = targetIds.has(h.id);
            const color = isAttacking ? ATTACKING_COLOR : (isTarget ? TARGET_COLOR : (DOMAIN_COLORS[h.domain] || DOMAIN_COLORS.core));

            nodesData.push({
                id: h.id, label: `${h.id}\n${h.ip}`, shape: "ellipse", x: hx, y: hy, fixed: true,
                color, borderWidth: (isAttacking || isTarget) ? 3 : 1,
            });
            edgesData.push({ from: switchId, to: h.id });
        });
    });

    topologyNodes.clear();
    topologyEdges.clear();
    topologyNodes.add(nodesData);
    topologyEdges.add(edgesData);
}

// ---------------------------------------------------------------------
// Status pills / controller & topology controls
// ---------------------------------------------------------------------

function setPill(id, status) {
    const e = el(id);
    e.textContent = status;
    e.className = "pill pill-" + status;
}

function postJSON(url, body) {
    return fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
    })
        .then((r) => r.json())
        .then((data) => {
            if (!data.ok) alert(data.error || "Error desconocido");
            refreshState();
            return data;
        })
        .catch((err) => alert("Error de red: " + err));
}

el("btn-controller-start").onclick = () => postJSON("/api/controller/start");
el("btn-controller-stop").onclick = () => postJSON("/api/controller/stop");
el("btn-topology-start").onclick = () => postJSON("/api/topology/start");
el("btn-topology-stop").onclick = () => postJSON("/api/topology/stop");

// ---------------------------------------------------------------------
// Attack form
// ---------------------------------------------------------------------

el("attack-domain").onchange = () => {
    const domain = el("attack-domain").value;
    el("row-count-per-node").style.display = domain === "mobile" ? "" : "none";

    // bgp has exactly one possible source (peer_ext) -- no switch
    // selection applies, show a fixed label instead.
    const isBgp = domain === "bgp";
    el("row-switch-checks").style.display = isBgp ? "none" : "";
    el("row-bgp-source").style.display = isBgp ? "" : "none";

    // SYN_DISTRIBUTED (8-session BNGBlaster scenario) only makes sense
    // for broadband -- enterprise/mobile already reach a distributed
    // attack via multiple switch_indices/count_per_node with plain SYN.
    const typeSelect = el("attack-type");
    const distributedOption = typeSelect.querySelector('option[value="SYN_DISTRIBUTED"]');
    distributedOption.hidden = domain !== "broadband";
    if (domain !== "broadband" && typeSelect.value === "SYN_DISTRIBUTED") {
        typeSelect.value = "SYN";
    }
};

function renderTargetOptions(nodes) {
    const select = el("attack-target");
    const previous = select.value;
    select.innerHTML = "";
    (nodes || [])
        // peer_ext is bgp's attack SOURCE (orchestrator.py's
        // valid_targets() never includes it either) -- excluded here
        // the same way "core" (the central server, a valid target) is
        // deliberately kept, just the opposite reason.
        .filter((n) => n.domain !== "core" && n.id !== "peer_ext")
        .forEach((n) => {
            const opt = document.createElement("option");
            opt.value = n.ip;
            opt.textContent = `${n.id} (${n.ip})`;
            select.appendChild(opt);
        });
    if ([...select.options].some((o) => o.value === previous)) select.value = previous;
}

el("attack-form").onsubmit = (ev) => {
    ev.preventDefault();

    const domain = el("attack-domain").value;
    const switchIndices = [...document.querySelectorAll(".switch-check:checked")].map((c) => parseInt(c.value, 10));
    if (domain !== "bgp" && switchIndices.length === 0) {
        alert("Selecciona al menos un switch origen.");
        return;
    }
    const targetIp = el("attack-target").value;
    if (!targetIp) {
        alert("No hay objetivos disponibles -- inicia la topologia primero.");
        return;
    }

    const payload = {
        domain,
        switch_indices: switchIndices,
        attack_type: el("attack-type").value,
        target_ip: targetIp,
        duration: el("attack-indefinite").checked ? null : (parseInt(el("attack-duration").value, 10) || null),
    };
    const port = el("attack-port").value;
    if (port !== "") payload.dst_port = parseInt(port, 10);
    if (domain === "mobile") payload.count_per_node = parseInt(el("attack-count").value, 10) || 1;

    postJSON("/api/attack/start", payload);
};

// ---------------------------------------------------------------------
// Test scenarios (webtool/TEST_PLAN.md, run on demand) -- two cascading
// dropdowns: pick the top-level scenario (1-5), then the sub-scenario
// within it (e.g. 2a/2b/2c). Grouping/order both come straight from the
// catalog (webtool/scenarios.py) -- nothing hardcoded here.
// ---------------------------------------------------------------------

let allScenarios = [];

function populateGroupSelect() {
    const select = el("scenario-group");
    const seen = new Set();
    select.innerHTML = "";
    for (const s of allScenarios) {
        if (seen.has(s.group)) continue;
        seen.add(s.group);
        const opt = document.createElement("option");
        opt.value = s.group;
        opt.textContent = s.group_label;
        select.appendChild(opt);
    }
}

function populateSubSelect() {
    const group = el("scenario-group").value;
    const select = el("scenario-sub");
    select.innerHTML = "";
    allScenarios
        .filter((s) => s.group === group)
        .forEach((s) => {
            const opt = document.createElement("option");
            opt.value = s.id;
            opt.textContent = s.label;
            select.appendChild(opt);
        });
}

function renderScenarioDetails() {
    const scenario = allScenarios.find((s) => s.id === el("scenario-sub").value);
    const details = el("scenario-details");
    const runBtn = el("btn-scenario-run");
    if (!scenario) {
        details.innerHTML = "";
        runBtn.disabled = true;
        return;
    }
    const isInfoOnly = !scenario.steps || scenario.steps.length === 0;
    details.innerHTML = `
        <div class="scenario-description">${scenario.description}</div>
        <div class="scenario-expected"><em>Esperado:</em> ${scenario.expected}</div>
        ${isInfoOnly ? '<div class="scenario-info-note">Sin ataque -- verificar manualmente.</div>' : ""}`;
    runBtn.disabled = isInfoOnly;
}

el("scenario-group").onchange = () => {
    populateSubSelect();
    renderScenarioDetails();
};
el("scenario-sub").onchange = renderScenarioDetails;

el("btn-scenario-run").onclick = () => {
    const scenarioId = el("scenario-sub").value;
    if (!scenarioId) return;
    const btn = el("btn-scenario-run");
    btn.disabled = true;
    postJSON(`/api/scenarios/${scenarioId}/run`).finally(() => {
        renderScenarioDetails();
    });
};

function loadScenarios() {
    fetch("/api/scenarios").then((r) => r.json()).then((scenarios) => {
        allScenarios = scenarios || [];
        populateGroupSelect();
        populateSubSelect();
        renderScenarioDetails();
    }).catch(() => {});
}

// ---------------------------------------------------------------------
// Active attacks / event log
// ---------------------------------------------------------------------

function renderAttacks(attacks) {
    const container = el("attacks");
    if (!attacks || attacks.length === 0) {
        container.innerHTML = '<div class="empty-note">Sin ataques activos.</div>';
        return;
    }
    container.innerHTML = attacks.map((a) => {
        const elapsed = a.started_at ? Math.floor(Date.now() / 1000 - a.started_at) : null;
        const durationText = a.duration ? `${a.duration}s` : "indefinido";
        return `
        <div class="attack-card">
          <div class="attack-info">
            <span class="attack-domain-tag tag-${a.domain}">${DOMAIN_LABELS[a.domain] || a.domain}</span>
            ${a.domain === "bgp" ? "origen=peer_ext" : `switches=[${(a.switch_indices || []).join(",")}]`}
            ${a.attack_type} -&gt; ${a.target_ip}
            (duracion: ${durationText}${elapsed !== null ? `, hace ${elapsed}s` : ""})
          </div>
          <button class="btn-danger" data-attack-id="${a.attack_id}">Detener</button>
        </div>`;
    }).join("");

    container.querySelectorAll("button[data-attack-id]").forEach((btn) => {
        btn.onclick = () => postJSON("/api/attack/stop", { attack_id: btn.dataset.attackId });
    });
}

const BLOCK_DOMAIN_LABELS = { enterprise: "Enterprise", mobile: "Mobile", broadband: "Broadband", bgp: "BGP" };

function elapsed(ts) {
    if (!ts) return "—";
    const secs = Math.floor(Date.now() / 1000 - ts);
    if (secs < 60) return secs + "s";
    const mins = Math.floor(secs / 60);
    if (mins < 60) return mins + "m " + (secs % 60) + "s";
    return Math.floor(mins / 60) + "h " + (mins % 60) + "m";
}

function renderBlocks(blocks) {
    const container = el("blocks");
    if (!blocks || blocks.length === 0) {
        container.innerHTML = '<div class="empty-note">Sin bloques activos.</div>';
        return;
    }
    const rows = blocks.map((b) => `
        <tr>
          <td>${b.src_ip}</td>
          <td>${b.dst_ip}</td>
          <td>${b.dst_port || "—"}</td>
          <td>${b.protocol}</td>
          <td><span class="attack-domain-tag tag-${b.domain}">${b.attack_type}</span></td>
          <td><span class="attack-domain-tag tag-${b.domain}">${BLOCK_DOMAIN_LABELS[b.domain] || b.domain}</span></td>
          <td>${elapsed(b.blocked_at)}</td>
          <td><button class="btn-danger btn-unblock"
                data-src="${b.src_ip}" data-dst="${b.dst_ip}"
                data-port="${b.dst_port || 0}" data-proto="${b.protocol}">
              Desbloquear
            </button></td>
        </tr>`).join("");
    container.innerHTML = `<table class="blocks-table">
        <thead><tr>
          <th>Fuente</th><th>Destino</th><th>Puerto</th><th>Protocolo</th>
          <th>Tipo</th><th>Dominio</th><th>Bloqueado hace</th><th>Acción</th>
        </tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
    container.querySelectorAll(".btn-unblock").forEach((btn) => {
        btn.onclick = () => {
            postJSON("/api/blocks/unblock", {
                src_ip:   btn.dataset.src,
                dst_ip:   btn.dataset.dst,
                dst_port: parseInt(btn.dataset.port, 10),
                protocol: btn.dataset.proto,
            });
        };
    });
}

function renderEvents(events) {
    const container = el("events");
    if (!events || events.length === 0) {
        container.innerHTML = '<div class="empty-note">Sin eventos todavia.</div>';
        return;
    }
    container.innerHTML = events.slice().reverse().map(
        (e) => `<div>${e.timestamp} — ${e.message}</div>`
    ).join("");
}

// ---------------------------------------------------------------------
// State plumbing -- REST for the initial paint, SocketIO for live updates
// ---------------------------------------------------------------------

function renderState(data) {
    setPill("controller-status", data.controller_status);
    setPill("topology-status", data.topology_status);
    renderTopologyGraph(data.nodes, data.active_attacks);
    renderTargetOptions(data.nodes);
    renderAttacks(data.active_attacks);
    renderBlocks(data.active_blocks);
    renderEvents(data.events);
}

function refreshState() {
    fetch("/api/state").then((r) => r.json()).then(renderState).catch(() => {});
}

socket.on("state_update", renderState);
refreshState();
loadScenarios();
