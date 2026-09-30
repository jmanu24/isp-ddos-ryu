const socket = io();
let topology = null;
let latestState = null;
const charts = {};

// -------------------------------------------------------------- colors --
const DOMAIN_COLORS = {
  shared: { background: "#eeeeee", border: "#999999" },
  enterprise: { background: "#dbe9ff", border: "#5b8def" },
  mobile: { background: "#ffe6d5", border: "#e8823c" },
  broadband: { background: "#dcf5df", border: "#4caf6b" },
  bgp: { background: "#ead6fd", border: "#8e44ad" },
};
const OFF_COLOR = { background: "#2a2f3a", border: "#555b68" };
const ATTACKING_BORDER = "#e0503c";
const TARGET_BORDER = "#e0a72c";
const DATA_NETWORKS = ["BB_ACCESS", "PEERING", "RAN", "ENT_LAN", "ENT_DC",
  "BACKBONE_MOBILE", "BACKBONE_FIXED", "BACKBONE_PEERING"]; // MGMT excluded -- pure management, not the attack/data path

let visNetwork = null;
const visNodes = new vis.DataSet([]);
const visEdges = new vis.DataSet([]);

function ensureVisNetwork() {
  if (visNetwork) return;
  visNetwork = new vis.Network(
    document.getElementById("topology-graph"),
    { nodes: visNodes, edges: visEdges },
    {
      physics: { stabilization: true, barnesHut: { springLength: 110, avoidOverlap: 0.6 } },
      layout: { improvedLayout: true },
      interaction: { hover: true },
      edges: { color: "#39404d", width: 1.2, smooth: false },
      nodes: { font: { size: 12, color: "#e6e8eb" } },
    }
  );
}

function nodeVisualState(nodeName) {
  const status = latestState && latestState.node_status ? latestState.node_status[nodeName] : null;
  const power = status ? status.power : "unknown";
  const checks = (status && status.checks) || {};
  if (power === "poweredOff") return "off";
  if (power !== "poweredOn") return "unknown";
  if (checks.reachable === false) return "unreachable";
  if (checks.healthy === false || checks.f1_setup_failed === true) return "warn";
  return "on";
}

// ---------------------------------------------------------------- tabs --
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
  });
});

socket.on("connect", () => {
  document.getElementById("conn-badge").textContent = "conectado";
  document.getElementById("conn-badge").className = "badge ok";
});
socket.on("disconnect", () => {
  document.getElementById("conn-badge").textContent = "desconectado";
  document.getElementById("conn-badge").className = "badge bad";
});
socket.on("state_update", (state) => {
  latestState = state;
  renderDomains();
  renderPowerTable();
  renderAnsibleConsole();
  renderAttacks();
  renderKpm();
  renderMetrics();
  renderEvents();
});

// ------------------------------------------------------------ topology --
async function loadTopology() {
  const res = await fetch("/api/topology");
  topology = await res.json();
  renderDomains();
  populateSelectors();
}

function powerDot(power) {
  if (power === "poweredOn") return "on";
  if (power === "poweredOff") return "off";
  return "unknown";
}

function renderDomains() {
  if (!topology) return;
  const container = document.getElementById("domains");
  container.innerHTML = "";
  for (const [domain, nodes] of Object.entries(topology.domains)) {
    const col = document.createElement("div");
    col.className = "domain-col";
    col.innerHTML = `<h2>${domain}</h2>`;
    for (const n of nodes) {
      const status = latestState && latestState.node_status ? latestState.node_status[n.name] : null;
      const power = status ? status.power : "unknown";
      const checks = status && status.checks ? status.checks : {};
      const card = document.createElement("div");
      card.className = "node-card";
      card.innerHTML = `
        <div><span class="dot ${powerDot(power)}"></span><span class="name">${n.name}</span></div>
        <div class="ip">${n.ip || "(sin IP)"} -- ${n.role}</div>
        <div class="checks">${escapeHtml(JSON.stringify(checks))}</div>
      `;
      col.appendChild(card);
    }
    container.appendChild(col);
  }
  renderTopologyGraph();
}

function escapeHtml(s) {
  return s.replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

// ---------------------------------------------------------- graph view --
function renderTopologyGraph() {
  if (!topology) return;
  ensureVisNetwork();

  const allNodes = Object.values(topology.domains).flat();
  const attackingIds = new Set();
  const targetIds = new Set();
  for (const a of (latestState && latestState.active_attacks) || []) {
    attackingIds.add(a.source);
    const targetNode = allNodes.find(n => n.ip === a.target_ip);
    if (targetNode) targetIds.add(targetNode.name);
  }

  const nodesData = [];
  const edgesData = [];
  const domainByName = {};
  for (const [domain, nodes] of Object.entries(topology.domains)) {
    for (const n of nodes) domainByName[n.name] = domain;
  }

  for (const n of allNodes) {
    const vstate = nodeVisualState(n.name);
    const domainColor = DOMAIN_COLORS[domainByName[n.name]] || DOMAIN_COLORS.shared;
    const isAttacking = attackingIds.has(n.name);
    const isTarget = targetIds.has(n.name);
    let color = vstate === "off" ? OFF_COLOR : domainColor;
    let borderColor = color.border;
    let borderWidth = 1;
    if (isAttacking) { borderColor = ATTACKING_BORDER; borderWidth = 3; }
    else if (isTarget) { borderColor = TARGET_BORDER; borderWidth = 3; }
    else if (vstate === "warn") { borderColor = "#e0a72c"; borderWidth = 2; }
    else if (vstate === "unreachable") { borderColor = "#d98c00"; borderWidth = 2; }
    nodesData.push({
      id: n.name, label: `${n.name}\n${n.ip || ""}`, shape: "ellipse",
      color: { background: color.background, border: borderColor },
      borderWidth, opacity: vstate === "off" ? 0.45 : 1,
    });
  }

  for (const netName of DATA_NETWORKS) {
    const members = allNodes.filter(n => (n.interfaces || []).some(i => i.network === netName));
    if (members.length < 2) continue;
    const hubId = `net:${netName}`;
    nodesData.push({
      id: hubId, label: netName, shape: "box", color: { background: "#171a21", border: "#3a4152" },
      font: { size: 10, color: "#8b93a1" }, margin: 6,
    });
    for (const m of members) edgesData.push({ from: hubId, to: m.name });
  }

  visNodes.clear();
  visEdges.clear();
  visNodes.add(nodesData);
  visEdges.add(edgesData);
}

// ------------------------------------------------------------- bring-up --
async function loadBringupSteps() {
  const res = await fetch("/api/bringup/steps");
  const steps = await res.json();
  const grid = document.getElementById("bringup-steps");
  grid.innerHTML = "";
  for (const s of steps) {
    const btn = document.createElement("button");
    btn.textContent = s.label;
    btn.addEventListener("click", async () => {
      await fetch("/api/bringup/step", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tag: s.tags }),
      });
    });
    grid.appendChild(btn);
  }
}

document.getElementById("btn-bringup-full").addEventListener("click", async () => {
  const power_cycle = document.getElementById("opt-power-cycle").checked;
  const skip_victim = document.getElementById("opt-skip-victim").checked;
  await fetch("/api/bringup/full", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ power_cycle, skip_victim }),
  });
});
document.getElementById("btn-bringup-cancel").addEventListener("click", async () => {
  await fetch("/api/bringup/cancel", { method: "POST" });
});

// ---------------------------------------------------------- power table --
// One row per VM in the WHOLE lab (all 4 domains + shared infra), not
// just the mobile domain -- the ordered bring-up below only exists for
// mobile (it drives reconnect_mobile_domain.yml); every other VM is
// powered individually here via plain govc on/off.
function renderPowerTable() {
  if (!topology) return;
  const tbody = document.getElementById("power-tbody");
  tbody.innerHTML = "";
  for (const [domain, nodes] of Object.entries(topology.domains)) {
    for (const n of nodes) {
      const status = latestState && latestState.node_status ? latestState.node_status[n.name] : null;
      const power = status ? status.power : "unknown";
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${n.name}</td><td>${domain}</td>
        <td><span class="dot ${powerDot(power)}"></span>${power}</td><td></td>`;
      const cell = tr.lastElementChild;
      const onBtn = document.createElement("button");
      onBtn.textContent = "Encender"; onBtn.className = "small";
      onBtn.addEventListener("click", () => fetch(`/api/power/${n.name}/on`, { method: "POST" }));
      const offBtn = document.createElement("button");
      offBtn.textContent = "Apagar"; offBtn.className = "small";
      offBtn.style.marginLeft = "4px";
      offBtn.addEventListener("click", () => fetch(`/api/power/${n.name}/off`, { method: "POST" }));
      cell.appendChild(onBtn); cell.appendChild(offBtn);
      tbody.appendChild(tr);
    }
  }
}

function renderAnsibleConsole() {
  if (!latestState) return;
  const job = latestState.ansible_job;
  const statusEl = document.getElementById("ansible-status");
  const consoleEl = document.getElementById("ansible-console");
  if (!job) { statusEl.textContent = "sin jobs corridos"; return; }
  statusEl.textContent = `${job.label} -- ${job.running ? "corriendo" : "terminado"}${job.rc !== null ? " (rc=" + job.rc + ")" : ""}`;
  consoleEl.textContent = (job.lines || []).join("\n");
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

// -------------------------------------------------------------- attacks --
function populateSelectors() {
  if (!topology) return;
  const nodeSel = document.getElementById("metrics-node");
  const logSel = document.getElementById("log-node");
  nodeSel.innerHTML = ""; logSel.innerHTML = "";
  for (const nodes of Object.values(topology.domains)) {
    for (const n of nodes) {
      nodeSel.appendChild(new Option(n.name, n.name));
      logSel.appendChild(new Option(n.name, n.name));
    }
  }
  loadAttackSources();
  loadLogSources();
}

document.getElementById("atk-domain").addEventListener("change", loadAttackSources);
async function loadAttackSources() {
  const domain = document.getElementById("atk-domain").value;
  const res = await fetch(`/api/attack/sources/${domain}`);
  const sources = await res.json();
  const sel = document.getElementById("atk-source");
  sel.innerHTML = "";
  for (const s of sources) sel.appendChild(new Option(s, s));
}

document.getElementById("btn-atk-start").addEventListener("click", async () => {
  const body = {
    domain: document.getElementById("atk-domain").value,
    source: document.getElementById("atk-source").value,
    attack_type: document.getElementById("atk-type").value,
    dst_port: parseInt(document.getElementById("atk-port").value || "0", 10),
    target_ip: document.getElementById("atk-target").value,
  };
  const res = await fetch("/api/attack/start", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!data.ok) alert("Error: " + data.error);
});

function renderAttacks() {
  if (!latestState) return;
  const tbody = document.getElementById("attacks-tbody");
  tbody.innerHTML = "";
  for (const a of latestState.active_attacks || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${a.domain}</td><td>${a.source}</td><td>${a.attack_type}</td><td>${a.target_ip}</td><td></td>`;
    const btn = document.createElement("button");
    btn.textContent = "Detener"; btn.className = "small";
    btn.addEventListener("click", async () => {
      await fetch("/api/attack/stop", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_id: a.attack_id }),
      });
    });
    tr.lastElementChild.appendChild(btn);
    tbody.appendChild(tr);
  }
}

// ------------------------------------------------------------------ kpm --
// gnb_du_id N maps directly onto UE netns "ueN" -- the KPM bridge's own
// per-DU numbering already follows the 1:1 DU<->UE pairing this lab
// bring-up uses (du->ue1, du2->ue2, ..., du5->ue5; see mobile-bringup-
// order memory / inventory.py's UE_NETNS table).
function renderKpm() {
  if (!latestState) return;
  const samples = latestState.kpm_samples || [];
  const byUeNum = {};
  for (const s of samples) {
    if (s && s.gnb_du_id != null) byUeNum[s.gnb_du_id] = s;
  }
  const tbody = document.getElementById("kpm-tbody");
  tbody.innerHTML = "";
  const ueList = (topology && topology.ue_netns) || [1, 2, 3, 4, 5].map(i => ({ netns: `ue${i}`, du_host: "?" }));
  for (const ue of ueList) {
    const num = parseInt(ue.netns.replace("ue", ""), 10);
    const s = byUeNum[num];
    const m = (s && s.metrics) || {};
    const updated = s && s.updated_at ? new Date(s.updated_at * 1000).toLocaleTimeString() : "--";
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${ue.netns}</td><td>${ue.du_host}</td><td>${s ? s.imsi || "" : "sin dato"}</td>
      <td>${m["DRB.UEThpUl"] ?? "--"}</td><td>${m["DRB.UEThpDl"] ?? "--"}</td>
      <td>${m["RRU.PrbUsedUl"] ?? "--"}</td><td>${m["RRU.PrbAvailUl"] ?? "--"}</td><td>${updated}</td>`;
    tbody.appendChild(tr);
  }
  document.getElementById("kpm-events").textContent = (latestState.mitigation_events || [])
    .map(e => `${e.timestamp}  ${e.message}`).join("\n");
}

// -------------------------------------------------------------- metrics --
function ensureCharts() {
  if (charts.cpu) return;
  const mkChart = (id, label) => new Chart(document.getElementById(id), {
    type: "line",
    data: { labels: [], datasets: [{ label, data: [], borderColor: "#4f8cff", tension: 0.2 }] },
    options: { animation: false, scales: { y: { beginAtZero: true } } },
  });
  charts.cpu = mkChart("chart-cpu", "CPU %");
  charts.mem = mkChart("chart-mem", "Mem %");
  charts.net = new Chart(document.getElementById("chart-net"), {
    type: "line",
    data: { labels: [], datasets: [] },
    options: { animation: false },
  });
}

document.getElementById("metrics-node").addEventListener("change", renderMetrics);

function renderMetrics() {
  if (!latestState || !latestState.metrics) return;
  ensureCharts();
  const node = document.getElementById("metrics-node").value;
  const m = latestState.metrics[node];
  if (!m) return;
  // history isn't included in the lightweight to_dict() snapshot; use the
  // single latest sample per tick, appended client-side for a live trend.
  const t = new Date().toLocaleTimeString();
  for (const chart of [charts.cpu, charts.mem]) {
    if (chart.data.labels.length > 60) { chart.data.labels.shift(); chart.data.datasets[0].data.shift(); }
  }
  charts.cpu.data.labels.push(t);
  charts.cpu.data.datasets[0].data.push(m.cpu_pct);
  charts.cpu.update();
  charts.mem.data.labels.push(t);
  charts.mem.data.datasets[0].data.push(m.mem_pct);
  charts.mem.update();

  const iface = m.iface || {};
  charts.net.data.labels = charts.cpu.data.labels;
  const names = Object.keys(iface);
  const colors = ["#4f8cff", "#35c47a", "#e0a72c", "#e0503c", "#a95fe0"];
  charts.net.data.datasets = names.map((name, i) => ({
    label: `${name} rx`, borderColor: colors[i % colors.length],
    data: charts.net.data.datasets.find(d => d.label === `${name} rx`)?.data || [],
  }));
  names.forEach((name, i) => {
    const ds = charts.net.data.datasets[i];
    if (ds.data.length > 60) ds.data.shift();
    ds.data.push(iface[name].rx_bps);
  });
  charts.net.update();
}

// ------------------------------------------------------------------ logs --
async function loadLogSources() {
  const node = document.getElementById("log-node").value;
  if (!node) return;
  const res = await fetch(`/api/logs/sources/${node}`);
  const sources = await res.json();
  const sel = document.getElementById("log-source");
  sel.innerHTML = "";
  for (const s of sources) sel.appendChild(new Option(s.label, s.id));
}
document.getElementById("log-node").addEventListener("change", loadLogSources);
document.getElementById("btn-log-fetch").addEventListener("click", async () => {
  const node = document.getElementById("log-node").value;
  const source = document.getElementById("log-source").value;
  const res = await fetch(`/api/logs/${node}/${source}`);
  const data = await res.json();
  document.getElementById("log-output").textContent = data.ok ? data.text : `ERROR: ${data.error || data.text}`;
});

// ---------------------------------------------------------------- events --
function renderEvents() {
  if (!latestState) return;
  document.getElementById("events-output").textContent = (latestState.events || [])
    .map(e => `${e.timestamp}  ${e.message}`).join("\n");
}

loadTopology();
loadBringupSteps();
