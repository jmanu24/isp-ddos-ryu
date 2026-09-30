"""
webtool/logs.py -- on-demand log fetch for the UI's troubleshooting
viewer. One SSH round trip per request (not polled), so this stays cheap
even with many components. Each source below is a concrete file/unit/
container this lab's own Ansible roles/playbooks already write to.
"""

from typing import List

from webtool.ssh_ops import docker_logs, journalctl, run, tail_file

# node -> list of {id, label, kind, target} log sources the UI can fetch.
LOG_SOURCES = {
    "core5g": [
        {"id": "open5gs", "label": "open5gs_5gc (docker)", "kind": "docker", "target": "open5gs_5gc"},
        {"id": "ue-telemetry-api", "label": "ue-telemetry-api.service", "kind": "journal", "target": "ue-telemetry-api"},
    ],
    "ric": [
        {"id": "compose", "label": "docker compose ps -a", "kind": "raw", "target": "cd ~/oran-sc-ric && sudo docker compose ps -a 2>&1"},
        {"id": "xapp-runner", "label": "python_xapp_runner (docker)", "kind": "docker", "target": "python_xapp_runner"},
        {"id": "rc_actuator", "label": "rc_actuator (docker)", "kind": "docker", "target": "rc_actuator"},
    ],
    "ran": [{"id": "cu", "label": "/tmp/cu.log", "kind": "file", "target": "/tmp/cu.log"},
            {"id": "cu_stdout", "label": "/tmp/cu_stdout.log", "kind": "file", "target": "/tmp/cu_stdout.log"}],
    "cu2": [{"id": "cu", "label": "/tmp/cu.log", "kind": "file", "target": "/tmp/cu.log"},
            {"id": "cu_stdout", "label": "/tmp/cu_stdout.log", "kind": "file", "target": "/tmp/cu_stdout.log"}],
    "bng": [{"id": "accel-ppp", "label": "accel-pppd.service", "kind": "journal", "target": "accel-pppd"},
            {"id": "flow", "label": "flow.service (softflowd)", "kind": "journal", "target": "flow"}],
    "br": [{"id": "bgpd", "label": "bgpd.service", "kind": "journal", "target": "bgpd"},
           {"id": "nfcapd", "label": "nfcapd.service", "kind": "journal", "target": "nfcapd"}],
    "peer-router": [{"id": "bird", "label": "bird.service", "kind": "journal", "target": "bird"}],
    "orchestrator": [{"id": "ryu", "label": "ryu-manager.service", "kind": "journal", "target": "ryu-manager"},
                      {"id": "exabgp", "label": "exabgp.service", "kind": "journal", "target": "exabgp"}],
    "pe": [{"id": "ovs", "label": "ovs-vsctl show", "kind": "raw", "target": "ovs-vsctl show 2>&1"}],
}
for _du in ("du", "du2", "du3", "du4", "du5"):
    LOG_SOURCES[_du] = [
        {"id": "du", "label": "/tmp/du.log", "kind": "file", "target": "/tmp/du.log"},
        {"id": "du_stdout", "label": "/tmp/du_stdout.log", "kind": "file", "target": "/tmp/du_stdout.log"},
    ]
for _ue_host, _nss in (("ue", ["ue1", "ue2", "ue3"]), ("ue2", ["ue4", "ue5"])):
    LOG_SOURCES[_ue_host] = [
        {"id": ns, "label": f"journalctl -u {ns}", "kind": "journal", "target": ns} for ns in _nss
    ]
for _i in range(1, 6):
    LOG_SOURCES[f"ent-site-{_i}"] = [
        {"id": "syslog", "label": "/var/log/syslog (tail)", "kind": "file", "target": "/var/log/syslog"},
    ]
LOG_SOURCES["suscriptor"] = [
    {"id": "agent", "label": "bng_subscriber_agent (raw ps)", "kind": "raw", "target": "ps aux | grep bng_subscriber_agent | grep -v grep"},
]
LOG_SOURCES["victim"] = [
    {"id": "victim", "label": "victim server (raw ps)", "kind": "raw", "target": "ps aux | grep python3 | grep -v grep"},
]


def fetch_log(node_name: str, source_id: str, lines: int = 300) -> dict:
    sources = LOG_SOURCES.get(node_name, [])
    src = next((s for s in sources if s["id"] == source_id), None)
    if src is None:
        return {"ok": False, "error": f"fuente de log desconocida: {node_name}/{source_id}"}
    if src["kind"] == "docker":
        res = docker_logs(node_name, src["target"], lines)
    elif src["kind"] == "journal":
        res = journalctl(node_name, src["target"], lines)
    elif src["kind"] == "file":
        res = tail_file(node_name, src["target"], lines)
    else:  # raw
        res = run(node_name, src["target"], timeout=15, become=True)
    return {"ok": res.ok, "text": res.stdout if res.ok else (res.stdout + res.stderr)}


def sources_for(node_name: str) -> List[dict]:
    return LOG_SOURCES.get(node_name, [])
