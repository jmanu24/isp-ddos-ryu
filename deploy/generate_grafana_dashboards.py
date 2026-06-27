"""
generate_grafana_dashboards.py — builds one Grafana dashboard JSON per
network domain (openflow, mobile, broadband, enterprise, bgp), each with
the same panel layout: traffic KPIs, detections, and mitigations for
that domain alone (every PromQL query below is filtered to
domain="<that domain>").

Generated from web/metrics.py's domain-labeled series -- DOMAIN_TRAFFIC_*
(every domain, every cycle, regardless of attack state), ATTACKS_DETECTED/
ATTACK_*_RATE, MITIGATIONS_APPLIED/MITIGATION_*_RATE, and
ACTIVE_BLOCKS_BY_DOMAIN. The pre-existing deploy/grafana_dashboard.json
stays as-is -- it's OpenFlow-specific (per-switch/per-port panels that
don't generalize to the other domains) and is meant as an additional,
richer dashboard for that one domain, not replaced by openflow.json here.

Usage:
  python3 deploy/generate_grafana_dashboards.py
  (writes deploy/grafana/<domain>.json for each domain in DOMAINS)
"""

import json
from pathlib import Path

DOMAINS = ["openflow", "mobile", "broadband", "enterprise", "bgp"]
OUT_DIR = Path(__file__).resolve().parent / "grafana"

_DOMAIN_TITLES = {
    "openflow": "SDN / OpenFlow",
    "mobile": "Mobile (O-RAN)",
    "broadband": "Fixed Broadband (BNG)",
    "enterprise": "Enterprise Services",
    "bgp": "BGP Peering",
}


def _panel(id_, title, type_, x, y, w, h, targets, extra=None):
    panel = {
        "id": id_,
        "title": title,
        "type": type_,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        # Referenced by NAME, not a "${DS_PROMETHEUS}" template variable
        # -- that form only resolves when a human imports the dashboard
        # through Grafana's UI (it prompts for the datasource to bind
        # the variable to); deploy/install_monitoring.sh's auto-
        # provisioning (Grafana's file-based dashboard provider) never
        # runs that substitution step, so panels would silently end up
        # pointing at a literal, nonexistent datasource named
        # "${DS_PROMETHEUS}". Plain name resolution works for both the
        # manual-import and auto-provisioned paths, as long as a
        # datasource literally named "Prometheus" exists -- which
        # install_monitoring.sh's own datasource provisioning step
        # already creates.
        "datasource": "Prometheus",
        "targets": targets,
    }
    if extra:
        panel.update(extra)
    return panel


def _target(expr, legend, ref):
    return {"expr": expr, "legendFormat": legend, "refId": ref}


def build_dashboard(domain: str) -> dict:
    panels = []
    pid = 1

    # Row 1 — traffic KPIs (always-on, not attack-gated)
    panels.append(_panel(
        pid, "Tráfico — paquetes/seg", "timeseries", 0, 0, 8, 8,
        [_target(f'ddos_domain_traffic_pps{{domain="{domain}"}}', "pps", "A")],
    )); pid += 1
    panels.append(_panel(
        pid, "Tráfico — bytes/seg", "timeseries", 8, 0, 8, 8,
        [_target(f'ddos_domain_traffic_bps{{domain="{domain}"}}', "bps", "A")],
    )); pid += 1
    panels.append(_panel(
        pid, "Fuentes activas", "stat", 16, 0, 8, 8,
        [_target(f'ddos_domain_active_sources{{domain="{domain}"}}', "fuentes", "A")],
    )); pid += 1

    # Row 2 — detection
    panels.append(_panel(
        pid, "Ataques detectados / seg, por tipo", "timeseries", 0, 8, 12, 8,
        [_target(
            f'rate(ddos_attacks_detected_total{{domain="{domain}"}}[1m])',
            "{{attack_type}}", "A",
        )],
    )); pid += 1
    panels.append(_panel(
        pid, "Tasa del ataque detectado (pps), por tipo", "timeseries", 12, 8, 12, 8,
        [_target(
            f'ddos_attack_packet_rate{{domain="{domain}"}}',
            "{{attack_type}}", "A",
        )],
    )); pid += 1

    panels.append(_panel(
        pid, "Tasa del ataque detectado (bps), por tipo", "timeseries", 0, 16, 12, 8,
        [_target(
            f'ddos_attack_byte_rate{{domain="{domain}"}}',
            "{{attack_type}}", "A",
        )],
    )); pid += 1
    panels.append(_panel(
        pid, "Bloqueos activos", "stat", 12, 16, 12, 8,
        [_target(f'ddos_active_blocks_by_domain{{domain="{domain}"}}', "bloqueos", "A")],
    )); pid += 1

    # Row 3 — mitigation
    panels.append(_panel(
        pid, "Mitigaciones aplicadas / seg, por tipo y acción", "timeseries", 0, 24, 12, 8,
        [_target(
            f'rate(ddos_mitigations_applied_total{{domain="{domain}"}}[1m])',
            "{{attack_type}} / {{action}}", "A",
        )],
    )); pid += 1
    panels.append(_panel(
        pid, "Tasa mitigada (pps), por tipo", "timeseries", 12, 24, 12, 8,
        [_target(
            f'ddos_mitigation_packet_rate{{domain="{domain}"}}',
            "{{attack_type}} / {{action}}", "A",
        )],
    )); pid += 1

    return {
        "title": f"ISP DDoS Controller — {_DOMAIN_TITLES.get(domain, domain)}",
        "uid": f"ddos-{domain}",
        "schemaVersion": 39,
        "version": 1,
        "refresh": "5s",
        "time": {"from": "now-15m", "to": "now"},
        "templating": {"list": []},
        "panels": panels,
    }


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for domain in DOMAINS:
        out_path = OUT_DIR / f"{domain}.json"
        out_path.write_text(json.dumps(build_dashboard(domain), indent=2) + "\n")
        print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
