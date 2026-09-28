#!/usr/bin/env python3
"""RIC-local E2SM-KPM exporter.

Runs FlexRIC's xapp_kpm_moni as a supervised child and exposes the latest
per-UE KPM sample through GET /kpm, keyed by AMF-UE-NGAP-ID.

xapp_kpm_moni emits one indication block per UE per E2 node. There are
three UE-ID shapes (confirmed against FlexRIC's own
examples/xApp/c/monitor/xapp_kpm_moni.c print routines):

  * CU-CP:   "UE ID type = gNB, amf_ue_ngap_id = <N>"
             optionally followed by one or more "gnb_cu_ue_f1ap = <F>"
             lines (this lab's srsran-cu-f1ap-ue-id-kpm-correlation.patch
             makes the CU-CP advertise that F1AP id) -- carries CU-CP-level
             metrics (RRC.ConnMean).
  * DU:      "UE ID type = gNB-DU, gnb_cu_ue_f1ap = <F>" -- carries the
             DU-level radio metrics (DRB.UEThpUl/Dl, RRU.PrbUsed/Tot Ul/Dl,
             delays). srsRAN's DU meas provider sets ran_ue_id_present =
             false, so a DU block carries NO amf_ue_ngap_id -- only <F>.
  * CU-UP:   "UE ID type = gNB-CU-UP, gnb_cu_cp_ue_e1ap = <E>" -- PDCP
             metrics; not joined (no F1AP id to bridge to a UE here).

Joining DU metrics to a UE therefore has to go through gnb_cu_ue_f1ap:
the CU-CP block gives (amf_ue_ngap_id <- gnb_cu_ue_f1ap); the DU block
gives (gnb_cu_ue_f1ap -> radio metrics). We build that f1ap->amf map from
CU-CP blocks and merge each DU block's metrics into the matching UE's
sample.

KNOWN BLOCKER, confirmed on a real 5-UE run (see docs/ran-testing.md):
srsRAN reports gnb_cu_ue_f1ap = 0 for EVERY UE, in both the CU-CP and DU
indications. The CU-CP's get_f1ap_ue_id_for_kpm() returns the real
cu_ue_f1ap_id (f1ap_cu_impl.h), but srsRAN allocates that id per-DU-F1-
interface, and this lab runs exactly one UE per DU -- so every UE is
"UE #0 on its DU" and gets f1ap id 0. gnb_cu_ue_f1ap is therefore NOT a
per-UE key: it only distinguishes (DU, id), and the DU identity that
would disambiguate is the E2 node, which xapp_kpm_moni does NOT print in
its callback. Net effect: a DU indication carries no usable key to
attribute it to a specific amf_ue_ngap_id.

This module still parses and joins DU blocks by gnb_cu_ue_f1ap and, when
an id maps to EXACTLY ONE amf_ue_ngap_id, merges the DU radio metrics
(DRB.UEThpUl/Dl, RRU.Prb*, delays -- confirmed real and per-UE-varying)
into that UE's sample. When an id maps to >1 UE (the f1ap=0 case above,
or a genuine cross-CU collision) the DU metrics are dropped, never
mis-attributed, and counted in `ambiguous_f1ap` so the condition is
observable rather than silent. So the join is correct and forward-ready,
but stays inert until a per-UE key exists. Two ways to unblock it, both
C-side: (a) modify xapp_kpm_moni to print the originating E2 node id per
indication (each DU -> one UE here, so node id resolves the UE); or
(b) make the DU meas provider populate ran_ue_id (globally unique) in its
KPM UEID -- it currently sets ran_ue_id_present = false
(e2sm_kpm_du_meas_provider_impl.cpp) -- then join on ran_ue_id here.
"""

import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_PORT = int(os.environ.get("KPM_API_PORT", "8767"))
RIC_ADDR = os.environ.get("RIC_ADDR", "10.10.0.4")
XAPP_BINARY = os.environ.get(
    "KPM_XAPP_BINARY", "/opt/flexric/build/examples/xApp/c/monitor/xapp_kpm_moni"
)
FLEXRIC_CONFIG = os.environ.get("FLEXRIC_CONFIG", "/usr/local/etc/flexric/flexric.conf")
FLEXRIC_LIB_PATH = os.environ.get("FLEXRIC_LIB_PATH", "/usr/local/lib/flexric/")
SAMPLE_TTL_S = float(os.environ.get("KPM_SAMPLE_TTL_S", "10"))
# f1ap->amf mappings age out on this same TTL -- a UE that detached and
# freed its f1ap id must stop shadowing a UE that later reuses that id.
F1AP_MAP_TTL_S = float(os.environ.get("KPM_F1AP_MAP_TTL_S", "30"))
# Optional: tee every raw xApp stdout line here for format inspection.
RAW_DUMP_PATH = os.environ.get("KPM_RAW_DUMP_PATH", "")

_INDICATION_RE = re.compile(r"^\s*\d+\s+KPM ind_msg latency =")
_CUCP_UEID_RE = re.compile(r"UE ID type = gNB, amf_ue_ngap_id = (\d+)")
_DU_UEID_RE = re.compile(r"UE ID type = gNB-DU, gnb_cu_ue_f1ap = (\d+)")
_CUUP_UEID_RE = re.compile(r"UE ID type = gNB-CU-UP")
_F1AP_ID_RE = re.compile(r"^gnb_cu_ue_f1ap = (\d+)$")
_METRIC_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9_.]*) = (-?\d+(?:\.\d+)?)\s*(?:\[([^]]*)\]|\(([^)]*)\))?"
)
# CU-CP-level and DU-level metrics we surface. The DU radio metrics
# (throughput, PRB, delay) are the point of joining DU blocks at all.
_KEEP_METRICS = {
    "RRC.ConnMean",
    "DRB.UEThpDl",
    "DRB.UEThpUl",
    "DRB.AirIfDelayUl",
    "DRB.RlcDelayUl",
    "DRB.RlcPacketDropRateDl",
    "DRB.RlcSduDelayDl",
    "DRB.RlcSduTransmittedVolumeDL",
    "DRB.RlcSduTransmittedVolumeUL",
    "RRU.PrbAvailDl",
    "RRU.PrbAvailUl",
    "RRU.PrbTotDl",
    "RRU.PrbTotUl",
    "RRU.PrbUsedDl",
    "RRU.PrbUsedUl",
}


class KpmState:
    def __init__(self):
        self.lock = threading.Lock()
        # amf_ue_ngap_id -> {"amf_ue_ngap_id", "gnb_cu_ue_f1ap", "metrics",
        #                    "updated_at"}
        self.samples = {}
        # gnb_cu_ue_f1ap -> {"amf": set(amf_ue_ngap_id), "updated_at"};
        # a set so an id claimed by >1 UE (cross-CU collision) is detected.
        self.f1ap_map = {}
        self.connected = False
        self.node_count = 0
        self.ambiguous_f1ap = 0
        self.last_error = ""
        # Current indication block being parsed.
        self._cur = None  # None | dict(kind=..., ...)

    # -- block lifecycle -----------------------------------------------

    def _start(self, kind, **fields):
        self.flush()
        self._cur = {"kind": kind, "metrics": {}, **fields}

    def _amf_for_f1ap(self, f1ap, now):
        """Return the single amf_ue_ngap_id an f1ap id maps to, or None if
        unknown / stale / ambiguous."""
        entry = self.f1ap_map.get(f1ap)
        if entry is None or now - entry["updated_at"] > F1AP_MAP_TTL_S:
            return None
        if len(entry["amf"]) != 1:
            return None
        return next(iter(entry["amf"]))

    def flush(self):
        cur = self._cur
        self._cur = None
        if not cur:
            return
        now = time.time()
        with self.lock:
            if cur["kind"] == "cucp":
                amf = cur["amf_ue_ngap_id"]
                # Record every f1ap id this UE advertised, for DU joins.
                for f1ap in cur.get("f1ap_ids", []):
                    entry = self.f1ap_map.setdefault(
                        f1ap, {"amf": set(), "updated_at": now})
                    entry["amf"].add(amf)
                    entry["updated_at"] = now
                sample = self.samples.get(amf)
                if sample is None:
                    sample = {"amf_ue_ngap_id": amf, "gnb_cu_ue_f1ap": None,
                              "metrics": {}}
                    self.samples[amf] = sample
                if cur.get("f1ap_ids"):
                    sample["gnb_cu_ue_f1ap"] = cur["f1ap_ids"][0]
                sample["metrics"].update(cur["metrics"])
                sample["updated_at"] = now
            elif cur["kind"] == "du":
                if not cur["metrics"]:
                    return
                amf = self._amf_for_f1ap(cur["f1ap"], now)
                if amf is None:
                    entry = self.f1ap_map.get(cur["f1ap"])
                    if entry is not None and len(entry["amf"]) > 1:
                        self.ambiguous_f1ap += 1
                    return
                sample = self.samples.get(amf)
                if sample is None:
                    return  # CU-CP block for this UE not seen yet; wait.
                sample["metrics"].update(cur["metrics"])
                sample["updated_at"] = now
            # cu-up blocks: parsed but not joined.

    # -- line consumer -------------------------------------------------

    def consume(self, line):
        if RAW_DUMP_PATH:
            try:
                with open(RAW_DUMP_PATH, "a") as fh:
                    fh.write(line if line.endswith("\n") else line + "\n")
            except OSError:
                pass
        line = line.strip()

        if line.startswith("Connected E2 nodes ="):
            with self.lock:
                self.node_count = int(line.rsplit("=", 1)[1])
                self.connected = True
            return
        if _INDICATION_RE.match(line):
            self.flush()
            return

        m = _CUCP_UEID_RE.search(line)
        if m:
            self._start("cucp", amf_ue_ngap_id=int(m.group(1)), f1ap_ids=[])
            return
        m = _DU_UEID_RE.search(line)
        if m:
            self._start("du", f1ap=int(m.group(1)))
            return
        if _CUUP_UEID_RE.search(line):
            self._start("cuup")
            return

        if self._cur is None:
            return

        # A bare "gnb_cu_ue_f1ap = <F>" line only appears inside a CU-CP
        # block (the DU/CU-UP ids are on their own "UE ID type" lines).
        m = _F1AP_ID_RE.match(line)
        if m and self._cur["kind"] == "cucp":
            self._cur["f1ap_ids"].append(int(m.group(1)))
            return

        m = _METRIC_RE.match(line)
        if m and m.group(1) in _KEEP_METRICS:
            value = float(m.group(2))
            if value.is_integer():
                value = int(value)
            self._cur["metrics"][m.group(1)] = value

    # -- readout -------------------------------------------------------

    def snapshot(self):
        now = time.time()
        with self.lock:
            stale = [k for k, v in self.samples.items()
                     if now - v["updated_at"] > SAMPLE_TTL_S]
            for k in stale:
                del self.samples[k]
            stale_map = [k for k, v in self.f1ap_map.items()
                         if now - v["updated_at"] > F1AP_MAP_TTL_S]
            for k in stale_map:
                del self.f1ap_map[k]
            return {
                "connected": self.connected,
                "node_count": self.node_count,
                "ambiguous_f1ap": self.ambiguous_f1ap,
                "samples": list(self.samples.values()),
                "last_error": self.last_error,
            }


state = KpmState()


def _xapp_loop():
    command = [
        "stdbuf", "-oL", "-eL", XAPP_BINARY,
        "-c", FLEXRIC_CONFIG, "-p", FLEXRIC_LIB_PATH, "-a", RIC_ADDR,
    ]
    while True:
        try:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            with state.lock:
                state.last_error = ""
            for line in process.stdout:
                state.consume(line)
            rc = process.wait()
            with state.lock:
                state.connected = False
                state.last_error = f"xapp_kpm_moni exited with status {rc}"
        except OSError as exc:
            with state.lock:
                state.connected = False
                state.last_error = str(exc)
        time.sleep(2)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path != "/kpm":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(state.snapshot()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    threading.Thread(target=_xapp_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
