#!/usr/bin/env python3
"""RIC-local E2SM-KPM exporter.

Runs FlexRIC's xapp_kpm_moni as a supervised child, retains only KPM
records that carry a real AMF-UE-NGAP-ID, and exposes the latest sample
per UE through GET /kpm. DU-only records are deliberately not joined:
their F1AP IDs are local to each DU and xapp_kpm_moni does not expose the
originating E2 node in its callback, so attributing them would be unsafe.
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

_INDICATION_RE = re.compile(r"^\s*\d+\s+KPM ind_msg latency =")
_AMF_ID_RE = re.compile(r"UE ID type = gNB, amf_ue_ngap_id = (\d+)")
_F1AP_ID_RE = re.compile(r"^gnb_cu_ue_f1ap = (\d+)$")
_METRIC_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9_.]*) = (-?\d+(?:\.\d+)?)\s*(?:\[([^]]*)\]|\(([^)]*)\))?"
)
_KEEP_METRICS = {
    "RRC.ConnMean",
    "DRB.UEThpDl",
    "DRB.UEThpUl",
    "DRB.AirIfDelayUl",
    "DRB.RlcDelayUl",
    "DRB.RlcPacketDropRateDl",
    "DRB.RlcSduDelayDl",
    "RRU.PrbTotDl",
    "RRU.PrbTotUl",
    "RRU.PrbUsedDl",
    "RRU.PrbUsedUl",
}


class KpmState:
    def __init__(self):
        self.lock = threading.Lock()
        self.samples = {}
        self.connected = False
        self.node_count = 0
        self.last_error = ""
        self._current = None

    def flush(self):
        if self._current and self._current["metrics"]:
            self._current["updated_at"] = time.time()
            with self.lock:
                self.samples[self._current["amf_ue_ngap_id"]] = self._current
        self._current = None

    def consume(self, line):
        line = line.strip()
        if line.startswith("Connected E2 nodes ="):
            with self.lock:
                self.node_count = int(line.rsplit("=", 1)[1])
                self.connected = True
            return
        if _INDICATION_RE.match(line):
            self.flush()
            return
        match = _AMF_ID_RE.search(line)
        if match:
            self.flush()
            self._current = {
                "amf_ue_ngap_id": int(match.group(1)),
                "gnb_cu_ue_f1ap": None,
                "metrics": {},
            }
            return
        if self._current is None:
            return
        match = _F1AP_ID_RE.match(line)
        if match:
            self._current["gnb_cu_ue_f1ap"] = int(match.group(1))
            return
        match = _METRIC_RE.match(line)
        if match and match.group(1) in _KEEP_METRICS:
            value = float(match.group(2))
            if value.is_integer():
                value = int(value)
            self._current["metrics"][match.group(1)] = value

    def snapshot(self):
        now = time.time()
        with self.lock:
            stale = [key for key, value in self.samples.items()
                     if now - value["updated_at"] > SAMPLE_TTL_S]
            for key in stale:
                del self.samples[key]
            return {
                "connected": self.connected,
                "node_count": self.node_count,
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
