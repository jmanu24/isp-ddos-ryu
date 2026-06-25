import csv
import json
import os
from typing import Dict, List, Optional

from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter
from oran_bridge.ue_ip_map import load_ue_ip_map

DEFAULT_KPM_CSV_PATH = "/tmp/ddos_xapp_events.csv"
DEFAULT_RC_COMMAND_QUEUE_PATH = "/tmp/oran_rc_commands.jsonl"

# simulation/parse_xapp_kpm_log.py writes these exact columns (see that
# file's record_to_csv_row) -- "rnti" there is actually the decoded IMSI,
# not a real RNTI (see oran_bridge/amf_ue_ngap_id.py).
_CSV_COLUMNS = ["timestamp", "imsi", "gnb_id", "ul_thr_mbps", "prb_usage_pct", "sinr_db", "state"]

# Average packet size assumed when converting a KPM throughput reading
# (bytes/sec) into an approximate packets/sec figure -- DDoSDetectionEngine
# thresholds purely on pps (config/settings.py), never bps, and KPM has no
# native packet-count field to derive a real one from. Matches this
# proposal's own test traffic (test_oran_e2_logging.cc's OnOff
# PacketSize=512) -- an approximation, not a measured value.
ASSUMED_AVG_PACKET_SIZE_BYTES = 512


class MobileNetworkAdapter(DomainAdapter):
    """
    Telemetry + mitigation adapter for the Mobile Network Domain
    (O-RAN Near-RT RIC, real E2/KPM pipeline -- see simulation/
    run_oran_e2_test.sh and parse_xapp_kpm_log.py for how the real
    pipeline up to this adapter's input CSV is wired and validated).

    Telemetry (collect()): tails the CSV that
    simulation/parse_xapp_kpm_log.py produces from xapp_kpm_moni's real
    output (one row per UE per KPM indication: imsi, ul_thr_mbps,
    prb_usage_pct, ...). Each row becomes a TelemetryEvent with
    domain="mobile" and dst_ip resolved from the static IMSI->IP table
    (oran_bridge/ue_ip_map.py) -- the RAN side only knows a UE by its
    IMSI; it has no visibility into which external IP(s) are actually
    flooding it, so src_ip is left as "*" (the same convention
    DetectionResult/MitigationAction already use for DDOS_DISTRIBUTED,
    where no single attacker IP is known either).

    Mitigation (apply_mitigation()): the actual E2SM-RC CONTROL message
    that would tell the Near-RT RIC to throttle/deny RAN resources to a
    UE has NOT been investigated or implemented yet in this proposal --
    only the real KPM/E2 telemetry path has been validated end-to-end so
    far. Until that follow-up investigation happens, this writes the
    decided action to a JSONL command queue (one line per command) that
    a future RC xApp bridge is meant to consume and translate into a
    real E2AP RIC CONTROL REQUEST. This is a deliberate, explicit
    integration seam, not a placeholder pretending to be a real actuator.
    """

    domain_name = "mobile"

    def __init__(
        self,
        kpm_csv_path: str = DEFAULT_KPM_CSV_PATH,
        rc_command_queue_path: str = DEFAULT_RC_COMMAND_QUEUE_PATH,
        ue_ip_map: Optional[Dict[int, str]] = None,
    ):
        self.kpm_csv_path = kpm_csv_path
        self.rc_command_queue_path = rc_command_queue_path
        self._ue_ip_map = ue_ip_map if ue_ip_map is not None else load_ue_ip_map()
        # Byte offset up to which kpm_csv_path has already been read --
        # collect() tails new rows only, same pattern as
        # parse_xapp_kpm_log.py's own follow().
        self._csv_read_offset = 0

    def is_connected(self) -> bool:
        return os.path.exists(self.kpm_csv_path)

    def collect(self) -> List[TelemetryEvent]:
        if not os.path.exists(self.kpm_csv_path):
            return []

        events: List[TelemetryEvent] = []

        with open(self.kpm_csv_path, "r", newline="") as f:
            f.seek(self._csv_read_offset)
            reader = csv.reader(f)
            for row in reader:
                if len(row) != len(_CSV_COLUMNS):
                    continue
                fields = dict(zip(_CSV_COLUMNS, row))
                event = self._row_to_event(fields)
                if event is not None:
                    events.append(event)
            self._csv_read_offset = f.tell()

        return events

    def _row_to_event(self, fields: dict) -> Optional[TelemetryEvent]:
        try:
            imsi = int(float(fields["imsi"]))
            gnb_id = fields["gnb_id"]
            ul_thr_mbps = float(fields["ul_thr_mbps"])
        except (KeyError, ValueError):
            return None

        dst_ip = self._ue_ip_map.get(imsi)
        if dst_ip is None:
            # No static mapping for this IMSI yet -- config/ue_ip_map.csv
            # needs a row for it (see oran_bridge/ue_ip_map.py). Silently
            # dropping rather than raising: a partially-populated map
            # during incremental testbed setup shouldn't take down the
            # whole adapter.
            return None

        bps = (ul_thr_mbps * 1e6) / 8.0
        pps = bps / ASSUMED_AVG_PACKET_SIZE_BYTES

        return TelemetryEvent(
            domain=self.domain_name,
            device_id=gnb_id,
            src_ip="*",
            dst_ip=dst_ip,
            dst_port=0,
            protocol="UDP",
            pps=pps,
            bps=bps,
        )

    def apply_mitigation(self, action: MitigationAction) -> bool:
        imsi = self._imsi_for_ip(action.dst_ip)
        if imsi is None:
            print(
                f"[MOBILE] cannot resolve dst_ip {action.dst_ip} back to an "
                f"IMSI -- ue_ip_map.csv may be out of date for this run"
            )
            return False

        command = {
            "imsi": imsi,
            "action": action.action,
            "duration": action.duration,
            "attack_type": action.attack_type,
        }

        with open(self.rc_command_queue_path, "a") as f:
            f.write(json.dumps(command) + "\n")

        print(
            f"[MOBILE] queued RC command for IMSI {imsi}: {action.action} "
            f"({action.attack_type}) -- real E2SM-RC delivery to the "
            f"Near-RT RIC not yet implemented, see this adapter's docstring"
        )
        return True

    def _imsi_for_ip(self, ip: str) -> Optional[int]:
        for imsi, mapped_ip in self._ue_ip_map.items():
            if mapped_ip == ip:
                return imsi
        return None
