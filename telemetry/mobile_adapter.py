import csv
import json
import logging
import os
from typing import Dict, List, Optional

from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter
from oran_bridge.ue_ip_map import DEFAULT_PATH as DEFAULT_UE_IP_MAP_PATH, load_ue_ip_map

DEFAULT_KPM_CSV_PATH = "/tmp/ddos_xapp_events.csv"
DEFAULT_RC_COMMAND_QUEUE_PATH = "/tmp/oran_rc_commands.jsonl"

# simulation/parse_xapp_kpm_log.py writes these exact columns (see that
# file's record_to_csv_row) -- "rnti" there is actually the decoded IMSI,
# not a real RNTI (see oran_bridge/amf_ue_ngap_id.py).
#
# dst_ip: this is UPLINK telemetry, so the UE is the traffic's SOURCE,
# not its destination -- a UE generating attack-volume UL traffic is
# flooding some external target, not itself. RAN-level KPM has no
# flow-level visibility to know that target's real IP (it's an
# aggregate per-UE throughput/PRB measurement, not a 5-tuple), so a
# real E2/KPM-fed producer can only ever leave this blank ("*", the
# same "no single known destination" convention DetectionResult/
# MitigationAction already use for DDOS_DISTRIBUTED). A synthetic
# producer that already knows what it's simulating (e.g.
# simulation/ul_traffic_simulator.py) can supply a real one instead.
_CSV_COLUMNS = ["timestamp", "imsi", "gnb_id", "dst_ip", "ul_thr_mbps", "prb_usage_pct", "sinr_db", "state"]

# dst_port/protocol: same RAN-has-no-L4-visibility limitation as dst_ip
# above -- a real KPM-fed producer (simulation/parse_xapp_kpm_log.py)
# never has these and keeps writing the _CSV_COLUMNS row above unchanged.
# Only a synthetic producer that already knows what attack it's
# simulating (ul_traffic_simulator.py) can supply them, as two optional
# trailing columns -- kept separate from _CSV_COLUMNS, rather than
# replacing it, so the real pipeline's rows don't suddenly fail the
# column-count check in collect() below.
_CSV_COLUMNS_EXT = _CSV_COLUMNS + ["dst_port", "protocol"]

# Falls back to this when a row uses the legacy (no dst_port/protocol)
# format -- matches DetectionResult/MitigationAction's existing "unknown
# protocol, no port" convention for telemetry with no L4 visibility.
_DEFAULT_PROTOCOL = "UDP"

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
        logger: Optional[logging.Logger] = None,
    ):
        self.kpm_csv_path = kpm_csv_path
        self.rc_command_queue_path = rc_command_queue_path
        # Passed down from the Ryu app (its own self.logger) so every log
        # line across domains shares the same name/format -- defaults to
        # a plain logging.Logger so this stays usable standalone (tests,
        # no Ryu runtime).
        self._logger = logger or logging.getLogger(__name__)
        # An explicitly-passed map (tests, callers with their own source
        # of truth) is used as-is, never reloaded. Otherwise this
        # adapter watches config/ue_ip_map.csv's mtime and reloads it on
        # change -- a long-running ryu-manager process previously cached
        # whatever was on disk at __init__ time forever, silently
        # ignoring a fresher mapping written by a telemetry source
        # started later (confirmed: a live run kept resolving IMSIs
        # against a stale map from hours earlier, dropping every event
        # for an IMSI the old map didn't even have).
        self._ue_ip_map_path = None if ue_ip_map is not None else DEFAULT_UE_IP_MAP_PATH
        self._ue_ip_map_mtime: Optional[float] = None
        self._ue_ip_map = ue_ip_map if ue_ip_map is not None else {}
        if self._ue_ip_map_path is not None:
            self._refresh_ue_ip_map()
        # Byte offset up to which kpm_csv_path has already been read --
        # collect() tails new rows only, same pattern as
        # parse_xapp_kpm_log.py's own follow().
        self._csv_read_offset = 0

        # Tracks the last-logged connection state so collect() logs a
        # "telemetry source connected/lost" event only on the transition
        # -- not once per cycle -- the same way ryu_controller_2.py logs
        # "Switch connected" once per actual connection, not once per
        # stats-poll cycle.
        self._was_connected = False

    def _refresh_ue_ip_map(self) -> None:
        if self._ue_ip_map_path is None:
            return
        try:
            mtime = os.path.getmtime(self._ue_ip_map_path)
        except OSError:
            return
        if mtime != self._ue_ip_map_mtime:
            self._ue_ip_map = load_ue_ip_map(self._ue_ip_map_path)
            self._ue_ip_map_mtime = mtime
            self._logger.info(
                "Reloaded UE IP map from %s (%d entries)",
                self._ue_ip_map_path, len(self._ue_ip_map),
            )

    def is_connected(self) -> bool:
        return os.path.exists(self.kpm_csv_path)

    def collect(self) -> List[TelemetryEvent]:
        self._refresh_ue_ip_map()

        connected = os.path.exists(self.kpm_csv_path)
        if connected and not self._was_connected:
            self._logger.info("Mobile domain telemetry source connected: %s", self.kpm_csv_path)
        elif not connected and self._was_connected:
            self._logger.warning("Mobile domain telemetry source lost: %s", self.kpm_csv_path)
        self._was_connected = connected

        if not connected:
            return []

        # One event per IMSI per collect() call, not per CSV row: each
        # row is a RATE sample (ul_thr_mbps), not a byte count to sum,
        # and the source can write faster than this gets polled (e.g.
        # ul_traffic_simulator.py's --tick vs. config/settings.py's
        # COLLECT_INTERVAL). MultidomainCorrelator sums every event in
        # a dst_ip bucket assuming they're concurrent flows -- handing
        # it N accumulated rate samples for one UE would inflate that
        # UE's apparent pps by ~N regardless of real traffic, including
        # for perfectly benign UEs. Keeping only the most recent sample
        # per IMSI is the correct fix at the source, not a downstream
        # threshold tweak.
        # Detect truncation/rotation -- e.g. ul_traffic_simulator.py
        # truncates this same path on every (re)start. A long-running
        # ryu-manager process's _csv_read_offset would otherwise still
        # point past the freshly-truncated file's new (much smaller) size;
        # seeking past EOF doesn't error, it just silently reads nothing
        # until the file grows back past that stale offset -- meaning a
        # fresh attack right after a simulator restart could go completely
        # undetected for as long as that takes. Falling back to 0 picks
        # the new file's contents back up from the start instead.
        try:
            if os.path.getsize(self.kpm_csv_path) < self._csv_read_offset:
                self._logger.info(
                    "Mobile domain telemetry source %s was truncated -- resuming from offset 0",
                    self.kpm_csv_path,
                )
                self._csv_read_offset = 0
        except OSError:
            pass

        latest_by_imsi: dict = {}

        with open(self.kpm_csv_path, "r", newline="") as f:
            f.seek(self._csv_read_offset)
            reader = csv.reader(f)
            for row in reader:
                if len(row) == len(_CSV_COLUMNS_EXT):
                    fields = dict(zip(_CSV_COLUMNS_EXT, row))
                elif len(row) == len(_CSV_COLUMNS):
                    fields = dict(zip(_CSV_COLUMNS, row))
                else:
                    continue
                imsi_raw = fields.get("imsi")
                if imsi_raw is not None:
                    latest_by_imsi[imsi_raw] = fields
            self._csv_read_offset = f.tell()

        events: List[TelemetryEvent] = []
        for fields in latest_by_imsi.values():
            event = self._row_to_event(fields)
            if event is not None:
                events.append(event)
        return events

    def _row_to_event(self, fields: dict) -> Optional[TelemetryEvent]:
        try:
            imsi = int(float(fields["imsi"]))
            gnb_id = fields["gnb_id"]
            ul_thr_mbps = float(fields["ul_thr_mbps"])
        except (KeyError, ValueError):
            return None

        src_ip = self._ue_ip_map.get(imsi)
        if src_ip is None:
            # No static mapping for this IMSI yet -- config/ue_ip_map.csv
            # needs a row for it (see oran_bridge/ue_ip_map.py). Silently
            # dropping rather than raising: a partially-populated map
            # during incremental testbed setup shouldn't take down the
            # whole adapter.
            return None

        # "*" (no single known target) unless the producer supplied a
        # real one -- see _CSV_COLUMNS' dst_ip comment above.
        dst_ip = fields.get("dst_ip") or "*"

        # dst_port/protocol: only present in the extended (synthetic)
        # format -- see _CSV_COLUMNS_EXT above. Falls back to the same
        # "no L4 visibility" convention the real KPM pipeline has always
        # used otherwise.
        try:
            dst_port = int(float(fields["dst_port"])) if "dst_port" in fields else 0
        except (KeyError, ValueError):
            dst_port = 0
        protocol = fields.get("protocol") or _DEFAULT_PROTOCOL

        bps = (ul_thr_mbps * 1e6) / 8.0
        pps = bps / ASSUMED_AVG_PACKET_SIZE_BYTES

        return TelemetryEvent(
            domain=self.domain_name,
            device_id=gnb_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            pps=pps,
            bps=bps,
        )

    def apply_mitigation(self, action: MitigationAction) -> bool:
        self._refresh_ue_ip_map()
        # The attacking UE is action.src_ip now (UL traffic's real
        # source), not action.dst_ip (the external target it was
        # flooding) -- see _row_to_event's src_ip/dst_ip comment.
        imsi = self._imsi_for_ip(action.src_ip)
        if imsi is None:
            self._logger.warning(
                "Cannot resolve src_ip %s back to an IMSI -- "
                "ue_ip_map.csv may be out of date for this run",
                action.src_ip,
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

        # No print here -- OrchestrationController already reports this
        # action through the same MITIGATION dashboard/logger line every
        # other domain's actions go through (ryu_controller_2.py's
        # _run_pipeline), so a second, differently-formatted message here
        # would just be noise. Real E2SM-RC delivery to the Near-RT RIC
        # is not yet implemented -- see this adapter's docstring.
        return True

    def _imsi_for_ip(self, ip: str) -> Optional[int]:
        for imsi, mapped_ip in self._ue_ip_map.items():
            if mapped_ip == ip:
                return imsi
        return None
