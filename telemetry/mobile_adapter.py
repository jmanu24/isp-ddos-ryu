import json
import logging
import urllib.error
import urllib.request
from typing import Dict, List, Optional

import config.settings as settings
from core.log_format import log_line
from core.models import TelemetryEvent, MitigationAction
from telemetry.base import DomainAdapter

DEFAULT_RC_COMMAND_QUEUE_PATH = "/tmp/oran_rc_commands.jsonl"


class MobileNetworkAdapter(DomainAdapter):
    """
    Telemetry + mitigation adapter for the Mobile Network Domain (real
    srsRAN Project + Open5GS VM lab -- see docs/ran-testing.md).

    REPLACES the earlier ns-3/mmwave-LENA-oran simulated-scenario design
    (static config/ue_ip_map.csv + a KPM-CSV tail, both built against
    that fork's fake IMSI/IP assignment -- see git history for
    oran_bridge/amf_ue_ngap_id.py and oran_bridge/ue_ip_map.py, kept
    around only as historical reference for a scenario this lab no
    longer runs). That design produced synthetic numbers with no real
    backing at all; this one is built entirely on real, live testbed
    state.

    Telemetry (collect()): a single HTTP GET per cycle to
    oran_bridge/ue_telemetry_api.py -- a small persistent service that
    runs on core5g itself (NOT on this process), since that's the one
    place both halves of what this domain needs actually live:

      - identity (amf_ue_ngap_id -> imsi -> ip), from Open5GS's own
        AMF/SMF docker logs -- there is no live query API in Open5GS
        for this (WebUI's own REST API is subscriber CRUD against
        MongoDB only, confirmed by reading its server/routes/db.js --
        no live session state ever reaches Mongo).
      - real per-(UE ip, destination) volumetric flow data, from the
        kernel's own conntrack table on core5g -- every UE's uplink
        traffic is decapsulated onto core5g's single ogstun interface,
        so this is a real, complete, OpenFlow/enterprise-domain-
        independent view of exactly what each UE is sending where.

    This adapter itself never tails a log or opens an SSH connection --
    it only ever does a plain, cheap HTTP GET, the same shape
    telemetry/broadband_adapter.py's own _read_active_scenario() already
    uses for suscriptor's /active_scenario endpoint. ue_telemetry_api.py
    already joins the two halves above server-side, so each row it
    returns maps directly onto one TelemetryEvent.

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
        telemetry_api_url: str = None,
        rc_command_queue_path: str = DEFAULT_RC_COMMAND_QUEUE_PATH,
        logger: Optional[logging.Logger] = None,
    ):
        self.telemetry_api_url = telemetry_api_url or settings.MOBILE_DIST_TELEMETRY_API_URL
        self.rc_command_queue_path = rc_command_queue_path
        # Passed down from the Ryu app (its own self.logger) so every log
        # line across domains shares the same name/format -- defaults to
        # a plain logging.Logger so this stays usable standalone (tests,
        # no Ryu runtime).
        self._logger = logger or logging.getLogger(__name__)

        # Tracks the last-logged connection state so collect() logs a
        # "telemetry source connected/lost" event only on the transition
        # -- not once per cycle -- the same way ryu_controller_2.py logs
        # "Switch connected" once per actual connection, not once per
        # stats-poll cycle.
        self._was_connected = False

        # ip -> imsi, refreshed from every collect() response -- the
        # only place apply_mitigation() can resolve a src_ip back to a
        # subscriber, since MitigationAction only ever carries the IP
        # DDoSDetectionEngine classified, never the imsi itself.
        self._imsi_by_ip: Dict[str, str] = {}

    def is_connected(self) -> bool:
        try:
            with urllib.request.urlopen(
                self.telemetry_api_url, timeout=settings.MOBILE_DIST_TELEMETRY_API_TIMEOUT_S
            ):
                return True
        except (urllib.error.URLError, OSError, TimeoutError):
            return False

    def collect(self) -> List[TelemetryEvent]:
        # Plain HTTP GET, not SSH -- eventlet's own monkey-patching
        # (applied by ryu-manager's startup, before this module ever
        # imports) already makes plain socket/urllib I/O cooperative, so
        # this doesn't need broadband_adapter.py's tpool.execute()
        # workaround (that exists specifically for subprocess.run()'s
        # fork/exec/waitpid, which isn't covered by that patching -- see
        # that module's own _ssh() docstring). Same reasoning as
        # broadband_adapter.py's own _read_active_scenario().
        try:
            with urllib.request.urlopen(
                self.telemetry_api_url, timeout=settings.MOBILE_DIST_TELEMETRY_API_TIMEOUT_S
            ) as resp:
                body = json.loads(resp.read())
            connected = True
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError):
            connected = False
            body = None

        if connected and not self._was_connected:
            self._logger.info(log_line(
                "mobile", "TELEMETRY", "SOURCE_CONNECTED", f"url={self.telemetry_api_url}"
            ))
        elif not connected and self._was_connected:
            self._logger.warning(log_line(
                "mobile", "TELEMETRY", "SOURCE_LOST", f"url={self.telemetry_api_url}"
            ))
        self._was_connected = connected

        if not connected:
            return []

        events: List[TelemetryEvent] = []
        for row in body.get("flows", []):
            event = self._row_to_event(row)
            if event is not None:
                events.append(event)
        return events

    def _row_to_event(self, row: dict) -> Optional[TelemetryEvent]:
        src_ip = row.get("src_ip")
        dst_ip = row.get("dst_ip")
        if not src_ip or not dst_ip:
            return None

        imsi = row.get("imsi") or ""
        amf_ue_ngap_id = row.get("amf_ue_ngap_id") or 0
        if imsi:
            # Refreshed on every sighting -- apply_mitigation() reads
            # this later, potentially several cycles after the UE that
            # triggered a detection last appeared here.
            self._imsi_by_ip[src_ip] = imsi

        return TelemetryEvent(
            domain=self.domain_name,
            # No real gNB/cell id is joined in yet (ue_telemetry_api.py
            # doesn't currently pull it from KPM) -- imsi/amf_ue_ngap_id
            # already identify the UE precisely enough for detection and
            # mitigation, so device_id is left blank rather than faked.
            device_id="",
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=row.get("dst_port", 0),
            protocol=row.get("protocol", "IP"),
            pps=row.get("pps", 0.0),
            bps=row.get("bps", 0.0),
            imsi=imsi,
            amf_ue_ngap_id=amf_ue_ngap_id,
        )

    def apply_mitigation(self, action: MitigationAction) -> bool:
        # The attacking UE is action.src_ip (the real source this domain
        # reported it under in collect() above).
        imsi = self._imsi_by_ip.get(action.src_ip)
        if imsi is None:
            self._logger.warning(log_line(
                "mobile", "MITIGATION", "IMSI_UNRESOLVED",
                f"src_ip={action.src_ip} (no recent telemetry row resolved this UE's imsi)",
            ))
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
