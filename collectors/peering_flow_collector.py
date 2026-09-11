"""
collectors/peering_flow_collector.py — ingress flow telemetry for the BGP
Peering domain.

softflowd on r1's external interface exports NetFlow v9/IPFIX to nfcapd,
which writes rotated binary capture files to PEERING_NFCAPD_DIR (see
config/settings.py). This collector never speaks the wire protocol
itself -- it shells out to `nfdump` (same suite as nfcapd) to decode each
new capture file into per-flow CSV records, the same "read via the
vendor's own tool" pattern the rest of this project uses (e.g. BNGBlaster
telemetry) instead of reimplementing IPFIX/NetFlow decoding here.

See docs/peering-plan.md for the FlowSpec-dataplane-support spike --
this telemetry path does NOT depend on it and works independently of
whether mitigation/peering_backend.py's announcements actually get
installed by r1's FRR.
"""
import csv
import io
import logging
import os
import subprocess
from typing import Dict, List, Optional

import config.settings as settings

_PROTO_NAMES = {"TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP"}


def _proto_name(raw: str) -> str:
    raw = (raw or "").strip().upper()
    return _PROTO_NAMES.get(raw, raw or "IP")


class PeeringFlowCollector:
    """
    Polls PEERING_NFCAPD_DIR for capture files not yet processed, decodes
    each with `nfdump -o csv`, and returns new per-flow records since the
    last call.

    A capture file is only read once it is no longer the most recent one
    in the directory -- nfcapd keeps appending to the current file until
    its rotation interval elapses, so reading it early would return a
    partial flow set for that interval.
    """

    def __init__(
        self,
        capture_dir: Optional[str] = None,
        nfdump_bin: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.capture_dir = capture_dir or settings.PEERING_NFCAPD_DIR
        self.nfdump_bin = nfdump_bin or settings.PEERING_NFDUMP_BIN
        self.logger = logger or logging.getLogger(__name__)
        # Seed with whatever's already on disk -- "tail -f" semantics, not
        # "read everything ever captured". Without this, a fresh controller
        # start replays hours-old capture files from an unrelated earlier
        # test session as if they were a live attack: confirmed on the VM,
        # where a stray nfcapd file from an earlier validate_peering.py run
        # fired a real (bogus) BGP_FLOWSPEC_DISCARD mitigation attempt the
        # moment ryu-manager booted, before the topology (and thus flow/
        # exabgp) even existed to receive it.
        self._processed_files = set(self._existing_files())

    def _existing_files(self) -> List[str]:
        try:
            return [f for f in os.listdir(self.capture_dir) if f.startswith("nfcapd.")]
        except OSError:
            return []

    def poll(self) -> List[Dict]:
        """Return flow records from every unread, fully-rotated capture file."""
        if not self.capture_dir or not os.path.isdir(self.capture_dir):
            return []

        try:
            entries = sorted(os.listdir(self.capture_dir))
        except OSError as exc:
            self.logger.warning("Cannot list nfcapd capture dir %s: %s", self.capture_dir, exc)
            return []

        files = [f for f in entries if f.startswith("nfcapd.")]
        if not files:
            return []

        # The lexicographically-last file is nfcapd's current, still-open
        # capture (nfcapd.YYYYMMDDhhmm filenames sort chronologically) --
        # never read it.
        readable = files[:-1]
        new_files = [f for f in readable if f not in self._processed_files]

        records: List[Dict] = []
        for fname in new_files:
            records.extend(self._decode_file(os.path.join(self.capture_dir, fname)))
            self._processed_files.add(fname)

        # nfcapd itself deletes files past its retention window, so this
        # set only needs to outlive that window, not grow forever.
        if len(self._processed_files) > 10000:
            self._processed_files = set(new_files[-1000:])

        return records

    def _decode_file(self, path: str) -> List[Dict]:
        try:
            result = subprocess.run(
                [self.nfdump_bin, "-r", path, "-o", "csv"],
                capture_output=True, text=True, timeout=30, check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self.logger.warning("nfdump failed on %s: %s", path, exc)
            return []

        return self._parse_csv(result.stdout)

    @staticmethod
    def _parse_csv(output: str) -> List[Dict]:
        """
        nfdump's `-o csv` output includes its own header row -- csv.DictReader
        picks up field names from it directly rather than this module
        hardcoding a column order that varies across nfdump versions.
        Short field names used below (sa/da/dp/pr/td/ipkt/ibyt) match
        nfdump 1.7.x's csv output; verify against `nfdump -o csv -c 1`
        on the deployed version if this ever stops parsing.
        """
        records = []
        for row in csv.DictReader(io.StringIO(output)):
            try:
                src_ip = row["sa"]
                dst_ip = row["da"]
                if not src_ip or not dst_ip:
                    continue
                duration_s = max(float(row["td"]), 0.001)
                packets = int(row["ipkt"])
                byte_count = int(row["ibyt"])
                records.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": int(row.get("dp") or 0),
                    "protocol": _proto_name(row.get("pr", "")),
                    "pps": packets / duration_s,
                    "bps": byte_count / duration_s,
                })
            except (KeyError, ValueError, TypeError):
                # TypeError specifically: nfdump's CSV output appends a
                # trailing "Summary" section (a different, shorter
                # column set) after the per-flow rows. DictReader maps
                # its short rows onto our original flow header by
                # position, so columns past the summary's own width
                # (e.g. ipkt) land as None via restval -- int(None)
                # raises TypeError, not caught by the other two. Only
                # surfaced once a capture file had real flow data ahead
                # of that trailing block to reach this far.
                continue
        return records
