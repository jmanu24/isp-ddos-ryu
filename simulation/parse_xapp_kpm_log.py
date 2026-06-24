"""
parse_xapp_kpm_log.py — O-RAN multidomain DDoS proposal.

Converts FlexRIC's xapp_kpm_moni's stdout (captured to a log file) into
the headerless CSV format oran_bridge/kpm_consumer.py polls
(timestamp,rnti,gnb_id,ul_thr_mbps,prb_usage_pct,sinr_db,state) — the
same role oran_bridge/kpm_consumer.py's docstring describes "a real
xApp" as eventually filling, now actually wired to one.

Why a log-scraper instead of a custom C xApp: xapp_kpm_moni (examples/
xApp/c/monitor/xapp_kpm_moni.c in FlexRIC) already does everything we
need — subscribes with RIC Report Style 4 (the only style ns-3's
KpmFunctionDescription advertises; confirmed there's no Style 5 to ask
for instead) and prints every received indication in a fixed text
format (confirmed against a real run in this session, both against
FlexRIC's own emu_agent_gnb and against our own ns-3 scenario). Writing
a parser against that proven-real text format is far lower-risk than
reimplementing the subscription/indication-parsing logic in a new C
xApp without access to FlexRIC's internal struct layouts.

Confirmed real log format (one indication block, repeated):

          1 KPM ind_msg latency = 2326 [μs]
    UE ID type = gNB, amf_ue_ngap_id = 112358132134
    DRB.PdcpSduVolumeDL = 13 [kb]
    DRB.PdcpSduVolumeUL = 951 [kb]
    DRB.RlcSduDelayDl = 5.50 [μs]
    DRB.UEThpDl = 5.47 [kbps]
    DRB.UEThpUl = 5.84 [kbps]
    RRU.PrbTotDl = 261 [PRBs]
    RRU.PrbTotUl = 791 [PRBs]
    UE ID type = gNB, amf_ue_ngap_id = 112358132134
    ... (next UE in the same indication) ...

Caveats carried over from the rest of this proposal's investigation:
  - ns-3's DU-side reporting only implements DOWNLINK PRB usage
    (RRU.PrbUsedDl/PrbTotDl) — RRU.PrbTotUl may always read 0 against
    real ns-3 traffic, even though FlexRIC's own emulator (synthetic
    data, not real ns-3 stats) happened to show non-zero UL PRB counts
    in this session's earlier smoke test. Verify against a real run
    before trusting RRU.PrbTotUl here.
  - amf_ue_ngap_id is used as the "rnti" field below for lack of a
    cleaner identifier in this text dump — it is NOT actually the RNTI,
    just a stable per-UE id repeated across this UE's indications.
  - PRB counts are converted to a percentage using --max-prb (default
    273, a common NR 100MHz numerology max) since this log format
    doesn't carry the available-PRB denominator the way
    config/oran_bridge.yaml-style DU CSVs do — treat as approximate
    until calibrated against a real run.
"""

import argparse
import csv
import re
import threading
import time
from typing import Optional, TextIO

IND_HEADER_RE = re.compile(r"^\s*\d+\s+KPM ind_msg latency = \d+ \[\D+\]\s*$")
UE_ID_RE = re.compile(r"^UE ID type = \w+, amf_ue_ngap_id = (\d+)\s*$")
MEASUREMENT_RE = re.compile(r"^([\w.\-]+) = ([\d.]+) \[\D+\]\s*$")


class XappKpmLogParser:
    """
    Stateful line-by-line parser — feed it lines as they're tailed from
    the log file; it emits one dict per UE block as soon as that
    block's UE ID line is followed by measurements and either another
    UE ID line or an indication-header line closes it out.
    """

    def __init__(self):
        self._current_rnti: Optional[str] = None
        self._current_measurements: dict = {}

    def feed_line(self, line: str) -> Optional[dict]:
        line = line.rstrip("\n")

        ue_match = UE_ID_RE.match(line)
        if ue_match:
            finished = self._flush()
            self._current_rnti = ue_match.group(1)
            self._current_measurements = {}
            return finished

        meas_match = MEASUREMENT_RE.match(line)
        if meas_match and self._current_rnti is not None:
            self._current_measurements[meas_match.group(1)] = float(meas_match.group(2))
            return None

        if IND_HEADER_RE.match(line):
            return self._flush()

        return None

    def flush_pending(self) -> Optional[dict]:
        """
        Call on stream end (EOF/interrupt) -- the last UE block in a
        finite log never gets flushed by feed_line() on its own, since
        nothing ever arrives afterward to trigger it (a live tail never
        hits this case: the next indication's header line always
        flushes the previous block first).
        """
        return self._flush()

    def _flush(self) -> Optional[dict]:
        if self._current_rnti is None or not self._current_measurements:
            self._current_rnti = None
            self._current_measurements = {}
            return None

        record = {"rnti": self._current_rnti, **self._current_measurements}
        self._current_rnti = None
        self._current_measurements = {}
        return record


def record_to_csv_row(record: dict, max_prb: int) -> str:
    """
    Maps a parsed UE record onto oran_bridge/kpm_consumer.py's
    DomainEvent CSV columns: timestamp,rnti,gnb_id,ul_thr_mbps,
    prb_usage_pct,sinr_db,state.
    """
    ul_thr_kbps = record.get("DRB.UEThpUl", 0.0)
    ul_thr_mbps = ul_thr_kbps / 1000.0

    prb_ul = record.get("RRU.PrbTotUl", 0.0)
    prb_usage_pct = min(100.0, (prb_ul / max_prb) * 100.0) if max_prb > 0 else 0.0

    sinr_db = record.get("DRB.RlcSduDelayDl", 0.0)  # no real SINR field in this log; placeholder
    # Real observed DRB.UEThpUl values run ~5-10 kbps (0.005-0.01 Mbps)
    # even for "active" UEs in this log format -- a 0.01 Mbps cutoff
    # would call everything IDLE.
    state = "ACTIVE" if ul_thr_mbps > 0 else "IDLE"

    return (
        f"{time.time():.6f},{record['rnti']},1,"
        f"{ul_thr_mbps:.6f},{prb_usage_pct:.3f},{sinr_db:.3f},{state}\n"
    )


def follow(path: str, stop_flag: threading.Event):
    """Tail -f generator — yields new lines as they're appended to path."""
    with open(path, "r") as f:
        f.seek(0, 2)  # start at end of file, like tail -f
        while not stop_flag.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-path", required=True, help="xapp_kpm_moni stdout, captured to a file")
    parser.add_argument("--out-csv", required=True, help="output path -- point KPMConsumer's csv_path here")
    parser.add_argument("--max-prb", type=int, default=273)
    args = parser.parse_args()

    kpm_parser = XappKpmLogParser()
    stop_flag = threading.Event()

    print(f"[parse_xapp_kpm_log] tailing {args.log_path} -> {args.out_csv}")
    try:
        out_f: TextIO = open(args.out_csv, "a")
        for line in follow(args.log_path, stop_flag):
            record = kpm_parser.feed_line(line)
            if record is not None:
                row = record_to_csv_row(record, args.max_prb)
                out_f.write(row)
                out_f.flush()
                print(f"[parse_xapp_kpm_log] {row.strip()}")
    except KeyboardInterrupt:
        print("\n[parse_xapp_kpm_log] interrupted")
    finally:
        stop_flag.set()
        final = kpm_parser.flush_pending()
        if final is not None:
            row = record_to_csv_row(final, args.max_prb)
            out_f.write(row)
            out_f.flush()
            print(f"[parse_xapp_kpm_log] {row.strip()}")


if __name__ == "__main__":
    main()
