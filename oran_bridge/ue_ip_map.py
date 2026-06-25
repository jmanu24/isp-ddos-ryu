"""
ue_ip_map.py — O-RAN multidomain DDoS proposal.

Loads the static IMSI -> UE IP testbed table that MobileNetworkAdapter
needs to turn a KPM measurement (identified by IMSI, see
oran_bridge/amf_ue_ngap_id.py) into a TelemetryEvent's dst_ip -- the field
MultidomainCorrelator groups on to cross-reference this domain's telemetry
with OpenFlow's for the same victim.

Why static and not auto-discovered: the ns-3 scenario assigns each UE's IP
deterministically at startup (MmWavePointToPointEpcHelper::
AssignUeIpv4Address, in the same fixed order UEs were created), so for a
given scenario run the mapping is fixed and known in advance -- there's no
RAN-side signaling in this fork that reports a UE's IP back over E2 (KPM
carries IMSI/throughput/PRB stats, not IP). A future xApp could query this
from the core network's session data instead; this testbed doesn't have
that available, hence the static table.

Populate config/ue_ip_map.csv by reading the IPs the ns-3 scenario itself
assigned -- e.g. add `std::cout << imsi << "," << ueIpIface.GetAddress(i)
<< std::endl;` right after AssignUeIpv4Address in the scenario, once per
UE, and copy that output in.
"""

import csv
from pathlib import Path
from typing import Dict

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "ue_ip_map.csv"


def load_ue_ip_map(path: Path = DEFAULT_PATH) -> Dict[int, str]:
    """
    Returns {imsi: ip}. Missing file is not an error -- MobileNetworkAdapter
    just won't be able to resolve any UE's events to a dst_ip until one is
    provided, same as any other not-yet-wired-up domain.
    """
    if not path.exists():
        return {}

    mapping: Dict[int, str] = {}
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            mapping[int(row["imsi"])] = row["ip"]
    return mapping
