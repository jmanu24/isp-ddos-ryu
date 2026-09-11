"""Join measured flows to unambiguous, time-valid mobile session contexts."""
import ipaddress
import math
from dataclasses import asdict
from core.models import TelemetryEvent


class MobileContext:
    def __init__(self, bindings=(), kpms=(), max_kpm_age=20):
        self.bindings = list(bindings)
        self.kpms = list(kpms)
        self.max_kpm_age = max_kpm_age

    def enrich(self, flow):
        ipaddress.ip_address(flow.src_ip)
        ipaddress.ip_address(flow.dst_ip)
        if not all(math.isfinite(x) for x in (flow.start, flow.end, flow.bytes_count, flow.packets_count)):
            raise ValueError("Non-finite flow measurement")
        if flow.end <= flow.start or min(flow.bytes_count, flow.packets_count) < 0:
            raise ValueError("Expected nonnegative interval counters, not cumulative counters")
        if not all(0 <= x <= 65535 for x in (flow.src_port, flow.dst_port)):
            raise ValueError("Invalid port")
        matches = [b for b in self.bindings if b.network_id == flow.network_id
                   and b.ue_ip in (flow.src_ip, flow.dst_ip)
                   and b.valid_from <= flow.start
                   and (b.valid_until is None or flow.end <= b.valid_until)]
        # No guessing across IP reuse, overlapping sessions or UE-to-UE traffic.
        binding = matches[0] if len(matches) == 1 else None
        context = []
        if binding:
            for k in self.kpms:
                if (k.source != binding.ran_source or k.node_id != binding.node_id
                        or not k.reliable or k.status != "VALID" or k.value is None
                        or not math.isfinite(k.value)
                        or not 0 <= flow.end - k.timestamp <= self.max_kpm_age):
                    continue
                if k.scope == "ue" and not (binding.ue_id is not None and
                        (k.ue_id_type, k.ue_id) == (binding.ue_id_type, binding.ue_id)):
                    continue
                if k.scope == "cell" and not (binding.cell_id and k.cell_id == binding.cell_id):
                    continue
                if k.scope not in ("node", "cell", "ue"):
                    continue
                context.append(asdict(k))
        duration = flow.end - flow.start
        return TelemetryEvent(domain="mobile", device_id=binding.node_id if binding and binding.node_id else flow.source,
            src_ip=flow.src_ip, dst_ip=flow.dst_ip, dst_port=flow.dst_port,
            protocol=flow.protocol, pps=flow.packets_count / duration,
            bps=flow.bytes_count / duration, timestamp=flow.end,
            flags={"observation_id": flow.observation_id, "measurement_source": flow.source,
                   "network_id": flow.network_id, "src_port": flow.src_port,
                   "identity_status": "resolved" if binding else "unresolved",
                   "ue_session": asdict(binding) if binding else None, "kpm_context": context})
