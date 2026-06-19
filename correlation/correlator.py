from collections import defaultdict
from typing import Dict, List

from core.models import CorrelatedEvent, TelemetryEvent


class MultidomainCorrelator:
    """
    Multidomain Correlation layer.

    Aggregates TelemetryEvents from all domain adapters and groups them
    by destination IP address. When multiple network domains independently
    report traffic toward the same destination, the resulting CorrelatedEvent
    carries that multidomain context, which the Detection Engine uses to
    boost attack confidence.

    Usage (called once per monitoring cycle):

        correlator.ingest(openflow_events)
        correlator.ingest(mobile_events)
        ...
        correlated = correlator.correlate()   # clears internal buffer
    """

    def __init__(self):
        # dst_ip -> list of TelemetryEvents accumulated in current window
        self._buckets: Dict[str, List[TelemetryEvent]] = defaultdict(list)

    def ingest(self, events: List[TelemetryEvent]) -> None:
        """
        Add normalized events from one domain adapter into the current window.
        """
        for ev in events:
            self._buckets[ev.dst_ip].append(ev)

    def correlate(self) -> List[CorrelatedEvent]:
        """
        Aggregate all ingested events by destination IP and return
        CorrelatedEvents. Clears the internal buffer after processing.
        """
        results: List[CorrelatedEvent] = []

        for dst_ip, events in self._buckets.items():

            if not events:
                continue

            total_pps = sum(e.pps for e in events)
            total_bps = sum(e.bps for e in events)

            # Unique domain names that contributed events for this destination
            domains = list({e.domain for e in events})

            results.append(CorrelatedEvent(
                dst_ip=dst_ip,
                total_pps=total_pps,
                total_bps=total_bps,
                domains=domains,
                events=list(events),
            ))

        self._buckets.clear()
        return results
