# Clock validation

Workers wait for start after their route/session/receiver preflight. The
coordinator uploads and prepares every plan first, then measures each
established SSH channel with five nonce-matched clock messages. Each probe
records controller send/receive times and worker receive/send times.
Offset = ((worker_receive - controller_send) +
          (worker_send - controller_receive)) / 2.
Network RTT subtracts the worker processing interval. The sample with the
lowest RTT is retained, with RTT/2 as the uncertainty bound assuming
nonnegative one-way delays. A controller wall-clock jump invalidates the probe.

The 250ms configured limit is unchanged. A probe passes only when
abs(offset) + uncertainty is within the limit. It fails as actual skew
when abs(offset) - uncertainty exceeds the limit. Otherwise it is
inconclusive due to communication latency, and the experiment does not start.
Inconclusive checks require a retry under lower load, not an NTP accusation.

Samples, offset, RTT, uncertainty, verdict and configured limit are saved
per agent in execution_mapping.json/run.json and included in exports.
All workers must be updated with the coordinator because the protocol adds
clock requests before the existing start message. BENIGN_V1, plan contents,
plan hashes and ground-truth windows are unchanged.

Validation: 12 tests passed on controller Python 3.8, including real Linux
agent messaging, TCP/UDP/HTTP bidirectional execution, cancellation, real
skew, asymmetric latency and invalid timestamps. A real-lab preflight used
the existing 7904-event plan without sending a start message. All 21 execution
contexts passed. This is clock/preflight validation, not a 600s baseline run.
