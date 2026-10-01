# Experimental capacity reference

Run on the controller with its deployed Python environment:

```sh
cd /home/ubuntu/isp-ddos-ryu/deploy/vm-lab/tools/benign-lab
.venv/bin/python scripts/calibrate_capacity.py --without-mitigation --fresh
```

The runner measures delivered TCP payload goodput to the victim data address
`10.55.0.100:19090`. Each domain runs separately, all its sources concurrently,
two streams per source, three repetitions in each direction. When the initial
maximum/minimum ratio exceeds 1.3, that direction receives two further
repetitions. Each repetition
lasts 10 seconds; bytes from the first two seconds are excluded. Upload bytes
are counted at the receiver; download bytes are counted at each client.
The reference is the smaller of the upload and download medians, in Mbps.
This is achievable goodput of these VM generators and paths; it does not measure
physical line rate, UDP loss capacity, or a simultaneous four-domain maximum.
The requested TCP send buffer is 128 KiB on clients and receiver; operating
system limits and buffering can further influence achieved throughput.
TCP MSS is bounded to 1200 bytes. Routes and current source IPs are verified
before each client run. Clients within a round start concurrently via SSH;
they do not share a hardware-synchronized measurement window.

Mobile runs in all five UE namespaces; Fixed binds ten live macvlan/IPoE
subscriber addresses; Enterprise binds all five site data IPs; Peering binds
the aggregate peer-router data IP. The controller is only an orchestrator.
Credentials are loaded from ignored runtime files and existing inventory,
passed through environment variables, and excluded from reports.

Initial measurements with the DDoS controller active triggered actual mitigation.
Those samples are retained separately and excluded from final references.
`LAB_CALIBRATION_MODE=true` temporarily bypasses detection and actuation while
keeping telemetry, correlation and normal forwarding validation. Its default
is false. The runner uses a volatile systemd override on the orchestrator VM,
restarts Ryu, and restores normal detection in its cleanup path. A separate
15-minute restoration timer also covers interrupted controller-side execution.
Do not run other experiments during calibration. Run only after existing
mitigations have been released; restart alone does not necessarily remove
all external mitigation state.

Enterprise calibration also installs two temporary OpenFlow rules restricted
to TCP port 19090 between `10.70.0.0/24` and the victim IP, using the inspected `br-ent` ports
3 (Enterprise) and 5 (victim). They keep bulk traffic in the switch data plane
instead of table-miss packet processing. Cookie `0xbe910090`, priority 20,
and hard timeout 900 seconds identify these rules; cleanup removes only that
cookie. General forwarding and mitigation rules are untouched. This Enterprise
reference therefore describes the data plane with installed forwarding rules;
it does not guarantee that the current application reaches that rate through
controller packet processing. Validate BENIGN_V1 throughput separately.

Fixed session renewal commands are queued through the existing subscriber
agent. Ten active BNG sessions are required, and Fixed is measured last to
allow queued renewals to complete. All current IPs must be reconciled with
the configured mappings before subsequent BENIGN_V1 experiments.

Raw samples live in `.runtime/benign-lab/calibration/measurements.json`.
Re-running resumes recorded complete rounds; archive that file first for
an independent calibration campaign, or pass `--fresh`, which archives it
automatically. The checkpoint and each round record the probe SHA-256; a
changed probe requires a fresh campaign. Upload failures without receiver
confirmation invalidate a round. Download resets/timeouts retain the bytes
actually received, count the remainder as outage over the full fixed window,
and record the error explicitly. The reviewed final report is copied to
`docs/CAPACITY_MEASUREMENTS.json`.
Changing `capacity_mbps` affects newly materialized plans only: existing
plans, their seeds, profiles, ground-truth windows and SHA-256 hashes remain
unchanged.
