#!/usr/bin/env python3
"""Run isolated, repeated DDoS trials in the distributed VM lab.

The runner is intentionally conservative: one trial is allowed to finish,
recover and cool down before the next one starts.  Individual trials use one
attacker.  MULTIDOMAIN_FLOOD uses one attacker *per domain* because a
multidomain event cannot exist with a single global source.

Outputs:
  trials_long.csv  one row per domain/vector/run, including timestamps/status
  trials_table.csv the wide Td/Tm/Tr table used by the thesis
  trials.jsonl     append-only checkpoint suitable for --resume
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import random
import re
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional


DOMAINS = ("enterprise", "broadband", "mobile", "peering")
VECTORS = ("TCP_SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "MULTIDOMAIN_FLOOD")
TARGET_IP = "10.55.0.100"

HOST_BY_DOMAIN = {
    "enterprise": "ent-site-1",
    "broadband": "suscriptor",
    "mobile": "ue",
    "peering": "peer-router",
}

SOURCE_HINT = {
    "enterprise": "10.70.0.11",
    "mobile": "10.45.1.2",
    "peering": "10.30.0.2",
}

DETECTION_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?).*"
    r"FlowStatsIDS \[(?P<domain>[^]]+)] DETECTION: ATTACK_DETECTED "
    r"(?P<kind>\S+) source=(?P<src>\S+) destination=(?P<dst>[^:]+):"
)
MITIGATION_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?).*"
    r"FlowStatsIDS \[(?P<domain>[^]]+)] MITIGATION: "
    r"(?P<action>BLOCK|THROTTLE|BGP_FLOWSPEC_DISCARD)\s+\S+.*"
    r"(?:source|src_ip)=(?P<src>\S+)"
)
RECOVERY_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?).*"
    r"FlowStatsIDS \[(?P<domain>[^]]+)] MITIGATION: "
    r"(?P<action>UNBLOCK|UNTHROTTLE)\s+\S+.*(?:source|src_ip)=(?P<src>\S+)"
)


@dataclass
class TrialResult:
    run_id: str
    iteration: int
    domain: str
    vector: str
    source: str
    target: str
    attack_at: str = ""
    detection_at: str = ""
    mitigation_at: str = ""
    recovery_at: str = ""
    Td_s: Optional[float] = None
    Tm_s: Optional[float] = None
    Tr_s: Optional[float] = None
    status: str = "ERROR"
    error: str = ""


class LabError(RuntimeError):
    pass


class Lab:
    def __init__(self, repo: Path, inventory: Path, dry_run: bool = False):
        self.repo = repo
        self.inventory = inventory
        self.dry_run = dry_run

    def _run(self, argv: list[str], timeout: int = 45, check: bool = True) -> str:
        print("+", " ".join(argv), flush=True)
        if self.dry_run:
            return ""
        cp = subprocess.run(
            argv, cwd=self.repo, text=True, capture_output=True, timeout=timeout
        )
        combined = "\n".join(part for part in (cp.stdout, cp.stderr) if part)
        if argv and argv[0] == "ansible" and (
            "No hosts matched" in combined
            or "Could not match supplied host pattern" in combined
            or "No inventory was parsed" in combined
        ):
            raise LabError(f"Ansible did not execute the requested host:\n{combined.strip()}")
        if check and cp.returncode != 0:
            raise LabError(f"command failed ({cp.returncode}): {cp.stderr.strip()}\n{cp.stdout.strip()}")
        return cp.stdout

    def shell(self, host: str, command: str, *, background: bool = False,
              timeout: int = 45, check: bool = True) -> str:
        argv = [
            "ansible", host, "-i", str(self.inventory), "-b",
        ]
        if background:
            argv += ["-B", "180", "-P", "0"]
        argv += ["-m", "shell", "-a", command]
        return self._run(argv, timeout=timeout, check=check)

    def log_size(self) -> int:
        if self.dry_run:
            return 0
        out = self.shell("orchestrator", "stat -c %s /var/log/ryu-manager.log")
        values = re.findall(r"(?m)^\s*(\d+)\s*$", out)
        if not values:
            raise LabError("could not read ryu-manager.log size")
        return int(values[-1])

    def log_from(self, offset: int) -> str:
        # tail -c is 1-based: byte offset N is read with -c +(N+1).
        return self.shell(
            "orchestrator",
            f"tail -c +{offset + 1} /var/log/ryu-manager.log",
            timeout=60,
        )

    @staticmethod
    def marker_path(run_id: str, domain: str) -> str:
        return f"/tmp/ddos-trial-{run_id}-{domain}.start"

    def _hping_command(self, domain: str, vector: str, run_id: str,
                       duration: int) -> str:
        marker = self.marker_path(run_id, domain)
        if vector in ("UDP_FLOOD", "MULTIDOMAIN_FLOOD"):
            args = f"--udp -p 53 -i u1000 {TARGET_IP}"
        elif vector == "TCP_SYN_FLOOD":
            args = f"-S -p 443 -i u1000 {TARGET_IP}"
        elif vector == "ICMP_FLOOD":
            args = f"--icmp -i u1000 {TARGET_IP}"
        else:
            raise LabError(f"unsupported vector: {vector}")
        prefix = "ip netns exec ue1 " if domain == "mobile" else ""
        return (
            f"date +%s.%N > {marker}; "
            f"timeout {duration} {prefix}hping3 {args} "
            f">/tmp/ddos-trial-{run_id}.log 2>&1"
        )

    def launch(self, domain: str, vector: str, run_id: str, duration: int) -> None:
        host = HOST_BY_DOMAIN[domain]
        marker = self.marker_path(run_id, domain)
        if domain == "broadband":
            scenario = {
                "TCP_SYN_FLOOD": "syn_flood",
                "UDP_FLOOD": "udp_flood",
                "ICMP_FLOOD": "icmp_flood",
                "MULTIDOMAIN_FLOOD": "udp_flood",
            }[vector]
            # The marker is written by the same shell that writes the FIFO.
            command = (
                f"date +%s.%N > {marker}; "
                f"printf '%s\\n' 'attack {scenario}' > /run/bng-agent/cmd"
            )
            self.shell(host, command)
        else:
            self.shell(host, self._hping_command(domain, vector, run_id, duration),
                       background=True)

    def attack_start(self, domain: str, run_id: str) -> float:
        if self.dry_run:
            return time.time()
        out = self.shell(HOST_BY_DOMAIN[domain], f"cat {self.marker_path(run_id, domain)}")
        matches = re.findall(r"(?m)^\s*(\d+\.\d+)\s*$", out)
        if not matches:
            raise LabError(f"missing attack start marker for {domain}")
        return float(matches[-1])

    def stop(self, domain: str) -> None:
        host = HOST_BY_DOMAIN[domain]
        if domain == "broadband":
            self.shell(host, "printf '%s\\n' baseline > /run/bng-agent/cmd", check=False)
        else:
            self.shell(host, "pkill -f '[h]ping3' || true", check=False)

    def cleanup(self) -> None:
        for domain in DOMAINS:
            self.stop(domain)

    def healthcheck(self) -> None:
        checks = (
            ("orchestrator", "systemctl is-active ryu-manager nfcapd exabgp"),
            ("bng", "systemctl is-active accel-pppd freeradius"),
            ("suscriptor", "systemctl is-active bng-subscriber-agent"),
        )
        for host, command in checks:
            out = self.shell(host, command)
            if self.dry_run:
                continue
            active = re.findall(r"(?m)^active$", out)
            expected = 3 if host == "orchestrator" else (2 if host == "bng" else 1)
            if len(active) < expected:
                raise LabError(f"health check failed on {host}: {out.strip()}")

    def broadband_session_count(self) -> int:
        out = self.shell("bng", "accel-cmd -p 2000 show sessions")
        return len(re.findall(r"(?m)^\s*ipoe\d+\s+\|.*\|\s+active\s+\|", out))

    def wait_for_baseline(self, timeout: int = 120) -> None:
        if self.dry_run:
            return
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if self.broadband_session_count() == 8:
                    return
            except LabError:
                pass
            time.sleep(5)
        raise LabError("broadband did not recover 8/8 active IPoE sessions")


def parse_ts(value: str) -> float:
    value = value.replace(",", ".")
    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in value else "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).timestamp()


def iso(epoch: Optional[float]) -> str:
    if epoch is None:
        return ""
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds")


def canonical_domain(log_domain: str) -> str:
    return "peering" if log_domain.lower() == "bgp" else log_domain.lower()


def source_matches(domain: str, expected: str, observed: str) -> bool:
    if observed == "*":
        return domain == "broadband"
    return not expected or observed == expected


def extract_result(log: str, result: TrialResult, attack_epoch: float) -> TrialResult:
    detection = mitigation = recovery = None
    detected_source = result.source

    for line in log.splitlines():
        m = DETECTION_RE.search(line)
        if m and canonical_domain(m.group("domain")) == result.domain and m.group("dst") == result.target:
            if source_matches(result.domain, result.source, m.group("src")):
                detection = detection or parse_ts(m.group("ts"))
                if m.group("src") != "*":
                    detected_source = m.group("src")
            continue
        m = MITIGATION_RE.search(line)
        if m and canonical_domain(m.group("domain")) == result.domain:
            if source_matches(result.domain, detected_source, m.group("src")):
                mitigation = mitigation or parse_ts(m.group("ts"))
            continue
        m = RECOVERY_RE.search(line)
        if m and canonical_domain(m.group("domain")) == result.domain:
            if source_matches(result.domain, detected_source, m.group("src")):
                recovery = recovery or parse_ts(m.group("ts"))

    result.source = detected_source
    result.attack_at = iso(attack_epoch)
    result.detection_at = iso(detection)
    result.mitigation_at = iso(mitigation)
    result.recovery_at = iso(recovery)
    if detection is not None:
        result.Td_s = round(max(0.0, detection - attack_epoch), 3)
    if detection is not None and mitigation is not None:
        result.Tm_s = round(max(0.0, mitigation - detection), 3)
    if mitigation is not None and recovery is not None:
        result.Tr_s = round(max(0.0, recovery - mitigation), 3)
    missing = [name for name, value in (("detection", detection), ("mitigation", mitigation), ("recovery", recovery)) if value is None]
    result.status = "OK" if not missing else "INCOMPLETE"
    result.error = "" if not missing else "missing " + ", ".join(missing)
    return result


def append_checkpoint(path: Path, rows: Iterable[TrialResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(asdict(row), sort_keys=True) + "\n")
        f.flush()


def load_checkpoint(path: Path) -> list[TrialResult]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(TrialResult(**json.loads(line)))
    return rows


def write_outputs(out_dir: Path, rows: list[TrialResult]) -> None:
    fields = list(TrialResult.__dataclass_fields__)
    with (out_dir / "trials_long.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)

    metric_fields = [f"{vector}_{metric}" for vector in VECTORS for metric in ("Td", "Tm", "Tr")]
    by_key = {(r.domain, r.iteration, r.vector): r for r in rows}
    with (out_dir / "trials_table.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["Dominio", "Corrida", *metric_fields]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for domain in DOMAINS:
            iterations = sorted({r.iteration for r in rows if r.domain == domain})
            for iteration in iterations:
                record = {"Dominio": domain, "Corrida": iteration}
                for vector in VECTORS:
                    row = by_key.get((domain, iteration, vector))
                    for metric in ("Td", "Tm", "Tr"):
                        record[f"{vector}_{metric}"] = "" if row is None else getattr(row, f"{metric}_s")
                writer.writerow(record)


def wait_and_collect(lab: Lab, offset: int, results: list[TrialResult], starts: dict[str, float],
                     timeout: int, poll: int) -> list[TrialResult]:
    deadline = time.monotonic() + timeout
    latest = ""
    while time.monotonic() < deadline:
        latest = lab.log_from(offset)
        parsed = [extract_result(latest, row, starts[row.domain]) for row in results]
        if all(row.status == "OK" for row in parsed):
            return parsed
        time.sleep(poll)
    # Fetch once after the deadline so an event emitted during the final sleep
    # is not discarded merely because it fell between polling instants.
    latest = lab.log_from(offset)
    return [extract_result(latest, row, starts[row.domain]) for row in results]


def run_trial(lab: Lab, iteration: int, vector: str, domains: tuple[str, ...],
              attack_duration: int, event_timeout: int, poll: int) -> list[TrialResult]:
    run_id = f"i{iteration:03d}-{vector.lower()}-{uuid.uuid4().hex[:8]}"
    offset = lab.log_size()
    results = [
        TrialResult(run_id, iteration, domain, vector, SOURCE_HINT.get(domain, ""), TARGET_IP)
        for domain in domains
    ]
    starts: dict[str, float] = {}
    try:
        # Async hping launches keep multidomain starts close together; broadband's
        # FIFO write is synchronous and takes only one local operation.
        # A multidomain trial is one sequential experiment, but its one source
        # per domain must start concurrently so the correlation windows truly
        # overlap.  Individual trials also pass through this same path.
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(domains)) as pool:
            futures = {
                pool.submit(lab.launch, domain, vector, run_id, attack_duration): domain
                for domain in domains
            }
            for future in concurrent.futures.as_completed(futures):
                future.result()
        for domain in domains:
            starts[domain] = lab.attack_start(domain, run_id)
        if lab.dry_run:
            for row in results:
                row.attack_at = iso(starts[row.domain])
                row.status = "DRY_RUN"
                row.error = "commands validated but not executed"
            return results
        parsed = wait_and_collect(lab, offset, results, starts, event_timeout, poll)
    except Exception as exc:
        for row in results:
            row.status = "ERROR"
            row.error = str(exc)
        parsed = results
    finally:
        for domain in domains:
            lab.stop(domain)
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=30,
                        help="independent repetitions per domain/vector (default: 30)")
    parser.add_argument("--inventory", type=Path,
                        default=Path("deploy/vm-lab/generated/ansible/inventory.ini"))
    parser.add_argument("--output-dir", type=Path, default=Path("analysis/results/vm-lab"))
    parser.add_argument("--domains", nargs="+", choices=DOMAINS, default=list(DOMAINS))
    parser.add_argument("--vectors", nargs="+", choices=VECTORS, default=list(VECTORS))
    parser.add_argument("--attack-duration", type=int, default=20)
    parser.add_argument("--event-timeout", type=int, default=150,
                        help="seconds allowed for detection, mitigation and recovery")
    parser.add_argument("--cooldown", type=int, default=15)
    parser.add_argument("--poll", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20260925)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.iterations < 2:
        parser.error("--iterations must be at least 2; use 30 for the thesis dataset")

    repo = Path(__file__).resolve().parents[1]
    if args.inventory.is_absolute():
        inventory = args.inventory
    else:
        candidates = (
            repo / args.inventory,
            Path.home() / "isp-ddos-ryu" / args.inventory,
        )
        inventory = next((candidate for candidate in candidates if candidate.is_file()), candidates[0])
    if not inventory.is_file():
        parser.error(
            "Ansible inventory not found. Generate the VM lab inventory or pass "
            "--inventory /absolute/path/to/inventory.ini"
        )
    print(f"Using Ansible inventory: {inventory}", flush=True)
    out_dir = args.output_dir if args.output_dir.is_absolute() else repo / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = out_dir / "trials.jsonl"
    previous = load_checkpoint(checkpoint) if args.resume else []
    if checkpoint.exists() and not args.resume:
        parser.error(f"{checkpoint} already exists; use --resume or a different --output-dir")
    completed = {(r.iteration, r.domain, r.vector) for r in previous if r.status == "OK"}
    lab = Lab(repo, inventory, args.dry_run)
    rng = random.Random(args.seed)

    lab.healthcheck()
    lab.cleanup()
    lab.wait_for_baseline()

    for iteration in range(1, args.iterations + 1):
        jobs: list[tuple[str, tuple[str, ...]]] = []
        for vector in args.vectors:
            if vector == "MULTIDOMAIN_FLOOD":
                domains = tuple(args.domains)
                if len(domains) < 2:
                    print("Skipping MULTIDOMAIN_FLOOD: at least two domains are required", file=sys.stderr)
                    continue
                if all((iteration, d, vector) in completed for d in domains):
                    continue
                jobs.append((vector, domains))
            else:
                for domain in args.domains:
                    if (iteration, domain, vector) not in completed:
                        jobs.append((vector, (domain,)))
        rng.shuffle(jobs)

        for vector, domains in jobs:
            print(f"\n=== iteration={iteration} vector={vector} domains={','.join(domains)} ===", flush=True)
            lab.healthcheck()
            lab.cleanup()
            lab.wait_for_baseline()
            rows = run_trial(lab, iteration, vector, domains, args.attack_duration,
                             args.event_timeout, args.poll)
            append_checkpoint(checkpoint, rows)
            previous.extend(rows)
            write_outputs(out_dir, previous)
            failed = [r for r in rows if r.status not in ("OK", "DRY_RUN")]
            if failed:
                print("Trial incomplete; checkpoint saved. Fix the cause and rerun with --resume.", file=sys.stderr)
                return 2
            time.sleep(args.cooldown)

    lab.cleanup()
    lab.wait_for_baseline()
    write_outputs(out_dir, previous)
    print(f"\nCompleted. Results: {out_dir / 'trials_table.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
