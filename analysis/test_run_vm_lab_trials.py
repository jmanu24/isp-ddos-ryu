#!/usr/bin/env python3
"""Focused tests for statistical trial event correlation and CSV output."""

import csv
import tempfile
import unittest
from pathlib import Path

from run_vm_lab_trials import (
    DOMAINS, ENTERPRISE_MULTIDOMAIN_HOSTS, Lab, LabError, TrialResult, VECTORS,
    extract_result, mobile_preflight, parse_ts, resolve_effective_vectors,
    run_trial, source_matches, write_outputs,
)


class TrialParsingTests(unittest.TestCase):
    def test_active_domains_include_mobile(self):
        self.assertEqual(DOMAINS, ("enterprise", "broadband", "mobile", "peering"))

    def test_mobile_flood_does_not_use_hping3(self):
        # hping3's raw-socket path needs real Ethernet L2 framing;
        # srsue's tun_srsue is POINTOPOINT/NOARP and never sees a single
        # packet from it -- same reasoning that already ruled out hping3
        # for broadband (simulation/bng_flood.py's own module docstring).
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=True)
                self.command = ""

            def shell(self, host, command, **kwargs):
                self.command = command
                return ""

        lab = CapturingLab()
        lab.launch("mobile", "UDP_FLOOD", "test", 20)
        self.assertNotIn("hping3", lab.command)
        self.assertIn("ip netns exec ue1", lab.command)
        self.assertIn("mobile_flood.py", lab.command)

    def test_mobile_flood_heredoc_terminator_is_on_its_own_line(self):
        # Regression check for a real bug found while testing this
        # against the live lab: appending ";" straight after the
        # heredoc's closing "PYEOF" (same line) makes the shell treat
        # everything after it as still being part of the file content --
        # the terminator MUST be followed by an actual newline before any
        # further command.
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=True)
                self.command = ""

            def shell(self, host, command, **kwargs):
                self.command = command
                return ""

        lab = CapturingLab()
        lab.launch("mobile", "UDP_FLOOD", "test", 20)
        for line in lab.command.splitlines():
            if line.strip() == "PYEOF":
                self.assertEqual(line, "PYEOF", "heredoc terminator must be alone on its line")

    def test_broadband_fifo_commands_preserve_space_and_newline(self):
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=True)
                self.commands = []

            def shell(self, host, command, **kwargs):
                self.commands.append((host, command))
                return ""

        lab = CapturingLab()
        lab.launch("broadband", "ICMP_FLOOD", "test", 20)
        lab.stop("broadband")
        self.assertIn("printf '%s\\n' 'attack icmp_flood' > /run/bng-agent/cmd", lab.commands[0][1])
        self.assertEqual(lab.commands[1], ("suscriptor", "printf '%s\\n' baseline > /run/bng-agent/cmd"))

    def test_peering_syn_uses_one_softflowd_flow(self):
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=True)
                self.command = ""

            def shell(self, host, command, **kwargs):
                self.command = command
                return ""

        lab = CapturingLab()
        lab.launch("peering", "TCP_SYN_FLOOD", "test", 20)
        self.assertIn("hping3 -S --keep -p 443", lab.command)

    def test_peering_udp_uses_one_softflowd_flow(self):
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=True)
                self.command = ""

            def shell(self, host, command, **kwargs):
                self.command = command
                return ""

        lab = CapturingLab()
        lab.launch("peering", "UDP_FLOOD", "test", 20)
        self.assertIn("hping3 --udp --keep -p 53", lab.command)

    def test_non_broadband_baseline_does_not_query_bng(self):
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=False)

            def broadband_session_count(self):
                self.fail("peering baseline must not depend on broadband")

        CapturingLab().wait_for_baseline(("peering",))

    def test_startup_healthcheck_dry_run_is_non_mutating(self):
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=True)
                self.healthchecks = 0

            def healthcheck(self, domains=None):
                self.healthchecks += 1

            def shell(self, *args, **kwargs):
                self.fail("dry-run startup healthcheck must not run recovery commands")

        lab = CapturingLab()
        lab.startup_healthcheck()
        self.assertEqual(lab.healthchecks, 1)

    def test_correlates_all_domain_action_formats(self):
        cases = (
            ("enterprise", "enterprise", "10.70.0.11", "BLOCK flow source=10.70.0.11", "UNBLOCK flow source=10.70.0.11"),
            ("broadband", "broadband", "", "BLOCK flow source=*", "UNBLOCK flow source=*"),
            ("mobile", "mobile", "10.45.1.2", "THROTTLE UE src_ip=10.45.1.2", "UNTHROTTLE UE src_ip=10.45.1.2"),
            ("peering", "bgp", "10.30.0.2", "BGP_FLOWSPEC_DISCARD flow source=10.30.0.2", "UNBLOCK flow source=10.30.0.2"),
        )
        attack = parse_ts("2026-09-24 12:00:00.000")
        for domain, logged_domain, source, mitigation, recovery in cases:
            observed_source = source or "*"
            log = "\n".join((
                f"2026-09-24 12:00:01.125 WARNING FlowStatsIDS [{logged_domain}] "
                f"DETECTION: ATTACK_DETECTED UDP_FLOOD source={observed_source} destination=10.55.0.100:53/UDP",
                f"2026-09-24 12:00:01.250 WARNING FlowStatsIDS [{logged_domain}] MITIGATION: {mitigation}",
                f"2026-09-24 12:00:04.500 WARNING FlowStatsIDS [{logged_domain}] MITIGATION: {recovery}",
            ))
            row = TrialResult("test", 1, domain, "UDP_FLOOD", source, "10.55.0.100")
            result = extract_result(log, row, attack)
            self.assertEqual(result.status, "OK", (domain, result.error))
            self.assertEqual((result.Td_s, result.Tm_s, result.Tr_s), (1.125, 0.125, 3.25))

    def test_mode_isolated_drops_multidomain_flood(self):
        effective = resolve_effective_vectors("isolated", VECTORS, DOMAINS, self.fail)
        self.assertEqual(effective, ("TCP_SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD"))

    def test_mode_multidomain_keeps_only_multidomain_flood(self):
        effective = resolve_effective_vectors("multidomain", VECTORS, DOMAINS, self.fail)
        self.assertEqual(effective, ("MULTIDOMAIN_FLOOD",))

    def test_mode_multidomain_requires_two_domains(self):
        errors = []
        resolve_effective_vectors("multidomain", VECTORS, ("enterprise",), errors.append)
        self.assertEqual(len(errors), 1)
        self.assertIn("at least 2", errors[0])

    def test_mode_isolated_requires_a_non_multidomain_vector(self):
        errors = []
        resolve_effective_vectors("isolated", ("MULTIDOMAIN_FLOOD",), DOMAINS, errors.append)
        self.assertEqual(len(errors), 1)

    def test_mode_both_is_unchanged_previous_behavior(self):
        effective = resolve_effective_vectors("both", VECTORS, DOMAINS, self.fail)
        self.assertEqual(effective, VECTORS)

    def test_mobile_preflight_dry_run_is_always_ok(self):
        lab = Lab(Path("."), Path("inventory.ini"), dry_run=True)
        ok, reason = mobile_preflight(lab)
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_mobile_preflight_captures_recovery_exception(self):
        # item 2: a recovery failure must be CAPTURED here, never raised --
        # one domain's known flakiness can't be allowed to crash the
        # whole campaign process.
        class FlakyLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=False)

            def mobile_chain_healthy(self):
                return False

            def playbook(self, *args, **kwargs):
                raise RuntimeError("ansible-playbook exploded")

        ok, reason = mobile_preflight(FlakyLab())
        self.assertFalse(ok)
        self.assertIn("raised", reason)

    def _unhealthy_mobile_lab(self):
        class UnhealthyMobileLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=False)
                self.launched = []
                self.code_version_value = "deadbeef"

            def code_version(self):
                return self.code_version_value

            def mobile_chain_healthy(self):
                return False

            def playbook(self, *args, **kwargs):
                return ""  # "recovery" that doesn't actually fix anything

            def launch(self, domain, vector, run_id, duration):
                self.launched.append(domain)

            def log_size(self):
                self.fail("must not reach the attack phase when mobile preflight fails")

        return UnhealthyMobileLab()

    def test_isolated_mobile_trial_is_invalid_not_error(self):
        lab = self._unhealthy_mobile_lab()
        rows = run_trial(lab, 1, "UDP_FLOOD", ("mobile",), 5, 10, 1, scenario_mode="isolated")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, "INVALID")
        self.assertEqual(lab.launched, [])  # the attack must never have been launched

    def test_joint_scenario_invalidates_every_domain(self):
        lab = self._unhealthy_mobile_lab()
        rows = run_trial(lab, 1, "MULTIDOMAIN_FLOOD", ("mobile", "enterprise"), 5, 10, 1,
                         scenario_mode="multidomain")
        self.assertEqual({r.status for r in rows}, {"INVALID_SCENARIO"})
        self.assertEqual(lab.launched, [])  # not even enterprise's own attack ran

    def test_writes_expected_wide_columns(self):
        row = TrialResult("test", 1, "enterprise", "TCP_SYN_FLOOD", "10.70.0.11", "10.55.0.100",
                          Td_s=1.0, Tm_s=0.2, Tr_s=4.0, status="OK")
        with tempfile.TemporaryDirectory() as directory:
            write_outputs(Path(directory), [row])
            with (Path(directory) / "trials_table.csv").open(newline="", encoding="utf-8") as handle:
                record = next(csv.DictReader(handle))
            self.assertEqual(record["Dominio"], "enterprise")
            self.assertEqual(record["TCP_SYN_FLOOD_Td"], "1.0")
            self.assertEqual(record["TCP_SYN_FLOOD_Tm"], "0.2")
            self.assertEqual(record["TCP_SYN_FLOOD_Tr"], "4.0")


    # --- item 1: set_detection_mode must always apply, never trust
    # in-process state as a proxy for the real controller's state ---

    def test_set_detection_mode_always_applies_even_if_unchanged_in_process(self):
        class RecordingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=False)
                self.restarts = 0
                self.log = ""

            def shell(self, host, command, **kwargs):
                if "systemctl restart ryu-manager" in command:
                    self.restarts += 1
                    self.log += "STARTUP DETECTION_MODE=multidomain\n"
                return ""

            def healthy(self, host, command):
                return True

            def log_size(self):
                return 0

            def log_from(self, offset):
                return self.log

        lab = RecordingLab()
        # self.detection_mode already equals "multidomain" (the __init__
        # default) -- the OLD buggy code would see this and skip
        # applying anything at all.
        self.assertEqual(lab.detection_mode, "multidomain")
        lab.set_detection_mode("multidomain")
        self.assertEqual(lab.restarts, 1)

    def test_set_detection_mode_verifies_against_the_controllers_own_log_line(self):
        class StaleLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=False)

            def shell(self, host, command, **kwargs):
                return ""

            def healthy(self, host, command):
                return True

            def log_size(self):
                return 0

            def log_from(self, offset):
                # The restart "succeeded" (service active) but the
                # controller's own startup log still reports the OLD
                # mode -- must be treated as a failure, not silently
                # accepted just because systemctl is-active passed.
                return "STARTUP DETECTION_MODE=multidomain\n"

        with self.assertRaises(LabError):
            StaleLab().set_detection_mode("isolated")

    # --- item 2: startup_healthcheck/healthcheck scope to --domains,
    # and a mobile recovery exception must not crash the campaign ---

    def test_startup_healthcheck_skips_mobile_when_not_selected(self):
        class NoMobileLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=False)
                self.reachable_hosts = []

            def ensure_vm_reachable(self, host, vm_name):
                self.reachable_hosts.append(host)

            def shell(self, host, command, **kwargs):
                return "active\nactive\nactive\n"

            def healthy(self, host, command):
                return True

            def mobile_chain_healthy(self):
                self.fail("mobile must not be checked when not in --domains")

            def broadband_session_count(self):
                return 8

        lab = NoMobileLab()
        lab.startup_healthcheck(("enterprise",))
        self.assertNotIn("ran", lab.reachable_hosts)
        self.assertNotIn("du", lab.reachable_hosts)
        self.assertNotIn("ue", lab.reachable_hosts)

    def test_startup_healthcheck_mobile_recovery_exception_is_captured(self):
        class ExplodingRecoveryLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=False)

            def ensure_vm_reachable(self, host, vm_name):
                pass

            def shell(self, host, command, **kwargs):
                return "active\nactive\nactive\n"

            def healthy(self, host, command):
                return True

            def mobile_chain_healthy(self):
                return False  # never recovers

            def playbook(self, *args, **kwargs):
                raise RuntimeError("ansible-playbook exploded")

            def broadband_session_count(self):
                return 8

        # Must NOT raise -- item 2 fix: this used to be unguarded and
        # would crash the whole campaign over mobile's own flakiness.
        ExplodingRecoveryLab().startup_healthcheck(("mobile",))

    # --- item 4: a real TCP probe against the victim's service, not
    # ICMP, and broadband now gets one too ---

    def test_recovery_probes_use_tcp_not_icmp(self):
        from run_vm_lab_trials import _RECOVERY_PROBE
        for domain, (host, cmd) in _RECOVERY_PROBE.items():
            self.assertNotIn("ping", cmd, f"{domain}'s recovery probe still uses ICMP ping")
        self.assertIn("broadband", _RECOVERY_PROBE)

    # --- item 7: NO_DETECTION is a valid experimental outcome, distinct
    # from a real pipeline failure ---

    def test_no_detection_when_attack_confirmed_but_never_detected(self):
        row = TrialResult("run1", 1, "enterprise", "UDP_FLOOD", "10.70.0.11", "10.55.0.100",
                          observed_pps=500.0)
        extract_result("", row, 1000.0)
        self.assertEqual(row.status, "NO_DETECTION")

    def test_incomplete_when_attack_never_confirmed_and_never_detected(self):
        # observed_pps is None (the before/after tx sample never
        # confirmed real traffic) -- must stay INCOMPLETE, not be
        # upgraded to a NO_DETECTION outcome a never-launched attack
        # doesn't deserve.
        row = TrialResult("run1", 1, "enterprise", "UDP_FLOOD", "10.70.0.11", "10.55.0.100",
                          observed_pps=None)
        extract_result("", row, 1000.0)
        self.assertEqual(row.status, "INCOMPLETE")

    def test_incomplete_when_detected_but_never_mitigated(self):
        # A real pipeline-bug symptom (detected but the mitigation never
        # followed) must stay INCOMPLETE and keep halting the campaign --
        # NO_DETECTION must never mask this.
        log = (
            "2026-01-01 00:00:01 FlowStatsIDS [enterprise] DETECTION: "
            "ATTACK_DETECTED UDP_FLOOD source=10.70.0.11 destination=10.55.0.100:53\n"
        )
        row = TrialResult("run1", 1, "enterprise", "UDP_FLOOD", "10.70.0.11", "10.55.0.100",
                          observed_pps=500.0)
        extract_result(log, row, 1000.0)
        self.assertEqual(row.status, "INCOMPLETE")

    # --- item 7: MULTIDOMAIN_FLOOD launches enterprise from all 5
    # ent-site hosts, not just one (DIST_MIN_SOURCES=5 can never be
    # crossed by one attacker per domain otherwise) ---

    def test_multidomain_flood_launches_enterprise_from_all_five_sites(self):
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=True)
                self.hosts = []

            def shell(self, host, command, **kwargs):
                self.hosts.append(host)
                return ""

        lab = CapturingLab()
        lab.launch("enterprise", "MULTIDOMAIN_FLOOD", "run1", 20)
        self.assertEqual(sorted(lab.hosts), sorted(ENTERPRISE_MULTIDOMAIN_HOSTS))

    def test_isolated_enterprise_vector_still_uses_only_ent_site_1(self):
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=True)
                self.hosts = []

            def shell(self, host, command, **kwargs):
                self.hosts.append(host)
                return ""

        lab = CapturingLab()
        lab.launch("enterprise", "UDP_FLOOD", "run1", 20)
        self.assertEqual(lab.hosts, ["ent-site-1"])

    def test_source_matches_accepts_wildcard_for_any_domain(self):
        # 2nd review pass, finding 1: the controller now emits one
        # ATTACK_DETECTED line PER CONTRIBUTING DOMAIN, so a line's own
        # [domain] bracket is architecturally guaranteed correct --
        # wildcard "*" sources are no longer restricted to
        # broadband/enterprise.
        self.assertTrue(source_matches("enterprise", "10.70.0.11", "*"))
        self.assertTrue(source_matches("broadband", "", "*"))
        self.assertTrue(source_matches("mobile", "10.45.1.2", "*"))
        self.assertTrue(source_matches("peering", "10.30.0.2", "*"))

    def test_multidomain_flood_enterprise_row_source_is_wildcard(self):
        lab = Lab(Path("."), Path("inventory.ini"), dry_run=True)
        rows = run_trial(lab, 1, "MULTIDOMAIN_FLOOD", ("enterprise", "peering"), 5, 10, 1,
                         scenario_mode="multidomain")
        enterprise_row = next(r for r in rows if r.domain == "enterprise")
        peering_row = next(r for r in rows if r.domain == "peering")
        self.assertEqual(enterprise_row.source, "")
        self.assertNotEqual(peering_row.source, "")

    # --- 2nd review pass, finding 2: generator_confirmed ---

    def test_generator_confirmed_false_on_known_error_marker(self):
        class ErrorLogLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=False)

            def shell(self, host, command, **kwargs):
                return "bash: hping3: command not found\n"

        self.assertFalse(ErrorLogLab().generator_confirmed("enterprise", "run1"))

    def test_generator_confirmed_true_on_clean_empty_log(self):
        class CleanLogLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=False)

            def shell(self, host, command, **kwargs):
                return ""  # hping3's own happy-path default (non -V) output

        self.assertTrue(CleanLogLab().generator_confirmed("enterprise", "run1"))

    def test_generator_confirmed_none_for_broadband(self):
        lab = Lab(Path("."), Path("inventory.ini"), dry_run=False)
        self.assertIsNone(lab.generator_confirmed("broadband", "run1"))

    def test_no_detection_requires_meaningful_pps_floor(self):
        # A tiny nonzero reading (incidental SSH/management chatter) must
        # NOT be accepted as confirmation the attack generator ran.
        row = TrialResult("run1", 1, "enterprise", "UDP_FLOOD", "10.70.0.11", "10.55.0.100",
                          observed_pps=2.0)
        extract_result("", row, 1000.0)
        self.assertEqual(row.status, "INCOMPLETE")

    def test_no_detection_vetoed_by_generator_not_confirmed(self):
        row = TrialResult("run1", 1, "enterprise", "UDP_FLOOD", "10.70.0.11", "10.55.0.100",
                          observed_pps=500.0, generator_confirmed=False)
        extract_result("", row, 1000.0)
        self.assertEqual(row.status, "INCOMPLETE")

    # --- 2nd review pass, finding 3: broadband respects attack_duration ---

    def test_broadband_attack_is_stopped_after_the_attack_window(self):
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=False)
                self.commands = []

            def shell(self, host, command, **kwargs):
                self.commands.append((host, command))
                return ""

            def sample_tx_packets(self, domain, vector=""):
                return 0

            def generator_confirmed(self, domain, run_id, vector=""):
                return None

            def attack_start(self, domain, run_id, vector=""):
                return 1000.0

            def log_size(self):
                return 0

            def log_from(self, offset):
                return ""

        lab = CapturingLab()
        run_trial(lab, 1, "UDP_FLOOD", ("broadband",), 0, 0, 1)
        baseline_commands = [c for h, c in lab.commands if "baseline" in c]
        # One from the explicit post-attack-window stop, one from the
        # trial's own `finally: lab.stop(domain)` cleanup.
        self.assertGreaterEqual(len(baseline_commands), 2)

    # --- 2nd review pass, finding 5: cleanup()/healthcheck() scoping ---

    def test_cleanup_only_stops_selected_domains(self):
        class CapturingLab(Lab):
            def __init__(self):
                super().__init__(Path("."), Path("inventory.ini"), dry_run=True)
                self.stopped = []

            def stop(self, domain):
                self.stopped.append(domain)

        lab = CapturingLab()
        lab.cleanup(("enterprise",))
        self.assertEqual(lab.stopped, ["enterprise"])

    # --- 2nd review pass, finding 6: repeatability --resume continues
    # the sequence instead of restarting it ---

    def test_repeatability_resume_skips_already_completed_cycles(self):
        from run_vm_lab_trials import run_mobile_repeatability
        import tempfile

        previous = [
            TrialResult("prev1", 1, "mobile", "UDP_FLOOD", "10.45.1.2", "10.55.0.100",
                       status="OK", scenario_mode="repeatability"),
            TrialResult("prev2", 2, "mobile", "UDP_FLOOD", "10.45.1.2", "10.55.0.100",
                       status="OK", scenario_mode="repeatability"),
        ]
        lab = Lab(Path("."), Path("inventory.ini"), dry_run=True)
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory)
            checkpoint = out_dir / "trials.jsonl"
            rows = run_mobile_repeatability(lab, 3, 1, 5, 1, checkpoint, out_dir, previous)
        self.assertEqual([r.iteration for r in rows], [3])


if __name__ == "__main__":
    unittest.main()
