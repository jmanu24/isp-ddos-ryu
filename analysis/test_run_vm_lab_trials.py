#!/usr/bin/env python3
"""Focused tests for statistical trial event correlation and CSV output."""

import csv
import tempfile
import unittest
from pathlib import Path

from run_vm_lab_trials import TrialResult, extract_result, parse_ts, write_outputs


class TrialParsingTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
