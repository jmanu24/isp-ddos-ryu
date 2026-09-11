import json
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from core.mobile_models import FlowObservation, UeSessionBinding, KpmObservation
from correlation.mobile_context import MobileContext
from telemetry.mobile_adapter import MobileNetworkAdapter


class MobileIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.flow = FlowObservation('one', 'upf-n6', 'pdu-net', '10.45.0.2',
                                    '192.0.2.1', 4000, 443, 'TCP', 1000, 10, 98, 100)
        self.binding = UeSessionBinding('pdu-net', 'imsi-001010000000001', '1',
            '10.45.0.2', 90, 'core-export', ran_source='srsran', node_id='7:411')

    def test_kpm_not_counted_as_flow(self):
        kpm = KpmObservation('srsran', '7:411', 'DRB.UEThpUl', 999999, 'kbps', 99)
        event = MobileContext([self.binding], [kpm]).enrich(self.flow)
        self.assertEqual((event.bps, event.pps), (500, 5))
        self.assertEqual(event.flags['kpm_context'][0]['scope'], 'node')

    def test_ambiguous_and_expired_identity(self):
        for bindings in ([self.binding, self.binding], [replace(self.binding, valid_until=99)]):
            event = MobileContext(bindings).enrich(self.flow)
            self.assertEqual(event.flags['identity_status'], 'unresolved')
            self.assertIsNone(event.flags['ue_session'])

    def test_ue_kpm_requires_exact_identity(self):
        kpm = KpmObservation('srsran', '7:411', 'x', 1, '%', 99,
                             scope='ue', ue_id_type='gnb-du', ue_id='2')
        event = MobileContext([self.binding], [kpm]).enrich(self.flow)
        self.assertEqual(event.flags['kpm_context'], [])

    def test_snapshot_dedup_and_staleness(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'snapshot.json'
            p.write_text(json.dumps(dict(schema_version='tesis.mobile.observations/v1',
                generated_at=100, flows=[asdict(self.flow)], bindings=[asdict(self.binding)])))
            adapter = MobileNetworkAdapter(str(p), clock=lambda: 101)
            self.assertEqual(len(adapter.collect()), 1)
            self.assertEqual(adapter.collect(), [])
            self.assertTrue(adapter.is_connected())
            adapter.clock = lambda: 140
            self.assertEqual(adapter.collect(), [])
            self.assertFalse(adapter.is_connected())
            self.assertFalse(adapter.apply_mitigation(None))

    def test_invalid_flow(self):
        for flow in (replace(self.flow, bytes_count=-1), replace(self.flow, dst_ip='*'),
                     replace(self.flow, end=98)):
            with self.assertRaises(ValueError):
                MobileContext().enrich(flow)


if __name__ == '__main__':
    unittest.main()
