"""Exercise the actual controller calibration branch without loading Ryu."""
import ast
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
import unittest

class CalibrationModeTest(unittest.TestCase):
    def test_keeps_telemetry_and_forwarding_without_actuation(self):
        tree=ast.parse(Path(__file__).with_name('ryu_controller_2.py').read_text())
        method=next(node for node in ast.walk(tree) if isinstance(node,ast.FunctionDef) and node.name=='_run_pipeline')
        module=ast.Module(body=[method],type_ignores=[])
        calls=[]
        namespace=dict(defaultdict=defaultdict,settings=SimpleNamespace(LAB_CALIBRATION_MODE=True),metrics=SimpleNamespace(update_domain_traffic=lambda *a,**k:calls.append('telemetry'),set_active_blocks_by_domain=lambda *a:None))
        exec(compile(module,'actual_controller_pipeline','exec'),namespace)
        event=SimpleNamespace(domain='enterprise',pps=100,bps=1000,src_ip='10.70.0.11')
        def forbidden():
            self.fail('Calibration must not enter mitigation processing')
        orchestrator=SimpleNamespace(active_block_counts_by_domain=lambda:{},validate=lambda events,detections:calls.append(('validate',events,detections)),check_unblocks=forbidden)
        instance=SimpleNamespace(all_adapters=[SimpleNamespace(domain_name='enterprise',collect=lambda:[event])],orchestrator=orchestrator,_known_active_block_domains=set(),correlator=SimpleNamespace(ingest=lambda events:calls.append('correlate'),correlate=lambda:['correlated']))
        namespace['_run_pipeline'](instance)
        self.assertIn('telemetry',calls)
        self.assertIn(('validate',['correlated'],[]),calls)

if __name__=='__main__':
    unittest.main()
