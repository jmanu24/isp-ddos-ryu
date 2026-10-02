import sys,json,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from webtool import govc_ops
class WorkstationRouting(unittest.TestCase):
 def test_tunnel_failure_never_starts_duplicate_esxi_vm(self):
  with patch.object(govc_ops.workstation_ops,'owns',return_value=True),patch.object(govc_ops.workstation_ops,'power',return_value=False),patch.object(govc_ops,'_govc') as origin:
   self.assertFalse(govc_ops.power('victim',True));origin.assert_not_called()
 def test_shutdown_goes_to_destination(self):
  with patch.object(govc_ops.workstation_ops,'owns',return_value=True),patch.object(govc_ops.workstation_ops,'power',return_value=True) as destination,patch.object(govc_ops,'_govc') as origin:
   self.assertTrue(govc_ops.power_off_clean('victim'));destination.assert_called_once_with('victim','shutdown');origin.assert_not_called()
 def test_destination_state_overrides_retained_original(self):
  from subprocess import CompletedProcess
  data={'virtualMachines':[{'name':'victim','summary':{'runtime':{'powerState':'poweredOff'}}}]}
  with patch.object(govc_ops,'_govc',return_value=CompletedProcess([],0,json.dumps(data))),patch.object(govc_ops.workstation_ops,'states',return_value={'victim':'poweredOn'}):
   self.assertEqual(govc_ops.power_states()['victim'],'poweredOn')
class GovcArguments(unittest.TestCase):
 def test_inventory_wildcard_is_not_a_shell_glob(self):
  from subprocess import CompletedProcess
  with patch.object(govc_ops.subprocess,'run',return_value=CompletedProcess([],0,'')) as run:
   govc_ops._govc(['vm.info','-json','*'])
   self.assertIn("'*'",run.call_args[0][0][-1])
 def test_native_power_off_uses_explicit_operation(self):
  from subprocess import CompletedProcess
  with patch.object(govc_ops.workstation_ops,'owns',return_value=False),patch.object(govc_ops,'_govc',return_value=CompletedProcess([],0,'')) as origin:
   self.assertTrue(govc_ops.power('ue',False));origin.assert_called_once_with(['vm.power','-off','ue'],timeout=30)

if __name__=='__main__':unittest.main()
