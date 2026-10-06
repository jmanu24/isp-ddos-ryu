import subprocess
from benign_lab.interface_probe import ipv4_addresses

def test_busybox_fallback_multiple_ipv4_and_peer_name(monkeypatch):
 def output(argv,**kwargs):
  if '-j' in argv:raise subprocess.CalledProcessError(1,argv)
  return b'2: eth1    inet 10.55.0.100/24 brd 10.55.0.255 scope global eth1\n3: eth2@eth0    inet 10.70.0.1/24 scope global eth2\n3: eth2@eth0    inet 10.70.0.2/24 scope global eth2\n'
 monkeypatch.setattr(subprocess,'check_output',output)
 assert ipv4_addresses()==({'eth1':['10.55.0.100'],'eth2':['10.70.0.1','10.70.0.2']},True)

def test_unavailable_addresses_are_unknown(monkeypatch):
 def fail(*args,**kwargs):raise subprocess.CalledProcessError(1,args[0])
 monkeypatch.setattr(subprocess,'check_output',fail)
 assert ipv4_addresses()==({},False)

def test_iproute_json_is_preferred(monkeypatch):
 monkeypatch.setattr(subprocess,'check_output',lambda *a,**kw:b'[{"ifname":"tun_srsue","addr_info":[{"family":"inet","local":"10.45.1.2"}]}]')
 assert ipv4_addresses()==({'tun_srsue':['10.45.1.2']},True)

def test_unparseable_text_not_empty_known(monkeypatch):
 def bad(argv,**kwargs):
  if '-j' in argv:raise subprocess.CalledProcessError(1,argv)
  return b'unexpected output\n'
 monkeypatch.setattr(subprocess,'check_output',bad)
 assert ipv4_addresses()==({},False)
