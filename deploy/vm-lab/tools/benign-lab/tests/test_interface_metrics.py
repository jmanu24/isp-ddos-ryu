import json,time
from benign_lab.interface_probe import rates
from benign_lab.interface_monitor import InterfaceMonitor

def test_reset_and_restart_do_not_create_bursts():
 old={'rx_bytes':1000000,'tx_bytes':2000000};new={'rx_bytes':10,'tx_bytes':20}
 assert rates(old,new,5)['rx_mbps'] is None
 assert rates(None,new,5)['tx_mbps'] is None
 assert rates(new,{'rx_bytes':625010,'tx_bytes':1250020},5)['tx_mbps']==2

def test_namespace_host_isolation_and_history(tmp_path):
 monitor=InterfaceMonitor(tmp_path,{'traffic_monitor':{'nodes':[]}})
 node=dict(name='ue2',domain='mobile',namespaces=['ue4','ue5'])
 now=time.time();monitor.accept(node,dict(timestamp=now,items=[dict(interface='ens160',namespace='',rx_bytes=0,tx_bytes=0),dict(interface='tun_srsue',namespace='ue4',rx_bytes=10,tx_bytes=20)]))
 monitor.accept(dict(name='ue',domain='mobile',namespaces=['ue1','ue2','ue3']),dict(timestamp=now,items=[dict(interface='tun_srsue',namespace='ue2',rx_bytes=30,tx_bytes=40)]))
 rows=monitor.rows(now-1,now+1)
 assert {r['element'] for r in rows}=={'ue2 (VM)','ue2','ue4'}
 assert len(monitor.rows(now-1,now+1,rows[0]['id']))==2
 assert monitor.rows(now+2,now+3)==[]
 monitor.db.close()

def test_ssh_password_is_not_in_arguments(tmp_path,monkeypatch):
 monitor=InterfaceMonitor(tmp_path,{})
 monkeypatch.setenv('BENIGN_SSH_PASSWORD','private-secret')
 argv=monitor.argv(dict(host='10.10.0.8',user='labadmin',known_hosts_file='/tmp/known',sudo=True,namespaces=['ue1']))
 assert 'private-secret' not in ' '.join(argv)
 assert 'StrictHostKeyChecking=yes' in argv
 monitor.db.close()
