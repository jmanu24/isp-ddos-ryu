import copy
from benign_lab.runner import Manager

def test_terminal_metrics_are_cached_only_after_cleanup(tmp_path):
    m=Manager(tmp_path);rid='cleanup'
    m.runs[rid]=dict(id=rid,status='failed',finished_at=None,elapsed_s=0,duration_s=5)
    e=dict(domain='fixed',status='pending',rate_bps=8,bytes_tx=0,bytes_rx=0)
    m.events[rid]={'e':e};m.logs[rid]=[]
    assert m.snapshot(rid)['counts']=={'pending':1}
    e['status']='failed';m.runs[rid]['finished_at']=1
    assert m.snapshot(rid)['counts']=={'failed':1}
    # Caller mutations must not corrupt the retained terminal metrics.
    snap=m.snapshot(rid);snap['domains']['fixed']['counts'].clear()
    assert m.snapshot(rid)['domains']['fixed']['counts']=={'failed':1}
