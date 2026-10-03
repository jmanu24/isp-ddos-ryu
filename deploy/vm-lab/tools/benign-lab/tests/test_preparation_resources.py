import time
from fastapi.testclient import TestClient
from benign_lab.api import create_app

def test_host_resources_are_available_before_traffic_starts(tmp_path):
    app=create_app(tmp_path)
    with TestClient(app) as c:
        now=time.time();rid='preparation-test'
        app.state.manager.folder(rid).mkdir()
        app.state.manager.runs[rid]=dict(id=rid,mode='lab',status='preparing',created_at=now-1,started_at=None,finished_at=None)
        app.state.host_monitor.accept({'name':'control'},dict(timestamp=now,cpu_pct=12,interval_s=5))
        result=c.get('/api/runs/'+rid+'/resources')
        assert result.status_code==200
        assert result.json()['available']
        assert result.json()['items'][0]['host']=='control'
        assert app.state.manager.runs[rid]['started_at'] is None
        app.state.manager.runs.clear()
