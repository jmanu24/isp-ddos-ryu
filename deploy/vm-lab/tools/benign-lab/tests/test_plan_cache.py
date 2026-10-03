import json
from fastapi.testclient import TestClient
from benign_lab.api import create_app

def test_cached_plan_is_revalidated_after_file_changes(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        p=c.post('/api/plans',json=dict(duration_s=5)).json();ph=p['plan_hash']
        assert c.get('/api/plans/'+ph).status_code==200
        assert c.get('/api/plans/'+ph).status_code==200
        path=tmp_path/'plans'/ (ph+'.json')
        p['seed']=999;path.write_text(json.dumps(p)+' ')
        result=c.get('/api/plans/'+ph)
        assert result.status_code==400
        assert 'SHA-256' in result.json()['detail']
