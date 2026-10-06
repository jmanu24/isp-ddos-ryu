import io,json,time
from unittest.mock import patch
import pytest
from benign_lab.mobile_budget import restore_mobile_budgets

IPS={f'ue{i}':f'10.45.1.{i+1}' for i in range(1,6)}
class Response(io.BytesIO):
 def __init__(self,value,status=200):super().__init__(json.dumps(value).encode());self.status=status
 def getcode(self):return self.status
class Backend:
 def __init__(self):
  self.sessions=[dict(ip=ip,imsi=str(10101234567800+i).zfill(15),kpm={'DRB.UEThpUl':0},kpm_updated_at=time.time()) for i,ip in enumerate(IPS.values())]
  self.enforced={};self.posts=[];self.accept=True;self.record=True
 def request(self,request,**kwargs):
  url=request.full_url if hasattr(request,'full_url') else request
  if url=='http://core/telemetry':return Response(dict(log_connected=True,kpm_connected=True,sessions=self.sessions))
  if url.endswith('/status'):return Response(dict(enforced=self.enforced))
  body=json.loads(request.data);self.posts.append(body)
  if self.record:self.enforced[body['imsi']]=dict(action='unblock',max_prb=100,attack_type=body['attack_type'],at=time.time(),e2_node='test-du')
  return Response(dict(accepted=self.accept),202)
def restore(backend,**kwargs):
 with patch('urllib.request.urlopen',backend.request):
  return restore_mobile_budgets('http://core/telemetry','http://ric',IPS,'run-test',confirmation_timeout=0,**kwargs)

def test_empty_registry_restores_every_configured_ue():
 b=Backend();result=restore(b)
 assert len(b.posts)==5 and all(p['action']=='unblock' for p in b.posts)
 assert result['initial_enforced_count']==0 and result['verified_count']==5
 assert result['ran_ack_verified'] is False
 assert all(i['actuator_record']['at']>=i['requested_at'] for i in result['identities'])

def test_extra_historical_entries_do_not_replace_expected_population():
 b=Backend();b.enforced['old-unrestricted']=dict(action='unblock',max_prb=100)
 assert restore(b)['verified_count']==5
 assert len(b.posts)==5

def test_missing_identity_fails_before_rc_commands():
 b=Backend();b.sessions.pop()
 with pytest.raises(RuntimeError,match='missing or ambiguous'):restore(b)
 assert not b.posts

def test_duplicate_imsi_rejected():
 b=Backend();b.sessions[1]['imsi']=b.sessions[0]['imsi']
 with pytest.raises(RuntimeError,match='duplicate IMSI'):restore(b)
 assert not b.posts

def test_stale_kpm_fails_before_commands():
 b=Backend();b.sessions[0]['kpm_updated_at']=time.time()-60
 with pytest.raises(RuntimeError,match='Recent identity-bound'):restore(b)
 assert not b.posts

def test_rejected_request_fails():
 b=Backend();b.accept=False
 with pytest.raises(RuntimeError,match='did not accept'):restore(b)

def test_old_registry_cannot_confirm_new_request():
 b=Backend();b.record=False
 for session in b.sessions:b.enforced[session['imsi']]=dict(action='unblock',max_prb=100,attack_type='BENIGN_BASELINE:run-test',at=time.time()-60)
 with pytest.raises(RuntimeError,match='fresh actuator confirmation'):restore(b)

def test_unprocessed_accepted_commands_fail():
 b=Backend();b.record=False
 with pytest.raises(RuntimeError,match='fresh actuator confirmation'):restore(b)
