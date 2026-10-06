"""Explicit restoration using live core identities and fresh actuator evidence."""
import json
import re
import time
import uuid
import urllib.request


def restore_mobile_budgets(core_url, ric_url, expected_ips, run_id,
                           http_timeout=3, confirmation_timeout=20, poll_interval=.5):
    if not expected_ips or len(set(expected_ips.values())) != len(expected_ips):
        raise RuntimeError('Mobile configuration requires distinct UE source IPs')
    def get(url):
        with urllib.request.urlopen(url, timeout=http_timeout) as response:
            return json.load(response)
    core=get(core_url)
    if core.get('log_connected') is not True or core.get('kpm_connected') is not True:
        raise RuntimeError('Core session identities or live KPM are unavailable')
    identities=[];seen=set()
    for name,ip in sorted(expected_ips.items()):
        matches=[s for s in core.get('sessions',[]) if s.get('ip')==ip]
        if len(matches)!=1:
            raise RuntimeError('Mobile identity missing or ambiguous for '+name+' / '+ip)
        session=matches[0];imsi=str(session.get('imsi',''))
        if not re.fullmatch(r'\d{15,16}',imsi) or imsi in seen:
            raise RuntimeError('Invalid or duplicate IMSI for '+name)
        updated=session.get('kpm_updated_at')
        if not isinstance(updated,(int,float)) or not 0<=time.time()-updated<=20 or not session.get('kpm'):
            raise RuntimeError('Recent identity-bound KPM missing for '+name)
        seen.add(imsi);identities.append(dict(ue=name,source_ip=ip,imsi=imsi))
    initial=get(ric_url+'/status')
    tag='BENIGN_BASELINE:'+run_id+':'+uuid.uuid4().hex
    for identity in identities:
        identity['requested_at']=time.time()
        request=urllib.request.Request(ric_url+'/rc',
            data=json.dumps(dict(imsi=identity['imsi'],action='unblock',attack_type=tag)).encode(),
            headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(request,timeout=http_timeout) as response:
            status=response.getcode();body=json.load(response)
        if status!=202 or body.get('accepted') is not True:
            raise RuntimeError('Actuator did not accept restoration for '+identity['ue'])
        identity.update(http_status=status,accepted=True)
    deadline=time.monotonic()+confirmation_timeout
    while True:
        snapshot=get(ric_url+'/status');enforced=snapshot.get('enforced',{})
        pending=[]
        for identity in identities:
            row=enforced.get(identity['imsi'],{})
            stamp=row.get('at')
            valid=(row.get('action')=='unblock' and row.get('max_prb')==100 and
                   row.get('attack_type')==tag and isinstance(stamp,(int,float)) and
                   identity['requested_at']-1<=stamp<=time.time()+1)
            if valid:identity['actuator_record']=dict(row)
            else:pending.append(identity['ue'])
        if not pending:
            return dict(method='active_core_identities_explicit_restore_v1',
                        expected_count=len(identities),verified_count=len(identities),
                        initial_enforced_count=len(initial.get('enforced',{})),
                        identities=identities,confirmation='fresh_actuator_state_after_dispatch',
                        ran_ack_verified=False,
                        clock_tolerance_s=1,request_tag=tag,limitation='Actuator state confirms processing/dispatch; no per-UE RAN acknowledgement or physical budget readback is exposed')
        if time.monotonic()>=deadline:
            raise RuntimeError('UE slice budget restoration lacks fresh actuator confirmation for: '+', '.join(pending))
        time.sleep(poll_interval)
