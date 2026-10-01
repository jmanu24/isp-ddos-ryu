import copy
import hashlib
from pathlib import Path
import pytest
from benign_lab.planner import canonical,generate,load_profiles,validate,plan_hash,DOMAINS,save_plan
from benign_lab.config import ROOT
from benign_lab.ground_truth import windows

@pytest.fixture(scope='module')
def profiles(): return load_profiles(ROOT/'profiles')

@pytest.fixture(scope='module')
def plan(profiles): return generate(profiles,3)


def test_determinism_and_seed_independence(profiles,plan):
    assert canonical(plan)==canonical(generate(profiles,3))
    modified=copy.deepcopy(profiles)
    modified['enterprise']['session_mix']['ssh']['weight']=.9
    changed=generate(modified,3)
    assert [e for e in plan['events'] if e['domain']=='mobile']==[e for e in changed['events'] if e['domain']=='mobile']
    assert plan['plan_hash']!=generate(profiles,4)['plan_hash']


def test_exact_peaks_means_mix_and_specials(plan):
    for d in DOMAINS:
        cfg=plan['profiles']['common']['domains'][d]
        assert plan['summary'][d]['peak_load']<=cfg['benign_peak_load']+1e-6
        assert abs(plan['summary'][d]['mean_load']/cfg['target_mean_load']-1)<=.2
    for proto,target in plan['profiles']['peering']['protocol_mix_by_bytes'].items():
        assert abs(plan['summary']['peering']['protocol_bytes_fraction'][proto]-target)<1e-5
    assert any(e['special'] and e['domain']=='mobile' for e in plan['events'])
    assert any(e['destination']=='ent-site-2' and e['special'] for e in plan['events'])
    assert all(e['label']=='BENIGN' for e in plan['events'])


def test_hash_tamper_and_file_immutability(plan,tmp_path):
    original=copy.deepcopy(plan)
    original['events'][0]['rate_bps']+=1
    with pytest.raises(ValueError): validate(original)
    path=save_plan(plan,tmp_path/'benign_plan.json')
    assert hashlib.sha256(canonical({k:v for k,v in plan.items() if k!='plan_hash'})).hexdigest()==plan['plan_hash']
    assert path.read_bytes()==canonical(plan)+b'\n'
    altered=copy.deepcopy(plan)
    altered['seed']=17
    altered['plan_hash']=plan_hash(altered)
    with pytest.raises(ValueError): save_plan(altered,path)


def test_half_open_ground_truth(plan):
    r=dict(id='x',status='completed',elapsed_s=600,attack_windows=[dict(name='x',start_s=300,end_s=360)],observed_attacks=[])
    rows=windows(plan,r)
    assert len(rows)==120 and rows[59]['label']=='BENIGN' and rows[60]['label']=='UNKNOWN' and rows[72]['label']=='BENIGN'
    r['observed_attacks']=[dict(name='x',start_s=300,end_s=360)]
    rows=windows(plan,r)
    assert sum(x['label']=='ATTACK' for x in rows)==12
    assert not rows[11]['evaluation'] and rows[12]['evaluation']
    r.update(status='stopped',elapsed_s=302)
    assert not windows(plan,r)[60]['observed_complete']


def test_invalid_rates_even_with_recomputed_hash(plan):
    p=copy.deepcopy(plan)
    p['events'][0]['rate_bps']*=100
    p['plan_hash']=plan_hash(p)
    with pytest.raises(ValueError): validate(p)
