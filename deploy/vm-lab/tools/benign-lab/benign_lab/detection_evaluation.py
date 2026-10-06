"""Window-level evaluation with explicit coverage and attribution; no alert silence TNs."""
import collections,math,json
from .ground_truth import windows

ALIASES={'broadband':'fixed','bgp':'peering'}
def domain(value):return ALIASES.get(value,value)
def affected(item):
    sources=item.get('sources') or [item.get('src_ip','')]
    mapping=item.get('source_domains',{})
    return [(domain(mapping.get(ip,item.get('domain',''))),ip) for ip in sources if ip not in ('','*')]

def evaluate(plan,run,records,interfaces=None,event_states=None,decision_threshold=None):
    start=run.get('started_at');domains=sorted({e['domain'] for e in plan['events']});truth=windows(plan,run)
    ips={d:set() for d in domains}
    cfg=run.get('_lab',{})
    for node in cfg.get('nodes',{}).values():
        if node.get('source_ip'):
            for d in domains:
                if d=='fixed' and node.get('access_mode') in ('ipoe_namespace','ipoe_bound'):ips[d].add(node['source_ip'])
                elif d=='mobile' and node.get('namespace','').startswith('ue'):ips[d].add(node['source_ip'])
                elif d=='enterprise' and node.get('source_ip','').startswith('10.70.'):ips[d].add(node['source_ip'])
                elif d=='peering' and node.get('source_ip','').startswith('10.30.'):ips[d].add(node['source_ip'])
    # Resolve generic node patterns from execution evidence, avoiding topology-specific identity assumptions.
    source_domains={e['source']:e['domain'] for e in plan['events']};source_names=collections.defaultdict(set)
    for agent in run.get('agents',{}).values():
        ip=agent.get('context',{}).get('source_ip')
        for src in agent.get('sources',[]):
            if ip and src in source_domains:ips[source_domains[src]].add(ip);source_names[ip].add(src)
    targets={x.get('host') for x in cfg.get('targets',{}).values()}
    for d in domains:ips[d].update(x for x in targets if x)
    changes=[];previous={}
    for name,node in cfg.get('nodes',{}).items():
        if node.get('access_mode') in ('ipoe_namespace','ipoe_bound'):previous[(node.get('namespace',''),node.get('interface',''))]=[node.get('source_ip')] if node.get('source_ip') else []
    for row in sorted([x for x in (interfaces or []) if start is not None and start<=x.get('timestamp',0)<start+run.get('elapsed_s',0)],key=lambda x:x.get('timestamp',0)):
        key=(row.get('namespace',''),row.get('interface',''))
        if key not in previous or not row.get('ipv4_known'):continue
        current=sorted(row.get('ipv4_addresses',[]));old=sorted(previous[key])
        if 'fixed' in ips:ips['fixed'].update(current)
        if current!=old:
            related=[a for a in records if a.get('kind')=='mitigation_issued' and 0<=row['timestamp']-a['timestamp']<=30 and any(ip in old for _,ip in affected(a.get('action',{})))]
            changes.append(dict(timestamp=row['timestamp'],namespace=key[0],interface=key[1],previous_ips=old,current_ips=current,nearby_mitigation_ids=[a.get('event_id') for a in related],association='temporal_only'))
        previous[key]=current
    gaps=[x for x in records if x.get('kind')=='capture_gap']
    buckets=collections.defaultdict(list)
    if start is not None:
        for rec in records:
            elapsed=rec.get('timestamp',0)-start
            if 0<=elapsed<plan['duration_s']:buckets[int(elapsed//5)].append(rec)
    result=[];unattributed=set();impacted=set()
    for w in truth:
        records_here=buckets[w['window']]
        for d in domains:
            covered=any(x.get('kind')=='cycle' and x.get('pipeline_active') and set(x.get('observed_sources',{}).get(next((raw for raw in x.get('observed_sources',{}) if domain(raw)==d),d),[])) & ips[d] for x in records_here)
            detected=False;decided=False;issued=False
            for rec in records_here:
                kind=rec.get('kind')
                if kind=='detection':
                    subjects=affected(rec.get('detection',{}))
                    detected|=any(dd==d and ip in ips[d] for dd,ip in subjects)
                    if not any(dd in ips and ip in ips[dd] for dd,ip in subjects):unattributed.add(rec.get('event_id'))
                if kind=='decision':
                    candidates=rec.get('candidates',[])
                    if candidates:
                        winner=max(candidates,key=lambda c:c.get('effective_score',0))
                        positive=rec.get('accepted',False) if decision_threshold is None else winner.get('effective_score',0)>=decision_threshold
                        if any(dd==d and ip in ips[d] for dd,ip in affected(winner.get('detection',{}))):decided|=positive
                if kind=='mitigation_issued':
                    for dd,ip in affected(rec.get('action',{})):
                        if dd==d and ip in ips[d]:issued=True;impacted.add((d,ip))
            # Only observed, complete benign evaluation windows enter FP/TN denominators.
            eligible=bool(start is not None and run.get('mode')=='lab' and w['evaluation'] and w['label']=='BENIGN' and covered and not any(g.get('gap_start',g['timestamp']-5)<start+w['end_s'] and g.get('gap_end',g['timestamp'])>=start+w['start_s'] for g in gaps))
            restricted=any(x.get('kind')=='cycle' and x.get('pipeline_active') and any(domain(dd)==d and count>0 for dd,count in x.get('active_blocks',{}).items()) for x in records_here)
            result.append(dict(window=w['window'],start_s=w['start_s'],end_s=w['end_s'],domain=d,truth=w['label'],covered=bool(covered),eligible=eligible,detection_positive=detected,decision_positive=decided,mitigation_issued=issued,controller_reports_restriction=restricted,classification=('FP' if detected else 'TN') if eligible else 'UNKNOWN_OR_EXCLUDED'))
    summaries=[]
    for d in domains:
        a=[x for x in result if x['domain']==d];valid=[x for x in a if x['eligible']];fp=sum(x['detection_positive'] for x in valid);decision_fp=sum(x['decision_positive'] for x in valid)
        summaries.append(dict(domain=d,eligible_benign_windows=len(valid),detection_fp=fp,detection_tn=len(valid)-fp,detection_fpr=fp/len(valid) if valid else None,decision_fp=decision_fp,decision_tn=len(valid)-decision_fp,decision_fpr=decision_fp/len(valid) if valid else None,mitigation_positive_windows=sum(x['mitigation_issued'] for x in valid),reported_restricted_seconds=sum(5 for x in valid if x['controller_reports_restriction']),unknown_or_excluded_windows=len(a)-len(valid)))
    impact=[]
    for d in domains:
        es=[x for x in (event_states or []) if x['domain']==d];planned=sum(x['planned_bytes'] for x in es);actual=sum(x.get('bytes_tx',0)+x.get('bytes_rx',0) for x in es)
        impact.append(dict(domain=d,planned_bytes=planned,actual_bytes=actual,payload_pct=100*actual/planned if planned else None,failed=sum(x.get('status')=='failed' for x in es),address_errors=sum('assign requested address' in (x.get('error') or '') for x in es)))
    policies={x['thresholds']['hash']:x['thresholds'] for x in records if x.get('thresholds',{}).get('hash')}
    weights=next((x.get('weights') for x in reversed(records) if x.get('kind')=='decision'),None)
    return dict(threshold_snapshots=list(policies.values()),decision_weights=weights,policy_changed_within_capture=len(policies)>1,schema=1,unit='domain x 5-second benign evaluation window',attribution='experiment source IPs and targets; unmatched detections excluded',available=any(x['covered'] for x in result),pipeline=run.get('pipeline'),final=run.get('finished_at') is not None,domains=summaries,windows=result,ip_changes=changes,impacted_sources=[dict(domain=d,ip=ip,sources=sorted(source_names.get(ip,set()))) for d,ip in sorted(impacted)],unattributed_detection_records=len(unattributed),impact=impact,limitations=['Coverage requires fresh experiment-related telemetry in a pipeline-active cycle. Missing evidence is UNKNOWN, never TN.','Issued mitigation means backend dispatch returned true, not independent dataplane confirmation.','Restricted seconds use 5-second controller-state samples; they are not exact enforcement duration.','IP-change associations are temporal and do not prove causality.'],replay=dict(threshold=decision_threshold,scope='Static decision gate over recorded candidates; no counterfactual detector or network simulation') if decision_threshold is not None else None)

def calibration(datasets,training_ids,validation_ids,thresholds,minimum_windows=200,minimum_per_domain=20):
    if not training_ids or not validation_ids or set(training_ids)&set(validation_ids):raise ValueError('Choose disjoint training and validation runs')
    for rid in training_ids+validation_ids:
        p,r,records,interfaces,events=datasets[rid]
        if r.get('purpose','baseline_plan')!='baseline_plan':raise ValueError('Use scientific baseline plans, not instrumentation diagnostics')
        if r.get('scenario')!='B0' or r.get('pipeline')!='enabled' or r.get('status') not in ('completed','completed_with_errors'):raise ValueError('Calibration requires completed B0 runs with active detection')
        if not any(x.get('kind')=='cycle' and x.get('pipeline_active') for x in records):raise ValueError('No active evaluation cycles in '+rid)
    policies=set()
    for rid in training_ids+validation_ids:
        for record in datasets[rid][2]:
            if record.get('kind')!='cycle' or not record.get('pipeline_active'):continue
            snapshot=record.get('thresholds',{})
            if not snapshot.get('values'):raise ValueError('Detector configuration snapshot missing in '+rid)
            values={k:v for k,v in snapshot['values'].items() if k!='DECISION_THRESHOLD'}
            policies.add(json.dumps(dict(values=values,implementation=snapshot.get('implementation_hashes',{})),sort_keys=True))
    if len(policies)>1:raise ValueError('Training and validation must use the same detector configuration and implementation')
    train_seeds={datasets[x][0]['seed'] for x in training_ids};valid_seeds={datasets[x][0]['seed'] for x in validation_ids}
    if train_seeds&valid_seeds:raise ValueError('Use independent seeds for training and validation')
    out=[]
    for threshold in thresholds:
        if not math.isfinite(threshold) or threshold<=0:raise ValueError('Threshold must be positive and finite')
        evaluations=[evaluate(*datasets[rid],decision_threshold=threshold) for rid in training_ids]
        eligible=sum(x['eligible_benign_windows'] for v in evaluations for x in v['domains']);fp=sum(x['decision_fp'] for v in evaluations for x in v['domains'])
        by_domain={}
        for evaluation in evaluations:
            for row in evaluation['domains']:
                counts=by_domain.setdefault(row['domain'],dict(windows=0,fp=0));counts['windows']+=row['eligible_benign_windows'];counts['fp']+=row['decision_fp']
        per_domain={d:dict(eligible_benign_windows=c['windows'],decision_fp=c['fp'],decision_fpr=c['fp']/c['windows'] if c['windows'] else None) for d,c in by_domain.items()}
        coverage=eligible>=minimum_windows and all(c['windows']>=minimum_per_domain for c in by_domain.values())
        out.append(dict(threshold=threshold,training=dict(eligible_benign_domain_windows=eligible,decision_fp=fp,decision_fpr=fp/eligible if eligible else None,per_domain=per_domain,coverage_sufficient=coverage),validation=None))
    target=0.01
    acceptable=[x for x in out if x['training']['coverage_sufficient'] and x['training']['decision_fpr'] is not None and all(d['decision_fpr'] is not None and d['decision_fpr']<=target for d in x['training']['per_domain'].values())]
    selected=min(acceptable,key=lambda x:x['threshold']) if acceptable else None
    if selected:
        evaluations=[evaluate(*datasets[rid],decision_threshold=selected['threshold']) for rid in validation_ids]
        eligible=sum(x['eligible_benign_windows'] for v in evaluations for x in v['domains']);fp=sum(x['decision_fp'] for v in evaluations for x in v['domains'])
        selected['validation']=dict(eligible_benign_domain_windows=eligible,decision_fp=fp,decision_fpr=fp/eligible if eligible else None)
    return dict(results=out,recommended_threshold=selected['threshold'] if selected else None,target_decision_fpr=target,minimum_benign_domain_windows=minimum_windows,minimum_per_domain=minimum_per_domain,training_ids=training_ids,validation_ids=validation_ids,scope='Decision threshold replay only; candidate chosen using training alone',warning='Validation evaluates only the candidate selected from training. Do not reuse validation seeds for tuning. Benign runs estimate false positives; attack runs are still required to validate sensitivity. Mitigation changes the observed distribution; replay is not a prediction of future payload delivery.')
