"""Read-only experimental analytics. Execution is the replicate; seed means are clusters."""
import collections,csv,hashlib,io,json,math,re,statistics,threading,time,zipfile
from pathlib import Path
from .planner import plan_hash as compute_plan_hash,validate
from .detection_evaluation import evaluate

T975=[12.706,4.303,3.182,2.776,2.571,2.447,2.365,2.306,2.262,2.228,2.201,2.179,2.160,2.145,2.131,2.120,2.110,2.101,2.093,2.086,2.080,2.074,2.069,2.064,2.060,2.056,2.052,2.048,2.045,2.042]
TERMINAL={'completed','completed_with_errors','failed','stopped','interrupted'}
DOMAINS=('mobile','fixed','enterprise','peering')
METRICS={'delivery_pct':('%','Entrega de cuota'),'mean_mbps':('Mbps','Payload medio'),'failed_pct':('%','Eventos fallidos'),'lateness_p95_ms':('ms','Retraso p95 al iniciar'),'detection_fpr_pct':('%','FP de detección'),'decision_fpr_pct':('%','FP de decisión')}
METHOD=dict(unit='execution',cluster='seed',mean='equal weight to each seed mean',confidence='two-sided Student t, df = independent seeds - 1; conservative df=30 cap',assumptions=['Independent seed means under comparable conditions','Approximate normality of seed means; no automatic normality validation','Events and windows are not independent experimental repeats'],sources=['https://www.itl.nist.gov/div898/handbook/eda/section3/eda352.htm','https://www.itl.nist.gov/div898/handbook/eda/section3/eda3672.htm','https://www.itl.nist.gov/div898/handbook/prc/section3/prc312.htm'])

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def finite(value):return isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value)
def percentile(values,p):
 values=sorted(x for x in values if finite(x))
 if not values:return None
 position=(len(values)-1)*p;a=int(position);b=min(a+1,len(values)-1);return values[a]+(values[b]-values[a])*(position-a)
def read_json(path,default=None):
 try:return json.loads(path.read_text(encoding='utf-8-sig'))
 except (OSError,ValueError):return default

def lines(path):
 if not path.exists():return
 with path.open(encoding='utf-8-sig') as f:
  for line in f:
   if not line.strip():continue
   try:yield json.loads(line)
   except ValueError:continue

def moments(values):
 values=[x for x in values if finite(x)];n=len(values)
 return dict(n=n,mean=statistics.mean(values) if n else None,sd=statistics.stdev(values) if n>1 else None,median=statistics.median(values) if n else None,p25=percentile(values,.25),p75=percentile(values,.75),minimum=min(values) if n else None,maximum=max(values) if n else None)

def seed_statistics(observations,precision=1):
 grouped=collections.defaultdict(list)
 for seed,value in observations:
  if finite(value):grouped[str(seed)].append(value)
 seed_rows=[dict(seed=seed,**moments(values)) for seed,values in sorted(grouped.items())]
 stats=moments([x['mean'] for x in seed_rows]);n=stats['n'];ci=None;reason='insufficient_seeds';additional=None
 if n>1 and stats['sd']>0:
  half=T975[min(n-1,30)-1]*stats['sd']/math.sqrt(n);ci=dict(low=stats['mean']-half,high=stats['mean']+half,half_width=half,level=.95,df=n-1,table_df=min(n-1,30));reason=None
  additional=max(0,math.ceil((1.96*stats['sd']/precision)**2)-n) if finite(precision) and precision>0 else None
 elif n>1:reason='no_observed_variance; zero-width certainty not asserted'
 return dict(n_runs=sum(x['n'] for x in seed_rows),n_seeds=n,seed_balanced=stats,run_weighted=moments([v for values in grouped.values() for v in values]),ci95=ci,ci_unavailable_reason=reason,seeds=seed_rows,repetition_balance=dict(minimum=min((x['n'] for x in seed_rows),default=0),maximum=max((x['n'] for x in seed_rows),default=0)),additional_seeds_precision_approx=additional,precision_target=precision)

def error_kind(message):
 text=(message or '').lower()
 if 'assign requested address' in text:return 'address_unavailable'
 if 'missed event deadline' in text:return 'missed_deadline'
 if 'deadline' in text:return 'deadline'
 if 'reset by peer' in text:return 'connection_reset'
 if 'run ended' in text:return 'run_aborted'
 if 'preflight' in text:return 'preflight'
 return 'other'

def topology(lab):
 keys=('adapter','host','namespace','interface','access_mode','python','port')
 return dict(nodes={name:{k:node[k] for k in keys if k in node} for name,node in lab.get('nodes',{}).items()},targets={name:{key:target[key] for key in ('host','tcp_port','udp_port','http_port') if key in target} for name,target in lab.get('targets',{}).items()},monitor=dict(interval_s=lab.get('traffic_monitor',{}).get('interval_s'),audit=lab.get('detection_audit',{}).get('enabled',False),ram_probes=sorted(n['name'] for n in lab.get('traffic_monitor',{}).get('nodes',[]) if n.get('bootstrap_probe'))))

class ExperimentalAnalytics:
 def __init__(self,data,manager):
  self.data=Path(data);self.manager=manager;self.imports=self.data/'analytics-imports';self.imports.mkdir(exist_ok=True);self.cache={};self.plan_cache={};self.detail_cache={};self.lock=threading.RLock();self.index_path=self.data/'analytics-index.json';self.code_hash=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
  saved=read_json(self.index_path,{})
  if saved.get('code_hash')==self.code_hash:self.cache={rid:(item['signature'],item['value']) for rid,item in saved.get('entries',{}).items()}
 def folders(self):
  found={rid:self.manager.folder(rid) for rid in self.manager.runs}
  for folder in self.imports.iterdir():
   if folder.is_dir() and (folder/'run.json').exists() and folder.name not in found:found[folder.name]=folder
  return found
 def folder(self,rid):
  if not isinstance(rid,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',rid):raise ValueError('Invalid execution identifier')
  folder=self.folders().get(rid)
  if folder is None:raise ValueError('Execution not found')
  return folder
 def fingerprint(self,folder,names):
  return tuple((name,p.stat().st_mtime_ns,p.stat().st_size) for name in names for p in [folder/name] if p.exists())
 def summary(self,rid):
  folder=self.folder(rid);signature=self.fingerprint(folder,['run.json','benign_plan.json','event_states.json','lab_snapshot.json','detection_evaluation.json'])
  live=self.manager.runs.get(rid);signature+=(('status',live.get('status'),live.get('elapsed_s')),) if live else ()
  signature=digest(signature)
  cached=self.cache.get(rid)
  if cached and cached[0]==signature:return cached[1]
  r=dict(live or read_json(folder/'run.json',{}));lab=read_json(folder/'lab_snapshot.json',{});states=self.manager.events.get(rid)
  plan_file=folder/'benign_plan.json'
  try:plan_bytes=plan_file.read_bytes();file_sha=hashlib.sha256(plan_bytes).hexdigest()
  except OSError:plan_bytes=b'{}';file_sha=None
  cached_plan=self.plan_cache.get(file_sha)
  if cached_plan:p=cached_plan
  else:
   
   try:p=json.loads(plan_bytes.decode('utf-8-sig'))
   except (ValueError,UnicodeError):p={}
   self.plan_cache[file_sha]=p
  if states is None:states=read_json(folder/'event_states.json',{})
  es=list(states.values()) if isinstance(states,dict) else (states or []);expected=p.get('events',[]);reasons=[];integrity='unverified'
  try:
   if p.get('plan_hash')==r.get('plan_hash') and file_sha and file_sha==r.get('plan_file_sha256'):integrity='verified'
   else:integrity='verified' if compute_plan_hash(p)==r.get('plan_hash') else 'mismatch'
  except (ValueError,KeyError,TypeError,OverflowError):integrity='invalid'
  if integrity!='verified':reasons.append('plan_integrity')
  if {e.get('event_id') for e in es}!={e.get('event_id') for e in expected}:reasons.append('event_evidence_incomplete')
  if r.get('mode')!='lab':reasons.append('simulation')
  if r.get('purpose','baseline_plan') not in ('baseline_plan','domain_benchmark'):reasons.append('diagnostic')
  if r.get('status') not in ('completed','completed_with_errors'):reasons.append('incomplete_or_aborted')
  if not finite(r.get('started_at')):reasons.append('no_traffic_start')
  if not finite(r.get('elapsed_s')) or r.get('elapsed_s',0)+.001<p.get('duration_s',math.inf):reasons.append('observation_incomplete')
  if any(not finite(e.get(field,0)) or e.get(field,0)<0 for e in es for field in ('bytes_tx','bytes_rx')):reasons.append('invalid_counters')
  if finite(r.get('started_at')) and finite(r.get('finished_at')) and r['finished_at']<r['started_at']:reasons.append('invalid_timestamps')
  result=[]
  for d in ('all',)+DOMAINS:
   subset=es if d=='all' else [e for e in es if e.get('domain')==d];planned_subset=expected if d=='all' else [e for e in expected if e.get('domain')==d]
   planned=sum(e.get('planned_bytes',0) for e in planned_subset);actual=sum((e.get(field,0) if finite(e.get(field,0)) and e.get(field,0)>=0 else 0) for e in subset for field in ('bytes_tx','bytes_rx'));counts=collections.Counter(e.get('status') for e in subset);lateness=[e['lateness_s']*1000 for e in subset if finite(e.get('lateness_s'))]
   result.append(dict(domain=d,events=len(planned_subset),completed=counts['completed'],failed=counts['failed'],planned_bytes=planned,actual_bytes=actual,delivery_pct=100*actual/planned if planned else None,mean_mbps=actual*8/p['duration_s']/1e6 if planned_subset and p.get('duration_s',0)>0 else None,offered_mean_mbps=planned*8/p['duration_s']/1e6 if planned_subset and p.get('duration_s',0)>0 else None,failed_pct=100*counts['failed']/len(planned_subset) if planned_subset else None,lateness_p95_ms=percentile(lateness,.95),lateness_samples=len(lateness),error_types=dict(collections.Counter(error_kind(e.get('error')) for e in subset if e.get('status')=='failed'))))
  value=dict(id=rid,created_at=r.get('created_at'),started_at=r.get('started_at'),status=r.get('status'),mode=r.get('mode'),scenario=r.get('scenario'),pipeline=r.get('pipeline'),purpose=r.get('purpose','baseline_plan'),benchmark_domain=r.get('benchmark_domain'),seed=r.get('seed',p.get('seed')),plan_hash=r.get('plan_hash'),execution_hash=r.get('execution_hash'),execution_profile=r.get('execution_profile'),duration_s=p.get('duration_s',r.get('duration_s')),warmup_s=p.get('warmup_s'),capacity_mbps=p.get('capacity_mbps'),profile_hash=p.get('profile_hash'),profile=p.get('profile'),eligible=not reasons,exclusion_reasons=reasons,integrity=integrity,metrics=result,error=r.get('error'),imported=folder.parent==self.imports,context=r.get('experiment_context'),topology_signature=digest(topology(lab)),topology=topology(lab),python_versions=sorted({a.get('python_version','unknown') for a in r.get('agents',{}).values()}),audit_available=(folder/'detection_events.jsonl').exists(),warnings=[])
  if not value['context']:value['warnings'].append('Physical transport and traffic code version were not explicitly captured')
  self.cache[rid]=(signature,value);return value
 def catalog(self):
  with self.lock:
   rows=[self.summary(rid) for rid in self.folders()]
   rows.sort(key=lambda r:r.get('created_at') or 0,reverse=True)
   entries={rid:dict(signature=item[0],value=item[1]) for rid,item in self.cache.items() if item[1]['status'] in TERMINAL}
   temp=self.index_path.with_suffix('.tmp');temp.write_text(json.dumps(dict(code_hash=self.code_hash,entries=entries)));temp.replace(self.index_path)
   return dict(items=rows,counts=dict(total=len(rows),eligible=sum(r['eligible'] for r in rows),aborted_before_traffic=sum(not finite(r.get('started_at')) for r in rows),diagnostics=sum('diagnostic' in r['exclusion_reasons'] for r in rows),simulations=sum(r['mode']=='simulation' for r in rows)),method=METHOD,generated_at=time.time())
 def detail(self,rid,domain='all'):
  with self.lock:
   folder=self.folder(rid);summary=self.summary(rid);signature=self.fingerprint(folder,['run.json','metrics.jsonl','vm_resources.jsonl','host_metrics.jsonl','detection_events.jsonl','interface_metrics.jsonl','event_states.json'])
   cached=self.detail_cache.get(rid)
   if cached and cached[0]==signature:base=cached[1]
   else:
    p=read_json(folder/'benign_plan.json',{});r=dict(self.manager.runs.get(rid) or read_json(folder/'run.json',{}));r['_lab']=read_json(folder/'lab_snapshot.json',{});states=self.manager.events.get(rid) or read_json(folder/'event_states.json',{});es=list(states.values()) if isinstance(states,dict) else states or []
    records=list(lines(folder/'detection_events.jsonl'));interfaces=list(lines(folder/'interface_metrics.jsonl')) if records else []
    evaluation=evaluate(p,r,records,interfaces,es) if p and r.get('started_at') is not None and summary['integrity']=='verified' else dict(available=False,domains=[],windows=[],ip_changes=[])
    metrics=list(lines(folder/'metrics.jsonl'));resource_groups=collections.defaultdict(list);start=r.get('started_at');end=start+r.get('elapsed_s',0) if finite(start) else None
    for filename in ['vm_resources.jsonl','host_metrics.jsonl']:
     for row in lines(folder/filename):
      if finite(start) and start<row.get('timestamp',0) and row.get('timestamp',0)-row.get('interval_s',5)<end:resource_groups[row.get('host','unknown')].append(row)
    resources=[];hardware={}
    for host,rows in sorted(resource_groups.items()):
     def weighted(field):
      pairs=[(x[field],max(0,min(x['timestamp'],end)-max(x['timestamp']-x.get('interval_s',5),start))) for x in rows if finite(x.get(field))]
      total=sum(w for _,w in pairs);return sum(v*w for v,w in pairs)/total if total else None
     cpus=sorted({x['logical_cpus'] for x in rows if finite(x.get('logical_cpus'))});memory=sorted({round(x['memory_total_bytes']/(64*1024**2))*64 for x in rows if finite(x.get('memory_total_bytes'))})
     if rows[0].get('platform')=='linux_guest':hardware[host]=dict(cpus=cpus,memory_mib=memory)
     resources.append(dict(host=host,platform=rows[0].get('platform'),samples=len(rows),cpu_mean_pct=weighted('cpu_pct'),cpu_p95_pct=percentile([x.get('cpu_pct') for x in rows],.95),ready_mean_pct=weighted('ready_vcpu_pct'),memory_mean_pct=weighted('memory_pct'),logical_cpus=cpus))
    if not hardware and 'Guest hardware evidence missing' not in summary['warnings']:summary['warnings'].append('Guest hardware evidence missing')
    if not evaluation.get('threshold_snapshots') and 'Detector policy evidence missing' not in summary['warnings']:summary['warnings'].append('Detector policy evidence missing')
    base=dict(summary=summary,evaluation=evaluation,resources=resources,hardware=hardware,metrics=metrics,plan=p,initial_cycles=[x for x in records if x.get('kind')=='cycle' and finite(start) and start<=x['timestamp']<start+5])
    if summary['status'] in TERMINAL:self.detail_cache[rid]=(signature,base)
    if len(self.detail_cache)>48:self.detail_cache.pop(next(iter(self.detail_cache)))
   payload=[dict(x) for x in base['summary']['metrics']]
   for item in payload:
    d=item['domain'];fp=[x for x in base['evaluation'].get('domains',[]) if d=='all' or x['domain']==d];n=sum(x['eligible_benign_windows'] for x in fp)
    item.update(detection_fpr_pct=100*sum(x['detection_fp'] for x in fp)/n if n else None,decision_fpr_pct=100*sum(x['decision_fp'] for x in fp)/n if n else None,eligible_benign_domain_windows=n,reported_restricted_seconds=sum(x['reported_restricted_seconds'] for x in fp))
   policy=base['evaluation'].get('threshold_snapshots',[]);policy_ids=sorted(x.get('hash','') for x in policy);recorded_context=base['summary'].get('context');context={k:v for k,v in recorded_context.items() if k not in ('captured_at','run_id')} if recorded_context else dict(provenance='legacy_unknown')
   first_cycles=base['initial_cycles']
   initial_state='not_recorded' if not first_cycles else ('reported_restricted' if any(any(v>0 for v in x.get('active_blocks',{}).values()) for x in first_cycles) else 'reported_clear')
   grouping=dict(initial_state=initial_state,profile=base['summary']['profile_hash'],capacity=base['summary']['capacity_mbps'],duration=base['summary']['duration_s'],warmup=base['summary']['warmup_s'],mode=base['summary']['mode'],scenario=base['summary']['scenario'],pipeline=base['summary']['pipeline'],purpose=base['summary']['purpose'],benchmark=base['summary']['benchmark_domain'],execution=base['summary']['execution_hash'],topology=base['summary']['topology_signature'],context=context,hardware=base['hardware'],policy=policy_ids,python=base['summary']['python_versions'])
   metric=next((x for x in payload if x['domain']==domain),payload[0]);series=[];previous=None;changes=[]
   for e in base['plan'].get('events',[]):
    if domain=='all' or e['domain']==domain:changes.extend([(e['start_s'],e['rate_bps']/1e6),(e['start_s']+e['duration_s'],-e['rate_bps']/1e6)])
   changes.sort();idx=0;planned=0
   for row in sorted(base['metrics'],key=lambda x:(x.get('elapsed_s',0),x.get('timestamp',0))):
    elapsed=row.get('elapsed_s',0)
    if not finite(elapsed) or elapsed>base['summary'].get('duration_s',0):continue
    while idx<len(changes) and changes[idx][0]<=elapsed:planned+=changes[idx][1];idx+=1
    part=row if domain=='all' else row.get('domains',{}).get(domain,{})
    total=part.get('bytes_tx',0)+part.get('bytes_rx',0);actual=None
    if previous and elapsed>previous[0]:actual=max(0,total-previous[1])*8/(elapsed-previous[0])/1e6
    if not previous or elapsed>previous[0]:series.append(dict(elapsed_s=elapsed,payload_mbps=actual,planned_mbps=max(0,planned),cumulative_bytes=total));previous=(elapsed,total)
   return dict(run=base['summary'],metrics=payload,selected_metric=metric,resources=base['resources'],evaluation=base['evaluation'],grouping=grouping,group_id=digest(grouping)[:16],series=series,hardware=base['hardware'])
 def report(self,ids,domain='all',metric='delivery_pct',precision=1):
  if not isinstance(domain,str) or not isinstance(metric,str) or domain not in ('all',)+DOMAINS or metric not in METRICS:raise ValueError('Unknown domain or metric')
  if not isinstance(ids,list) or any(not isinstance(rid,str) for rid in ids) or not 1<=len(ids)<=100 or len(set(ids))!=len(ids):raise ValueError('Select between 1 and 100 distinct executions')
  with self.lock:
   details=[self.detail(rid,domain) for rid in ids];groups=collections.defaultdict(list);excluded=[]
   for detail in details:
    if not detail['run']['eligible']:excluded.append(dict(id=detail['run']['id'],reasons=detail['run']['exclusion_reasons']));continue
    groups[detail['group_id']].append(detail)
   summaries=[]
   for group_id,items in groups.items():
    observations=[(x['run']['seed'],x['selected_metric'].get(metric)) for x in items];statistics_result=seed_statistics(observations,precision)
    summaries.append(dict(group_id=group_id,run_ids=[x['run']['id'] for x in items],configuration=items[0]['grouping'],statistics=statistics_result,warnings=sorted({w for x in items for w in x['run']['warnings']})))
   # Pair effects only within exact same materialized plan, execution and recorded context.
   pairs=[]
   for i,a in enumerate(details):
    for b in details[i+1:]:
     if not a['run']['eligible'] or not b['run']['eligible']:continue
     if a['run']['plan_hash']!=b['run']['plan_hash'] or a['run']['execution_hash']!=b['run']['execution_hash']:continue
     av=a['selected_metric'].get(metric);bv=b['selected_metric'].get(metric)
     if not finite(av) or not finite(bv):continue
     differences=[k for k in a['grouping'] if a['grouping'][k]!=b['grouping'][k]]
     verified=bool(a['run'].get('context') and b['run'].get('context') and a['hardware'] and b['hardware'] and len(differences)==1 and differences[0] in ('pipeline','policy'))
     pairs.append(dict(reference=a['run']['id'],comparison=b['run']['id'],seed=a['run']['seed'],delta=bv-av,differing_conditions=differences,context_verified=verified,scope='single-factor paired candidate' if verified else 'descriptive same-plan difference; comparability not fully verified'))
   group_comparisons=[]
   for i,ga in enumerate(summaries):
    for gb in summaries[i+1:]:
     a,b=ga,gb
     if a['configuration']['pipeline']=='enabled' and b['configuration']['pipeline']=='baseline':a,b=b,a
     differences=[key for key in a['configuration'] if a['configuration'][key]!=b['configuration'][key]]
     if len(differences)!=1 or differences[0] not in ('pipeline','policy'):continue
     left=collections.defaultdict(list);right=collections.defaultdict(list)
     for x in details:
      val=x['selected_metric'].get(metric)
      if not finite(val) or not x['run']['eligible']:continue
      key=(str(x['run']['seed']),x['run']['plan_hash'])
      if x['group_id']==a['group_id']:left[key].append(val)
      if x['group_id']==b['group_id']:right[key].append(val)
     matches=[dict(seed=key[0],plan_hash=key[1],n_reference=len(left[key]),n_comparison=len(right[key]),delta=statistics.mean(right[key])-statistics.mean(left[key])) for key in sorted(left.keys()&right.keys())]
     if matches:group_comparisons.append(dict(reference_group=a['group_id'],comparison_group=b['group_id'],factor=differences[0],matches=matches,statistics=seed_statistics([(x['seed'],x['delta']) for x in matches],precision),context_verified=all(x['run'].get('context') and x['hardware'] for x in details if x['group_id'] in (a['group_id'],b['group_id'])),scope='paired seed-mean differences, conditional on recorded comparability'))
   return dict(group_comparisons=group_comparisons,schema=1,domain=domain,metric=metric,unit=METRICS[metric][0],delta_unit='pp' if METRICS[metric][0]=='%' else METRICS[metric][0],metric_label=METRICS[metric][1],groups=summaries,excluded=excluded,runs=[dict(run=x['run'],metric=x['selected_metric'],resources=x['resources'],group_id=x['group_id']) for x in details],pairs=pairs,method=METHOD,generated_at=time.time(),warning='No pooling across distinct groups. Confidence intervals are model-based over seed means; they do not establish causality or treat events/windows as independent repeats.')
 def import_archive(self,raw):
  if len(raw)>32*1024**2:raise ValueError('ZIP exceeds 32 MiB')
  with zipfile.ZipFile(io.BytesIO(raw)) as archive:
   allowed={'run.json','benign_plan.json','event_states.json','lab_snapshot.json','metrics.jsonl','vm_resources.jsonl','host_metrics.jsonl','interface_metrics.jsonl','detection_events.jsonl','detection_evaluation.json','ground_truth_windows.csv','execution_mapping.json','execution_profile.json','logs.jsonl'}
   if any('/' in n or '\\' in n for n in archive.namelist()):raise ValueError('ZIP must contain flat exported data files')
   if len(archive.infolist())>100 or sum(x.file_size for x in archive.infolist())>256*1024**2:raise ValueError('Archive exceeds extraction limits')
   if any(n not in archive.namelist() for n in ['run.json','benign_plan.json','event_states.json']):raise ValueError('Missing experiment data')
   r=json.loads(archive.read('run.json'));p=json.loads(archive.read('benign_plan.json'));states=json.loads(archive.read('event_states.json'));validate(p)
   if not isinstance(r,dict) or not isinstance(states,dict) or any(not isinstance(e,dict) for e in states.values()):raise ValueError('Invalid execution evidence structure')
   if any(not finite(e.get(k,0)) or e.get(k,0)<0 for e in states.values() for k in ('bytes_tx','bytes_rx')):raise ValueError('Invalid byte counters')
   rid=r.get('id','')
   if not isinstance(rid,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',rid) or r.get('status') not in TERMINAL:raise ValueError('Only terminal exported executions can be imported')
   if r.get('plan_hash')!=p['plan_hash']:raise ValueError('Plan hash mismatch')
   for name in set(archive.namelist()) & allowed:
    if name.endswith('.jsonl'):
     for line in archive.read(name).decode('utf-8-sig').splitlines():
      if line.strip() and not isinstance(json.loads(line),dict):raise ValueError('Invalid telemetry record')
   existing=self.folders().get(rid)
   if existing:
    old=read_json(existing/'event_states.json',{});old_run=read_json(existing/'run.json',{})
    if digest(old)==digest(states) and old_run.get('plan_hash')==r['plan_hash']:return dict(id=rid,duplicate=True,imported=False)
    raise ValueError('Execution identifier already exists with different data')
   if len(set(archive.namelist()))!=len(archive.namelist()):raise ValueError('Duplicate archive filenames')
   folder=self.imports/rid;folder.mkdir()
   for name in allowed & set(archive.namelist()):(folder/name).write_bytes(archive.read(name))
   return dict(id=rid,duplicate=False,imported=True)

def csv_data(report):
 out=io.StringIO();fields=['run_id','seed','mode','scenario','pipeline','status','eligible','group_id','domain','metric','value','planned_bytes','actual_bytes','failed_events','eligible_benign_domain_windows']
 writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
 for item in report['runs']:
  r=item['run'];m=item['metric'];writer.writerow(dict(run_id=r['id'],seed=r['seed'],mode=r['mode'],scenario=r['scenario'],pipeline=r['pipeline'],status=r['status'],eligible=r['eligible'],group_id=item['group_id'],domain=report['domain'],metric=report['metric'],value=m.get(report['metric']),planned_bytes=m['planned_bytes'],actual_bytes=m['actual_bytes'],failed_events=m['failed'],eligible_benign_domain_windows=m.get('eligible_benign_domain_windows')))
 return out.getvalue()
