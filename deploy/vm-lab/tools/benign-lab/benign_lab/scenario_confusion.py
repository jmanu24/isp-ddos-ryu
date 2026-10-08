"""Conservative 5-second confusion matrix with verified attack identity."""
from .ground_truth import windows

def window_confusion(plan,run,records,domain_windows):
 from .detection_evaluation import affected
 counts=dict(FP=0,FN=0,VP=0,VN=0,unknown=0);rows=[];start=run.get('started_at');sources=set(run.get('attack_source_ips',[]))
 for w in windows(plan,run):
  relevant=[x for x in records if start is not None and start+w['start_s']<=x.get('timestamp',0)<start+w['end_s']]
  ds=[x for x in domain_windows if x['window']==w['window']]
  eligible=bool(run.get('pipeline')=='enabled' and run.get('mode')=='lab' and w['evaluation'] and w['label'] in ('BENIGN','ATTACK') and ds and all(x['covered'] for x in ds))
  gap=any(x.get('kind')=='capture_gap' and x.get('gap_start',x['timestamp']-5)<start+w['end_s'] and x.get('gap_end',x['timestamp'])>=start+w['start_s'] for x in records) if start is not None else True
  eligible=eligible and not gap
  if w['label']=='ATTACK':
   observed=set(ip for x in relevant if x.get('kind')=='cycle' and x.get('pipeline_active') for ips in x.get('observed_sources',{}).values() for ip in ips)
   eligible=eligible and bool(sources & observed)
   positive=any(x.get('kind')=='detection' and any(ip in sources for _,ip in affected(x.get('detection',{}))) for x in relevant)
  else:positive=any(x['detection_positive'] for x in ds)
  classification=('VP' if positive else 'FN') if eligible and w['label']=='ATTACK' else ('FP' if positive else 'VN') if eligible else 'unknown'
  counts[classification]+=1;rows.append(dict(window=w['window'],truth=w['label'],classification=classification))
 return dict(unit='global 5-second window',counts=counts,windows=rows,coverage_policy='All experimental domains covered; attack windows also require declared attacker IP observed in an active cycle. Missing evidence is UNKNOWN.',fpr=counts['FP']/(counts['FP']+counts['VN']) if counts['FP']+counts['VN'] else None,recall=counts['VP']/(counts['VP']+counts['FN']) if counts['VP']+counts['FN'] else None)
