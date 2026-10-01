import math


def overlap(a,b,c,d):
    return max(0.,min(b,d)-max(a,c))


def windows(plan,run):
    result=[]
    elapsed=run.get('elapsed_s',0)
    final=run['status'] in ('completed','completed_with_errors','stopped','failed','interrupted')
    for i in range(math.ceil(plan['duration_s']/5)):
        a,b=i*5,min((i+1)*5,plan['duration_s'])
        expected=[x for x in run.get('attack_windows',[]) if overlap(a,b,x['start_s'],x['end_s'])>0]
        observed=[x for x in run.get('observed_attacks',[]) if overlap(a,b,x['start_s'],x.get('end_s') if x.get('end_s') is not None else elapsed)>0]
        complete=b<=elapsed+1e-6
        # Planned attack windows are never silently promoted to observed truth.
        label='ATTACK' if observed else ('UNKNOWN' if expected or not complete else 'BENIGN')
        result.append(dict(experiment_id=run['id'],plan_hash=plan['plan_hash'],window=i,start_s=a,end_s=b,
                           label=label,label_id={'BENIGN':0,'ATTACK':1,'UNKNOWN':-1}[label],
                           planned_label='ATTACK' if expected else 'BENIGN',
                           annotation_source='operator_external' if observed else ('schedule_unconfirmed' if expected else 'baseline'),
                           attack_names=';'.join(x['name'] for x in observed or expected),
                           observed_complete=complete,evaluation=complete and a>=plan['warmup_s'],
                           run_final=final))
    return result
