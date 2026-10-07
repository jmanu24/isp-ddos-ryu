"""Materialized duration-floor variants; original plans remain immutable."""
import copy,hashlib,math
from .planner import validate,summarize,plan_hash,digest,DOMAINS

class _Schedule:
    def __init__(self, events, duration):
        import bisect
        self.bisect=bisect;delta={0.:0.,float(duration):0.}
        for e in events:
            a=round(e['start_s'],6);b=round(a+e['duration_s'],6)
            delta[a]=delta.get(a,0)+e['rate_fraction'];delta[b]=delta.get(b,0)-e['rate_fraction']
        self.edges=sorted(delta);self.loads=[];load=0
        for edge in self.edges:load+=delta[edge];self.loads.append(load)
    def peak(self,a,b):
        i=self.bisect.bisect_right(self.edges,a)-1;j=self.bisect.bisect_left(self.edges,b)
        return max(self.loads[i:j] or [0])
    def add(self,a,b,rate):
        for edge in (a,b):
            i=self.bisect.bisect_left(self.edges,edge)
            if i==len(self.edges) or self.edges[i]!=edge:
                load=self.loads[i-1] if i else 0;self.edges.insert(i,edge);self.loads.insert(i,load)
        i=self.bisect.bisect_left(self.edges,a);j=self.bisect.bisect_left(self.edges,b)
        for k in range(i,j):self.loads[k]+=rate
    def place(self,anchor,width,rate,limit,duration):
        def valid(a):return self.peak(a,round(a+width,6))+rate<=limit+1e-8
        anchor=round(min(anchor,duration-width),6)
        if valid(anchor):return anchor
        candidates={round(max(0,min(duration-width,x)),6) for edge in self.edges for x in (edge,edge-width)}
        for a in sorted(candidates,key=lambda x:(abs(x-anchor),x)):
            if valid(a):return a
        raise ValueError('No feasible placement for minimum burst inside capacity bounds')


def duration_variant(parent, minimum_s, retain_fraction=.1):
    validate(parent)
    if parent['profile']!='BENIGN_V1':raise ValueError('Variant requires an original BENIGN_V1 plan')
    if minimum_s not in (1,2) or not 0<=retain_fraction<=1:raise ValueError('Supported minimums: 1 or 2 s')
    result=copy.deepcopy(parent)
    params=dict(version=1,minimum_s=minimum_s,retain_short_fraction=retain_fraction,selection='sha256_per_domain_parent_event_id_v1',quota_policy='preserve_bytes_reduce_rate',tail_policy='nearest_feasible_slot_inside_run')
    retained=set()
    for domain in DOMAINS:
        short=[e for e in parent['events'] if e['domain']==domain and e['wire_protocol'] in ('tcp','http') and e['duration_s']<2]
        ranked=sorted(short,key=lambda e:hashlib.sha256((parent['plan_hash']+':'+e['event_id']).encode()).hexdigest())
        retained.update(e['event_id'] for e in ranked[:math.ceil(len(short)*retain_fraction)])
    changed=[]
    for e in result['events']:
        if e['wire_protocol'] not in ('tcp','http') or e['duration_s']>=minimum_s or e['event_id'] in retained:continue
        original={k:e[k] for k in ('start_s','duration_s','rate_bps','rate_fraction')}
        e['duration_s']=minimum_s
        e['start_s']=min(e['start_s'],result['duration_s']-minimum_s)
        e['rate_bps']=e['planned_bytes']*8/minimum_s
        e['rate_fraction']=e['rate_bps']/(result['capacity_mbps'][e['domain']]*1e6)
        changed.append(dict(event_id=e['event_id'],original=original,new_start_s=e['start_s'],new_duration_s=minimum_s))
    changed_ids={x['event_id'] for x in changed}
    by_id={e['event_id']:e for e in result['events']}
    for domain in DOMAINS:
        fixed=[e for e in result['events'] if e['domain']==domain and e['event_id'] not in changed_ids]
        schedule=_Schedule(fixed,result['duration_s']);limit=result['profiles']['common']['domains'][domain]['benign_peak_load']
        pending=sorted([x for x in changed if by_id[x['event_id']]['domain']==domain],key=lambda x:(-by_id[x['event_id']]['rate_fraction'],x['original']['start_s'],x['event_id']))
        for item in pending:
            e=by_id[item['event_id']];e['start_s']=schedule.place(e['start_s'],minimum_s,e['rate_fraction'],limit,result['duration_s'])
            schedule.add(e['start_s'],round(e['start_s']+minimum_s,6),e['rate_fraction']);item['new_start_s']=e['start_s']
    result.update(profile='BENIGN_BURST_MIN_V1',parent_plan_hash=parent['plan_hash'],variant_parameters=params,variant_changes=changed,retained_short_event_ids=sorted(retained))
    result['profiles']['burst_variant']=params
    result['profile_hash']=digest(result['profiles'])
    result['summary']=summarize(result)
    result['plan_hash']=plan_hash(result)
    validate(result)
    assert sum(e['planned_bytes'] for e in parent['events'])==sum(e['planned_bytes'] for e in result['events'])
    return result
