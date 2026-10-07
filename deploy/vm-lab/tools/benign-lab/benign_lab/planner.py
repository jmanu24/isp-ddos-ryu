"""Pure deterministic plan materialization. No clock or global RNG is used here."""
from __future__ import annotations
import copy
import hashlib
import json
import math
import random
from pathlib import Path
import yaml

DOMAINS = ('mobile', 'fixed', 'enterprise', 'peering')
SCALABLE = {'streaming', 'download', 'upload', 'cloud_file', 'file_transfer', 'calibration_bulk'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def plan_hash(plan):
    return digest({k: v for k, v in plan.items() if k != 'plan_hash'})


def rng_for(seed, domain):
    raw = hashlib.sha256(f'{seed}:{domain}:BENIGN_V1'.encode()).digest()
    return random.Random(int.from_bytes(raw[:8], 'big'))


def sample(rng, spec, default=1):
    if spec is None:
        return default
    if isinstance(spec, (float, int)):
        return spec
    kind = spec.get('distribution', 'uniform')
    if kind == 'fixed':
        return spec['value']
    if kind == 'uniform':
        return rng.uniform(spec['min'], spec['max'])
    if kind == 'uniform_integer':
        return rng.randint(spec['min'], spec['max'])
    if kind == 'exponential':
        return rng.expovariate(1 / spec['mean'])
    if kind == 'lognormal':
        return min(spec.get('maximum', math.inf), rng.lognormvariate(math.log(spec['median']), spec['sigma']))
    if kind == 'truncated_pareto':
        lo, hi, a = spec['minimum'], spec['maximum'], spec['alpha']
        return lo / (1 - rng.random() * (1 - (lo / hi) ** a)) ** (1 / a)
    raise ValueError(f'Unknown distribution: {kind}')


def choice(rng, items):
    keys = list(items)
    return rng.choices(keys, [items[k]['weight'] for k in keys], k=1)[0]


def load_profiles(folder):
    result = {n: yaml.safe_load((Path(folder) / f'{n}.yaml').read_text()) for n in ('common', *DOMAINS)}
    for n in DOMAINS:
        if result[n]['domain']['name'] != n:
            raise ValueError(f'Invalid domain profile {n}')
    return result


def _event(domain, source, dest, app, protocol, direction, start, duration, rate, packet=1200, special=False):
    return dict(domain=domain, source=source, destination=dest, application=app,
                protocol=protocol, wire_protocol='udp' if protocol == 'other' else protocol,
                direction=direction, start_s=round(start, 6), duration_s=round(round(start + duration, 6) - round(start, 6), 6),
                rate_fraction=rate, packet_size_bytes=int(max(28, min(1400, packet))),
                special=special, scalable=app in SCALABLE and not special, label='BENIGN')


def _population(domain, p):
    pop = p['population']
    if domain == 'mobile':
        return pop['users']
    if domain == 'enterprise':
        return pop['sites']
    ids = pop['identifiers']
    return [f"{ids['prefix']}{i}" for i in range(ids['start'], ids['end'] + 1)]


def regular_events(domain, p, common, rng, duration, capacity):
    events = []
    mix = p.get('state_machine', p.get('application_mix', p.get('session_mix')))
    def emit(source, dest, app, proto, direction, t, d, rate, packet=1200, special=False):
        d = min(d, duration - t)
        if t >= 0 and d >= .000001 and rate > 0:
            events.append(_event(domain, source, dest, app, proto, direction, t, d, rate, packet, special))
    for source in _population(domain, p):
        t = sample(rng, common['experiment']['start_jitter_s'])
        while t < duration:
            app = choice(rng, mix)
            spec = mix[app]
            d = max(.1, sample(rng, spec.get('duration_s'), 15))
            dest = 'victim-web'
            if domain == 'enterprise':
                routes = [r for r in p['communication_matrix'] if r['source'] == source and (not r.get('services') or app in r['services'])]
                if routes:
                    dest = rng.choices(routes, weights=[r['weight'] for r in routes])[0]['destination']
            ratio = p['directionality']['target_dl_ul_ratio']
            direction_spec = spec.get('direction', {})
            dlprob = direction_spec.get('dl_probability', direction_spec.get('download_probability', ratio / (1 + ratio)))
            direction = 'dl' if rng.random() < dlprob else 'ul'
            proto = spec.get('protocol', 'tcp')
            rate = sample(rng, spec.get('rate_fraction'), .02)
            packet = sample(rng, spec.get('packet_size_bytes'), 1200)
            if app == 'idle':
                t += d
                continue
            if app in ('web', 'http_https'):
                end = min(t + d, duration)
                while t < end:
                    size = sample(rng, spec['object_size_bytes'])
                    ed = max(.01, size * 8 / (capacity * 1e6 * rate))
                    emit(source, dest, app, 'http', direction, t, min(ed, end-t), rate)
                    t += ed + sample(rng, spec.get('think_time_s'), 1)
                t = max(t, end)
                continue
            if app == 'streaming':
                dl = sample(rng, spec['dl_rate_fraction'])
                ul = sample(rng, spec['ul_rate_fraction'])
                cursor, end = t, min(duration, t + d)
                cycle = spec.get('burst_cycle', {})
                while cursor < end:
                    on = min(end - cursor, sample(rng, cycle.get('on_s'), d))
                    emit(source, dest, app, 'tcp', 'dl', cursor, on, dl)
                    emit(source, dest, app, 'tcp', 'ul', cursor, on, ul)
                    cursor += on + (sample(rng, cycle['off_s']) if cycle.get('enabled') else 0)
            elif app in ('gaming', 'dns', 'background'):
                if app == 'background':
                    proto = rng.choice(spec['protocols'])
                interval = sample(rng, spec.get('packet_interval_ms'), 0) / 1000 if spec.get('packet_interval_ms') else sample(rng, spec.get('interval_s'), .05)
                rate = packet * 8 / interval / (capacity * 1e6)
                emit(source, dest, app, proto, direction, t, d, rate, packet)
                if spec.get('bidirectional'):
                    emit(source, dest, app, proto, 'ul' if direction == 'dl' else 'dl', t, d, rate, packet)
            else:
                size = None
                for key, factor in (('file_size_bytes', 1), ('file_size_mb', 1e6), ('object_size_kb', 1e3)):
                    if key in spec:
                        size = sample(rng, spec[key]) * factor
                if size is not None:
                    d = max(.01, size * 8 / (capacity * 1e6 * rate))
                if app == 'upload':
                    direction = 'ul'
                if app == 'download':
                    direction = 'dl'
                emit(source, dest, app, proto, direction, t, d, rate, packet)
                if spec.get('bidirectional'):
                    emit(source, dest, app, proto, 'ul' if direction == 'dl' else 'dl', t, d, rate, packet)
            t += d + sample(rng, spec.get('think_time_s'), 1)
    for special in p.get('special_benign_events', []):
        start = sample(rng, special['start_s'])
        source = special.get('source') or rng.choice(special['source_candidates'])
        emit(source, special.get('destination', 'victim-web'), special['name'], special['protocol'], special.get('direction', 'ul'), start,
             sample(rng, special['duration_s']), sample(rng, special['rate_fraction']), special=True)
    return events


def normalize(events, config, duration):
    """Scale only bulk rates, cap at every exact event boundary, then split rates."""
    marks = {}
    for i, e in enumerate(events):
        marks.setdefault(e['start_s'], []).append((i, 1))
        marks.setdefault(round(e['start_s'] + e['duration_s'], 6), []).append((i, -1))
    times, active, slices = sorted(marks), set(), []
    for idx, t in enumerate(times[:-1]):
        for i, sign in marks[t]:
            active.add(i) if sign == 1 else active.discard(i)
        end = times[idx + 1]
        fixed = sum(events[i]['rate_fraction'] for i in active if not events[i]['scalable'])
        scalable = sum(events[i]['rate_fraction'] for i in active if events[i]['scalable'])
        cap = config['benign_peak_load'] if any(events[i]['special'] for i in active) else config['normal_max_load']
        if fixed > cap + 1e-8:
            raise ValueError('Non-scalable traffic exceeds capacity cap; revise profile/capacity')
        slices.append((t, end, sorted(active), fixed, scalable, cap))
    def mean(k):
        return sum((b-a) * (f + min(s*k, max(0, cap-f))) for a,b,ids,f,s,cap in slices) / duration
    lo, hi = 0., 1e6
    target = config['target_mean_load']
    for _ in range(65):
        mid = (lo+hi)/2
        if mean(mid) < target:
            lo = mid
        else:
            hi = mid
    k = (lo+hi)/2
    result, tails = [], {}
    for a,b,ids,f,s,cap in slices:
        factor = min(k, max(0, cap-f)/s) if s else 1
        for i in ids:
            original = events[i]
            rate = original['rate_fraction'] * (factor if original['scalable'] else 1)
            if rate <= 1e-12:
                continue
            tail = tails.get(i)
            if tail is not None and abs(tail['start_s'] + tail['duration_s'] - a) < 1e-7 and abs(tail['rate_fraction'] - rate) < 1e-12:
                tail['duration_s'] = round(b - tail['start_s'], 6)
            else:
                e = dict(original, start_s=a, duration_s=round(b-a, 6), rate_fraction=rate, parent_event=i)
                tails[i] = e
                result.append(e)
                if len(result) > 100000:
                    raise ValueError('Normalized plan exceeds 100000 events')
    return result, mean(k)


def peering_events(p, common, rng, duration, capacity):
    step = p['rate_envelope']['interval_s']
    walk = p['rate_envelope']['load_fraction']
    peak = p['benign_peak']
    peakstart = sample(rng, peak['start_s']) if peak['enabled'] else duration
    peakend = peakstart + sample(rng, peak['duration_s'])
    peakload = sample(rng, peak['load_fraction'])
    bounds = sorted(set([float(t) for t in range(0, math.ceil(duration), step)] + [duration] + [t for t in (peakstart, peakend) if 0 < t < duration]))
    envelope, current = [], walk['initial']
    for a,b in zip(bounds, bounds[1:]):
        current = max(walk['minimum'], min(walk['maximum'], current + rng.gauss(0, walk['step_sigma'])))
        special = peakstart <= a < peakend
        envelope.append([a,b,peakload if special else current,special])
    # Center the random walk without exceeding its specified normal envelope.
    target = common['domains']['peering']['target_mean_load']
    lo, hi = 0., 10.
    for _ in range(60):
        k = (lo+hi)/2
        avg = sum((b-a)*(v if sp else max(walk['minimum'], min(walk['maximum'], v*k))) for a,b,v,sp in envelope)/duration
        if avg < target: lo = k
        else: hi = k
    events = []
    for a,b,value,special in envelope:
        value = value if special else max(walk['minimum'], min(walk['maximum'], value*(lo+hi)/2))
        count = int(sample(rng, p['concurrency']['active_flows']))
        protocols = list(p['protocol_mix_by_bytes'])
        slots = protocols + rng.choices(protocols, weights=list(p['protocol_mix_by_bytes'].values()), k=count-len(protocols))
        for slot, proto in enumerate(slots):
            rate = value * p['protocol_mix_by_bytes'][proto] / slots.count(proto)
            candidates = {k:v for k,v in p['flow_classes'].items() if v['protocol'] == proto}
            t = a
            while t < b - 1e-6:
                app = choice(rng, candidates)
                spec = candidates[app]
                d = min(b-t, max(.1, sample(rng, spec.get('duration_s'), b-a)))
                if 'payload_kb' in spec:
                    d = min(d, max(.01, sample(rng, spec['payload_kb'])*1000*8/(capacity*1e6*rate)))
                source = f"peer-flow{rng.randint(1, p['population']['flow_pool_size'])}"
                e = _event('peering', source, 'victim-web', app, proto, 'ul', t, d, rate,
                           sample(rng, spec.get('packet_size_bytes'), 1200), special)
                events.append(e)
                if len(events) > 100000:
                    raise ValueError('Plan exceeds 100000 events; reduce duration/capacity')
                t += d
    return events


def summarize(plan):
    stats = {}
    for domain in DOMAINS:
        es = [e for e in plan['events'] if e['domain'] == domain]
        marks = {}
        for e in es:
            marks[e['start_s']] = marks.get(e['start_s'], 0) + e['rate_fraction']
            end = round(e['start_s'] + e['duration_s'], 6)
            marks[end] = marks.get(end, 0) - e['rate_fraction']
        running = peak = 0
        for t in sorted(marks):
            running += marks[t]
            peak = max(peak, running)
        volumes = {}
        for e in es:
            volumes[e['protocol']] = volumes.get(e['protocol'], 0) + e['planned_bytes']
        total = sum(volumes.values())
        stats[domain] = dict(events=len(es), mean_load=sum(e['rate_fraction']*e['duration_s'] for e in es)/plan['duration_s'],
                             peak_load=peak, planned_bytes=total, protocol_bytes_fraction={k:v/total for k,v in volumes.items()} if total else {})
    return stats


def generate(profiles, seed=1, duration_s=None, capacities=None):
    p = copy.deepcopy(profiles)
    c = p['common']
    duration = float(duration_s or c['experiment']['duration_s'])
    if not 5 <= duration <= 3600 or not isinstance(seed, int):
        raise ValueError('Duration must be 5–3600 s; seed must be an integer')
    capacities = capacities or dict.fromkeys(DOMAINS, 100.)
    if set(capacities) != set(DOMAINS) or any(not isinstance(v,(int,float)) or not math.isfinite(v) or not .01 <= v <= 10000 for v in capacities.values()):
        raise ValueError('Specify capacity 0.01–10000 Mbps for all four domains')
    events, warnings = [], []
    for domain in DOMAINS:
        rng = rng_for(seed, domain)
        if domain == 'peering':
            es = peering_events(p[domain], c, rng, duration, capacities[domain])
        else:
            es = regular_events(domain, p[domain], c, rng, duration, capacities[domain])
            raw_events = es
            es, mean = normalize(es, c['domains'][domain], duration)
            target = c['domains'][domain]['target_mean_load']
            if mean < target*.8 and c.get('normalization', {}).get('supplement_bulk_when_sparse', False):
                ratio = p[domain]['directionality']['target_dl_ul_ratio']
                for source in _population(domain, p[domain]):
                    start = min((e['start_s'] for e in raw_events if e['source'] == source), default=0)
                    for direction, share in (('dl', ratio/(1+ratio)), ('ul', 1/(1+ratio))):
                        raw_events.append(_event(domain, source, 'victim-web', 'calibration_bulk', 'tcp', direction, start, duration-start, .001*share))
                es, mean = normalize(raw_events, c['domains'][domain], duration)
                warnings.append(f'{domain}: explicit calibration_bulk sessions added to reach the mean target within caps.')
            if abs(mean-target) > target*.2:
                warnings.append(f'{domain}: mean load {mean:.4f} outside ±20% target {target}; short or sparse plan')
        for i,e in enumerate(sorted(es, key=lambda x:(x['start_s'], x['source'], x['application'], x['direction']))):
            e['event_id'] = f'{domain}-{i:06d}'
            e['rate_fraction'] = round(e['rate_fraction'], 12)
            e['rate_bps'] = round(e['rate_fraction']*capacities[domain]*1e6, 6)
            e['planned_bytes'] = max(1, int(e['rate_bps']*e['duration_s']/8))
        events += es
    if duration < 530:
        warnings.append('Short plan: some legitimate bursts of the 600 s scenario may be absent.')
    warnings.append('Peering other (3%) is explicitly represented by a UDP surrogate; not a fifth IP protocol.')
    result = dict(schema_version=1, generator_version='1.0.0', profile='BENIGN_V1', seed=seed,
                  duration_s=duration, warmup_s=min(c['experiment']['warmup_s'], duration), window_s=5,
                  capacity_mbps=capacities, profile_hash=digest(p), profiles=p, warnings=warnings,
                  events=sorted(events, key=lambda e:(e['start_s'], e['domain'], e['event_id'])))
    result['summary'] = summarize(result)
    result['plan_hash'] = plan_hash(result)
    validate(result)
    return result


def generate_benchmark(profiles, seed, duration_s, capacities, domain):
    if domain not in DOMAINS: raise ValueError('Invalid benchmark domain')
    plan=generate(profiles,seed,duration_s,capacities)
    parent=plan['plan_hash']
    plan['events']=[e for e in plan['events'] if e['domain']==domain]
    if not plan['events']:raise ValueError('Benchmark has no events; increase duration')
    plan.update(purpose='domain_benchmark',benchmark_domain=domain,parent_plan_hash=parent)
    plan['warnings']=[w for w in plan['warnings'] if not any(w.startswith(d+':') for d in DOMAINS if d!=domain)]
    plan['warnings'].append('Single-domain BENIGN_V1 load benchmark; shared infrastructure and background load remain present.')
    plan['summary']=summarize(plan);plan['plan_hash']=plan_hash(plan);validate(plan)
    return plan


def validate(plan):
    if plan.get('schema_version') != 1 or plan.get('plan_hash') != plan_hash(plan):
        raise ValueError('Plan schema or SHA-256 invalid')
    if plan.get('profile') not in ('BENIGN_V1','BENIGN_BURST_MIN_V1') or plan.get('window_s') != 5:
        raise ValueError('Unsupported profile or window')
    if plan.get('profile')=='BENIGN_BURST_MIN_V1':
        params=plan.get('variant_parameters',{})
        if params.get('minimum_s') not in (1,2) or params!=plan['profiles'].get('burst_variant') or not isinstance(plan.get('parent_plan_hash'),str) or len(plan['parent_plan_hash'])!=64:
            raise ValueError('Invalid burst variant provenance or parameters')
    if plan.get('purpose')=='domain_benchmark':
        domain=plan.get('benchmark_domain')
        if domain not in DOMAINS or not plan['events'] or any(e['domain']!=domain for e in plan['events']):
            raise ValueError('Benchmark must contain events from exactly its selected domain')
    elif plan.get('benchmark_domain') is not None:
        raise ValueError('Benchmark domain requires domain_benchmark purpose')
    duration = plan['duration_s']
    if plan.get('profile_hash') != digest(plan['profiles']):
        raise ValueError('Profile hash mismatch')
    if not 0 <= plan['warmup_s'] <= duration:
        raise ValueError('Invalid warmup')
    if set(plan['capacity_mbps']) != set(DOMAINS) or any(not math.isfinite(v) or not .01 <= v <= 10000 for v in plan['capacity_mbps'].values()):
        raise ValueError('Invalid capacities')
    if not math.isfinite(duration) or not 5 <= duration <= 3600 or len(plan['events']) > 100000:
        raise ValueError('Invalid duration or event count')
    ids = set()
    for e in plan['events']:
        if e['event_id'] in ids or e['domain'] not in DOMAINS or e['label'] != 'BENIGN':
            raise ValueError('Invalid event identity/domain/label')
        ids.add(e['event_id'])
        if any(not isinstance(e[k], str) or not e[k] or len(e[k]) > 120 for k in ('event_id','source','destination','application')):
            raise ValueError('Invalid event names')
        for key in ('start_s', 'duration_s', 'rate_fraction', 'rate_bps', 'planned_bytes'):
            if not isinstance(e[key], (int,float)) or not math.isfinite(e[key]) or e[key] < 0:
                raise ValueError(f'Invalid {key}')
        if e['duration_s'] <= 0 or e['rate_bps'] <= 0 or e['rate_fraction'] <= 0 or e['start_s'] + e['duration_s'] > duration + .00001:
            raise ValueError('Event out of bounds')
        if e['protocol'] not in ('http','tcp','udp','icmp','other') or e['wire_protocol'] != ('udp' if e['protocol']=='other' else e['protocol']):
            raise ValueError('Unsupported wire protocol')
        if e['direction'] not in ('ul','dl') or not 28 <= e['packet_size_bytes'] <= 1400:
            raise ValueError('Invalid direction/packet size')
        expected = e['rate_fraction'] * plan['capacity_mbps'][e['domain']] * 1e6
        if abs(expected - e['rate_bps']) > .1 or abs(e['planned_bytes'] - expected*e['duration_s']/8) > 2:
            raise ValueError('Rate/volume inconsistency')
    stats = summarize(plan)
    for d in DOMAINS:
        if stats[d]['peak_load'] > plan['profiles']['common']['domains'][d]['benign_peak_load'] + 1e-6:
            raise ValueError(f'{d} exceeds peak capacity')
    return plan


def save_plan(plan, path):
    validate(plan)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = canonical(plan) + b'\n'
    if path.exists():
        if path.read_bytes() != blob:
            raise ValueError(f'Refusing to overwrite a different plan: {path}')
    else:
        with path.open('xb') as f:
            f.write(blob)
    return path
