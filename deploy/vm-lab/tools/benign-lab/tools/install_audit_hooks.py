"""Add audit-only hooks to the installed controller, preserving local pipeline code."""
from pathlib import Path

def install(root):
    root=Path(root)
    p=root/'controller/ryu_controller_2.py';s=p.read_text()
    if 'from core.experiment_audit import' not in s:
        s=s.replace('import config.settings as settings','import config.settings as settings\nfrom dataclasses import asdict\nfrom core.experiment_audit import emit as audit_emit, thresholds as audit_thresholds')
        if '\nimport time\n' not in s:s='import time\n'+s
        needle='        # Stage 2 — correlate across domains';assert needle in s
        s=s.replace(needle,"""        audit_observed={}
        for event in all_events:
            if 0 <= time.time()-event.timestamp <= max(10,2*settings.COLLECT_INTERVAL):
                audit_observed.setdefault(event.domain,set()).add(event.src_ip)
        audit_sources={domain:sorted(sources) for domain,sources in audit_observed.items()}
        # Stage 2 — correlate across domains""")
        needle='            self.orchestrator.validate(correlated, [])\n            return';assert needle in s
        s=s.replace(needle,"            self.orchestrator.validate(correlated, [])\n            audit_emit(self.logger,'cycle',pipeline_active=False,observed_sources=audit_sources,thresholds=audit_thresholds(settings),active_blocks=block_counts)\n            return")
        marker=s.index('# Surface every NEW detection');index=s.index('        for d in detections:\n',marker)+len('        for d in detections:\n')
        s=s[:index]+"            audit_emit(self.logger,'detection',detection=asdict(d),thresholds=audit_thresholds(settings))\n"+s[index:]
        needle='        unblock_actions = openflow_unblock_actions + mobile_unblock_actions';assert needle in s
        s=s.replace(needle,"        audit_emit(self.logger,'cycle',pipeline_active=True,observed_sources=audit_sources,thresholds=audit_thresholds(settings),active_blocks=block_counts)\n        unblock_actions = openflow_unblock_actions + mobile_unblock_actions\n        for action in unblock_actions:\n            audit_emit(self.logger,'mitigation_release',action=asdict(action))")
        compile(s,str(p),'exec');p.write_text(s)
    p=root/'orchestration/controller.py';s=p.read_text()
    if 'from core.experiment_audit import' not in s:
        s='from dataclasses import asdict\nfrom core.experiment_audit import emit as audit_emit\n'+s
        needle='            if decision is None:\n                continue';assert needle in s
        s=s.replace(needle,"            audit_emit(self._logger,'decision',accepted=decision is not None,threshold=self._decision_engine.global_threshold,weights=self._decision_engine.weights,candidates=[dict(detection=asdict(d),effective_score=d.score*d.confidence*self._decision_engine.weights.get(d.attack_type,1.0)) for d in group])\n"+needle)
        needle='            for action in actions:\n                if self._dispatch(action):';assert needle in s
        s=s.replace(needle,"            for action in actions:\n                audit_emit(self._logger,'mitigation_attempt',action=asdict(action))\n                if self._dispatch(action):\n                    audit_emit(self._logger,'mitigation_issued',action=asdict(action),confirmation='backend_dispatch_returned_true')")
        compile(s,str(p),'exec');p.write_text(s)

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('root');a=p.parse_args();install(a.root)
