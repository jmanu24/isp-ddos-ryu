"""Execution variants are distinct from the immutable scientific traffic plan."""
def execution_options(cfg, profile=None):
    settings=cfg.get('execution',{})
    profile=profile or settings.get('default_profile','classic')
    if profile not in ('classic','coordinated','persistent'):
        raise ValueError('Unknown execution profile')
    interval=float(settings.get('metrics_interval_s',2))
    if not .2<=interval<=10: raise ValueError('Metrics interval must be 0.2–10 seconds')
    return dict(profile=profile,supervisor_per_vm=profile!='classic',metrics_batch=profile!='classic',
                metrics_interval_s=interval if profile!='classic' else 1,
                connection_reuse=profile=='persistent',preconnect_limit=8,
                idle_ttl_s=20,max_idle_per_key=2,max_idle_total=128,
                checkpoint_mode='immutable_snapshot_background_writer')
