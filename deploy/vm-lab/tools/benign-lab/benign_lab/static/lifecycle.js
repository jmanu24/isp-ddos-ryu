/* Persistent experiment queue and recoverable deletion. */
(()=>{
 const states={pending:'En espera',starting:'Preparando',running:'Ejecutando',completed:'Completada',failed:'Fallida',cancelled:'Cancelada',attention:'Requiere revisión'};
 let timer=null,batchBusy=false;
 const selected={run:new Set(),seed:new Set(),plan:new Set()};
 let available={run:[],seed:[],plan:[]};
 function request(){
  if(!plan||!Array.from($('plans').options).some(o=>o.value===plan.plan_hash))throw Error('Selecciona un plan de la biblioteca en Monitor');
  const mode=$('mode').value,benchmark=!!plan.benchmark_domain;
  if(!benchmark&&$('scenario').value!=='B0')throw Error('Las series automáticas requieren B0. Los ataques externos se ejecutan manualmente');
  return {plan_hash:plan.plan_hash,mode,scenario:'B0',pipeline:benchmark&&mode==='lab'?'baseline':$('pipeline').value,execution_profile:$('execution-profile').value,speed:mode==='lab'?1:Number($('speed').value),attack_windows:[]};
 }
 function summary(){try{const r=request();$('job-options').textContent=`Plan ${r.plan_hash.slice(0,12)} · semilla ${plan.seed} · ${plan.duration_s} s · ${r.mode} · pipeline ${r.pipeline} · ${r.execution_profile}. Repetir la misma semilla mide repetibilidad; no agrega semillas independientes.`;}catch(e){$('job-options').textContent=e.message;}}
 async function refresh(){
  summary();
  const [jobs,ps,rs]=await Promise.all([api('/jobs'),api('/plans'),api('/analytics/catalog')]);
  const allRuns=rs.items;
  available={run:allRuns.filter(r=>terminal(r.status)).map(r=>r.id),seed:[...new Set(ps.map(p=>String(p.seed)))],plan:ps.map(p=>p.plan_hash)};
  for(const kind of Object.keys(selected))for(const id of selected[kind])if(!available[kind].includes(id))selected[kind].delete(id);
  $('job-list').innerHTML=jobs.length?jobs.map(j=>`<div class="panel"><strong>${escape(states[j.status]||j.status)}</strong> · ${new Date(j.scheduled_at*1000).toLocaleString('es-PE',{timeZone:'America/Lima'})} Lima · ${j.run_ids.length}/${j.count} iniciadas · semilla del plan ${escape(j.request.plan_hash.slice(0,12))}<p>${escape(j.request.mode)} · ${escape(j.request.pipeline)} · pausa ${j.gap_s} s</p><p>${j.run_ids.map(id=>`<button data-job-run="${escape(id)}" class="text-button">${escape(id)}</button>`).join(' ')}</p>${j.error?`<p>${escape(j.error)}</p>`:''}${!['completed','failed','cancelled','attention'].includes(j.status)?`<button data-cancel-job="${j.id}" class="secondary" ${j.cancel_requested?'disabled':''}>${j.cancel_requested?'Cancelación solicitada':'Cancelar serie después de la prueba actual'}</button>`:''}</div>`).join(''):'<p>No hay series programadas.</p>';
  $('job-list').querySelectorAll('[data-cancel-job]').forEach(b=>b.onclick=()=>api('/jobs/'+b.dataset.cancelJob+'/cancel',{}).then(refresh).catch(e=>notice(e.message,true)));
  $('job-list').querySelectorAll('[data-job-run]').forEach(b=>b.onclick=()=>{document.querySelector('[data-view="monitor"]').click();loadRuns().then(()=>selectRun(b.dataset.jobRun)).catch(e=>notice(e.message,true));});
  $('delete-runs').innerHTML=allRuns.map(r=>`<div class="lifecycle-run"><div class="lifecycle-run-info"><label class="batch-choice"><input type="checkbox" data-batch-kind="run" data-batch-id="${escape(r.id)}" aria-label="Seleccionar prueba ${escape(r.id)}" ${selected.run.has(r.id)?'checked':''} ${terminal(r.status)?'':'disabled'}><strong>${escape(r.id)}</strong></label><small>Semilla ${r.seed} <span class="badge ${['failed','completed_with_errors','interrupted'].includes(r.status)?'error':''}">${escape(labels[r.status]||r.status)}</span>${r.imported?' · Importada':''}</small></div><div class="lifecycle-actions">${r.imported?'':`<button class="secondary" data-repeat-run="${escape(r.id)}">Repetir prueba</button>`}<button class="danger" data-delete-run="${escape(r.id)}" ${terminal(r.status)?'':'disabled'}>Retirar prueba</button></div></div>`).join('')||'<p>No hay pruebas.</p>';
  $('delete-runs').querySelectorAll('[data-repeat-run]').forEach(b=>b.onclick=async()=>{try{const r=await api('/runs/'+b.dataset.repeatRun);if(r.scenario!=='B0')throw Error('Las pruebas con ataques externos requieren ejecución manual');await loadPlans(r.plan_hash);if(!Array.from($('plans').options).some(o=>o.value===r.plan_hash))throw Error('Restaura el plan desde la papelera o impórtalo antes de repetir');resetRun();await selectPlan(r.plan_hash);$('plans').value=r.plan_hash;$('mode').value=r.mode;$('scenario').value=r.scenario;$('pipeline').value=r.pipeline;$('execution-profile').value=r.execution_profile||'classic';$('speed').value=r.speed;buttons();summary();$('job-count').focus();notice('Opciones copiadas. Elige cuántas repeticiones y cuándo ejecutarlas.');}catch(e){notice(e.message,true);}});
  $('delete-runs').querySelectorAll('[data-delete-run]').forEach(b=>b.onclick=async()=>{if(!confirm('Retirar del historial y de la analítica la prueba '+b.dataset.deleteRun+'? Sus archivos pasarán a la papelera.'))return;try{await api('/runs/'+b.dataset.deleteRun,{},'DELETE');if(selectedRunId===b.dataset.deleteRun)resetRun();await loadRuns();await refresh();notice('Prueba retirada; archivos recuperables en el nodo control.');}catch(e){notice(e.message,true);}});
  const seeds=[...new Set(ps.map(p=>p.seed))];
  $('delete-plans').innerHTML=seeds.map(seed=>`<div class="panel"><div class="lifecycle-seed-head"><div><label class="batch-choice"><input type="checkbox" data-batch-kind="seed" data-batch-id="${seed}" aria-label="Seleccionar semilla ${seed}" ${selected.seed.has(String(seed))?'checked':''}><strong>Semilla ${seed}</strong></label><p>${ps.filter(p=>p.seed===seed).length} planes guardados</p></div><button class="danger" data-delete-seed="${seed}">Retirar semilla</button></div>${ps.filter(p=>p.seed===seed).map(p=>`<div class="lifecycle-plan"><div class="lifecycle-plan-info"><label class="batch-choice"><input type="checkbox" data-batch-kind="plan" data-batch-id="${p.plan_hash}" aria-label="Seleccionar plan ${p.plan_hash.slice(0,16)}" ${selected.plan.has(p.plan_hash)?'checked':''}><code>${escape(p.plan_hash.slice(0,16))}</code></label><small>${p.duration_s} s · ${escape(p.benchmark_domain||'Todos los dominios')}</small></div><button class="text-button" data-delete-plan="${p.plan_hash}">Retirar plan</button></div>`).join('')}</div>`).join('')||'<p>No hay semillas en la biblioteca.</p>';
  async function remove(url,message){if(!confirm(message+' Las copias de planes incluidas en pruebas anteriores se conservan.'))return;await api(url,{},'DELETE');resetRun();await loadPlans();if(!Array.from($('plans').options).some(o=>o.value===plan?.plan_hash)){plan=null;buttons();}await refresh();notice('Retirado de la biblioteca; recuperable en la papelera.');}
  $('delete-plans').querySelectorAll('[data-delete-plan]').forEach(b=>b.onclick=()=>remove('/plans/'+b.dataset.deletePlan,'Retirar el plan '+b.dataset.deletePlan.slice(0,16)+'?').catch(e=>notice(e.message,true)));
  $('delete-plans').querySelectorAll('[data-delete-seed]').forEach(b=>b.onclick=()=>remove('/seeds/'+b.dataset.deleteSeed,'Retirar TODOS los planes de la semilla '+b.dataset.deleteSeed+'?').catch(e=>notice(e.message,true)));
  document.querySelectorAll('[data-batch-kind]').forEach(c=>c.onchange=()=>{const set=selected[c.dataset.batchKind];c.checked?set.add(c.dataset.batchId):set.delete(c.dataset.batchId);updateSelection();});
  updateSelection();

 }

 function updateSelection(){
  const n=selected.run.size+selected.seed.size+selected.plan.size;
  $('batch-count').textContent=`${selected.run.size} pruebas · ${selected.seed.size} semillas · ${selected.plan.size} planes individuales`;
  $('batch-delete').disabled=!n||batchBusy;
 }
 for(const kind of ['run','seed','plan'])$('batch-all-'+kind).onclick=()=>{for(const id of available[kind])selected[kind].add(id);document.querySelectorAll(`[data-batch-kind="${kind}"]`).forEach(c=>{if(!c.disabled)c.checked=true;});updateSelection();};
 $('batch-clear').onclick=()=>{Object.values(selected).forEach(s=>s.clear());document.querySelectorAll('[data-batch-kind]').forEach(c=>c.checked=false);updateSelection();};
 $('batch-delete').onclick=async()=>{
  const b=$('batch-delete');batchBusy=true;b.disabled=true;
  try{
   const body={run_ids:[...selected.run],seeds:[...selected.seed].map(Number),plan_hashes:[...selected.plan],dry_run:true};
   const preview=await api('/lifecycle/batch-delete',body),ready=preview.items.filter(r=>r.status==='ready');
   const blocked=preview.items.filter(r=>r.status!=='ready');
   if(!ready.length){notice('Ningún elemento puede retirarse: '+blocked.map(r=>r.detail).join('; '),true);return;}
   const nr=ready.filter(r=>r.kind==='run').length,np=ready.length-nr;
   if(!confirm(`Retirar ${nr} pruebas y ${np} planes de la biblioteca? ${blocked.length} elementos protegidos o no disponibles se conservarán. Los archivos irán a la papelera y los planes incorporados a pruebas conservadas permanecerán intactos.`))return;
   const result=await api('/lifecycle/batch-delete',{run_ids:ready.filter(r=>r.kind==='run').map(r=>r.id),plan_hashes:ready.filter(r=>r.kind==='plan').map(r=>r.id),dry_run:false});
   if(result.items.some(r=>r.status==='deleted')){resetRun();await loadRuns();await loadPlans();if(!Array.from($('plans').options).some(o=>o.value===plan?.plan_hash)){plan=null;buttons();}}
   Object.values(selected).forEach(s=>s.clear());await refresh();
   $('batch-result').textContent=`Retirados: ${result.counts.deleted}. Conservados: ${blocked.length+result.counts.blocked+result.counts.error}. `+[...blocked,...result.items.filter(r=>r.status!=='deleted')].map(r=>`${r.id}: ${r.detail}`).join(' · ');
   notice('Borrado por lote terminado. Los archivos retirados están en la papelera.');
  }catch(e){notice(e.message,true);}finally{batchBusy=false;updateSelection();}
 };
 async function create(scheduled){
  const body={run:request(),count:Number($('job-count').value),gap_s:Number($('job-gap').value)};
  if(scheduled){if(!$('job-date').value)throw Error('Selecciona fecha y hora de Lima');body.scheduled_at=new Date($('job-date').value+':00-05:00').getTime()/1000;if(!Number.isFinite(body.scheduled_at))throw Error('Fecha inválida');}
  await api('/jobs',body);notice(scheduled?'Serie programada en el nodo control.':'Serie añadida a la cola.');await refresh();
 }
 for(const [id,fn] of [['job-now',()=>create(false)],['job-schedule',()=>create(true)],['lifecycle-refresh',refresh]])$(id).onclick=async()=>{const b=$(id);b.disabled=true;try{await fn();}catch(e){notice(e.message,true);}finally{b.disabled=false;}};
 document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>{clearInterval(timer);timer=null;if(b.dataset.view==='lifecycle'){refresh().catch(e=>notice(e.message,true));timer=setInterval(()=>refresh().catch(e=>notice(e.message,true)),10000);}}));
})();
