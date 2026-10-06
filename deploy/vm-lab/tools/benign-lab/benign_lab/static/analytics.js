'use strict';
const analyticsState={catalog:[],selected:new Set(),report:null,detail:null};
const analysisNames={all:'Todos',mobile:'Mobile',fixed:'Fixed',enterprise:'Enterprise',peering:'Peering'};
const analysisReasons={plan_integrity:'Plan sin integridad verificada',event_evidence_incomplete:'Eventos incompletos',simulation:'Demostración',diagnostic:'Diagnóstico',incomplete_or_aborted:'Prueba parcial o abortada',no_traffic_start:'No inició tráfico',observation_incomplete:'Observación parcial'};
const anNumber=(n,d=2)=>n===null||n===undefined?'—':Number(n).toLocaleString('es-PE',{maximumFractionDigits:d,minimumFractionDigits:d});
const anDate=n=>n?new Intl.DateTimeFormat('es-PE',{timeZone:'America/Lima',dateStyle:'short',timeStyle:'short'}).format(new Date(n*1000)):'—';
const anPipeline=p=>p==='baseline'?'Sin pipeline':'Pipeline activo';
const anFiltered=()=>analyticsState.catalog.filter(r=>{
 const search=$('analysis-search').value.toLowerCase(),mode=$('analysis-mode').value,pipeline=$('analysis-pipeline').value,status=$('analysis-status').value;
 const scientific=r.purpose==='baseline_plan'||r.purpose==='domain_benchmark';
 if(!$('analysis-diagnostics').checked&&!scientific)return false;
 if(mode&&r.mode!==mode||pipeline&&r.pipeline!==pipeline||status==='valid'&&!r.eligible||status==='excluded'&&r.eligible)return false;
 if(search&&!`${r.id} ${r.seed} ${r.plan_hash} ${r.execution_profile}`.toLowerCase().includes(search))return false;
 const from=$('analysis-from').value,to=$('analysis-to').value;
 if(from&&r.created_at<Date.parse(from+'T00:00:00-05:00')/1000)return false;
 if(to&&r.created_at>Date.parse(to+'T23:59:59-05:00')/1000)return false;
 return true;
});
function renderAnalyticsCatalog(){
 const rows=anFiltered(),domain=$('analysis-domain').value;
 $('analysis-count').textContent=`${rows.length} ejecuciones visibles · ${analyticsState.selected.size} seleccionadas`;
 $('analysis-runs').innerHTML=rows.map(r=>{const m=r.metrics.find(x=>x.domain===domain)||r.metrics[0];return `<tr><td><input type="checkbox" data-analysis-select="${escape(r.id)}" ${analyticsState.selected.has(r.id)?'checked':''} aria-label="Seleccionar ${escape(r.id)}"></td><td><button class="text-button" data-analysis-detail="${escape(r.id)}">${escape(r.id)}</button><small>${anDate(r.created_at)} · Lima</small></td><td>${r.seed??'—'}<small>${escape(r.execution_profile||'Sin registro')}</small></td><td>${escape(r.scenario||'—')}<small>${anPipeline(r.pipeline)} · ${r.mode==='lab'?'Real':'Demo'}</small></td><td>${anNumber(m.delivery_pct)} %<small>${anNumber(m.mean_mbps)} Mbps</small></td><td>${m.failed}<small>de ${m.events} eventos</small></td><td><span class="badge ${r.eligible?'live':''}">${r.eligible?'Completa':escape(labels[r.status]||r.status)}</span><small>${r.eligible?'Estadística por grupo':escape(r.exclusion_reasons.map(x=>analysisReasons[x]||x).join(' · '))}</small></td><td><code>${escape(r.plan_hash?.slice(0,10)||'—')}</code><small>${r.imported?'ZIP importado':r.context?'Contexto capturado':'Contexto histórico parcial'}</small></td></tr>`;}).join('')||'<tr><td colspan="8" class="empty">No hay ejecuciones con estos filtros.</td></tr>';
 document.querySelectorAll('[data-analysis-select]').forEach(el=>el.onchange=()=>{el.checked?analyticsState.selected.add(el.dataset.analysisSelect):analyticsState.selected.delete(el.dataset.analysisSelect);$('analysis-count').textContent=`${rows.length} ejecuciones visibles · ${analyticsState.selected.size} seleccionadas`;});
 document.querySelectorAll('[data-analysis-detail]').forEach(el=>el.onclick=()=>loadAnalyticsDetail(el.dataset.analysisDetail).catch(e=>notice(e.message,true)));
}
async function loadAnalyticsCatalog(){
 $('analysis-state').textContent='Leyendo historial de resultados…';
 const value=await api('/analytics/catalog');analyticsState.catalog=value.items;
 const existing=new Set(value.items.map(x=>x.id));analyticsState.selected=new Set([...analyticsState.selected].filter(x=>existing.has(x)));
 $('analysis-total').textContent=value.counts.total;$('analysis-valid').textContent=value.counts.eligible;$('analysis-aborted').textContent=value.counts.aborted_before_traffic;$('analysis-demo').textContent=value.counts.diagnostics+value.counts.simulations;
 $('analysis-state').textContent='Historial guardado · las pruebas abortadas y de diagnóstico se separan de las repeticiones científicas.';renderAnalyticsCatalog();
}
function analysisBody(){return {run_ids:[...analyticsState.selected],domain:$('analysis-domain').value,metric:$('analysis-metric').value,precision:Number($('analysis-precision').value)};}
function analyticsGroupLabel(group,index){
 const row=analyticsState.report.runs.find(x=>x.group_id===group.group_id)?.run;
 return `G${index+1} · ${anPipeline(group.configuration.pipeline)} · ${row?.execution_profile||'—'} · ${group.configuration.benchmark||'4 dominios'} · ${group.configuration.duration}s`;
}
function renderAnalyticsReport(value){
 analyticsState.report=value;$('analysis-results').hidden=false;
 $('analysis-exclusions').textContent=value.excluded.length?`${value.excluded.length} ejecuciones seleccionadas quedan fuera de las medias: ${value.excluded.map(x=>x.id).join(', ')}.`:'Las ejecuciones seleccionadas se agrupan sin mezclar configuraciones diferentes.';
 $('analysis-groups').innerHTML=value.groups.map((g,i)=>{const s=g.statistics,c=s.ci95,b=s.seed_balanced;return `<article class="panel analysis-cohort"><h3>${escape(analyticsGroupLabel(g,i))}</h3><code>${g.group_id}</code><div class="metric-grid"><div><span>Ejecuciones / semillas</span><strong>${s.n_runs} / ${s.n_seeds}</strong></div><div><span>Media por semilla</span><strong>${anNumber(b.mean)} ${escape(value.unit)}</strong></div><div><span>SD entre semillas</span><strong>${anNumber(b.sd)} ${escape(value.unit)}</strong></div><div><span>IC 95 %</span><strong>${c?`${anNumber(c.low)}–${anNumber(c.high)}`:'No estimable'}</strong></div></div><p class="help">Mediana ${anNumber(b.median)} · rango ${anNumber(b.minimum)}–${anNumber(b.maximum)} · repeticiones por semilla ${s.repetition_balance.minimum}–${s.repetition_balance.maximum}.</p><p class="help">${c?`Semiancho observado ±${anNumber(c.half_width)}. Objetivo ±${anNumber(s.precision_target)}. Estimación piloto de semillas adicionales: ${s.additional_seeds_precision_approx??'—'}.`:(s.n_seeds<2?'Faltan semillas distintas para estimar variabilidad.':'Sin variación observada: no se afirma incertidumbre nula.')}</p>${g.warnings.length?'<p class="analysis-warning">Parte del contexto histórico no fue capturada. Esta comparación describe los parámetros registrados.</p>':''}<details><summary>Condiciones del grupo y repeticiones</summary><pre>${escape(JSON.stringify({configuration:g.configuration,seeds:s.seeds},null,2))}</pre></details></article>`;}).join('')||'<p class="empty">No hay ejecuciones elegibles para esta estadística.</p>';
 $('analysis-pairs').innerHTML=value.pairs.map(p=>`<tr><td>${escape(p.reference)}</td><td>${escape(p.comparison)}</td><td>${p.seed}</td><td>${anNumber(p.delta)} ${value.unit==='%'?'pp':escape(value.unit)}</td><td>${p.context_verified?'Par candidato con contexto registrado':'Diferencia descriptiva; paridad no verificada'}<small>${escape(p.differing_conditions.join(', '))}</small></td></tr>`).join('')||'<tr><td colspan="5" class="empty">No hay pares con el mismo plan y ejecución en esta selección.</td></tr>';
 $('analysis-paired-stats').textContent=value.group_comparisons.length?value.group_comparisons.map(x=>`Grupos ${x.reference_group} → ${x.comparison_group}: ${x.statistics.n_seeds} semillas pareadas; diferencia media ${anNumber(x.statistics.seed_balanced.mean)} ${value.unit==='%'?'pp':value.unit}; IC ${x.statistics.ci95?anNumber(x.statistics.ci95.low)+'–'+anNumber(x.statistics.ci95.high):'no estimable'}.`).join('\n'):'El efecto pareado se resume solo cuando las condiciones registradas difieren en pipeline o política y hay planes emparejados.';
 drawAnalyticsDistribution(value);$('analysis-download').disabled=false;
}
function drawAnalyticsDistribution(value){
 const svg=$('analysis-chart'),points=[];
 value.groups.forEach((g,i)=>g.statistics.seeds.forEach(seed=>{if(seed.mean!==null)points.push({group:i,seed:seed.seed,value:seed.mean});}));
 if(!points.length){svg.innerHTML='';return;}
 const W=1000,H=270,pad=55,min=Math.min(0,...points.map(x=>x.value)),max=Math.max(1,...points.map(x=>x.value))*1.08,y=v=>H-pad-(v-min)/(max-min)*(H-2*pad),x=i=>pad+(i+.5)*(W-2*pad)/Math.max(1,value.groups.length),colors=['#286fe8','#078b7d','#ac58cf','#d38b18'];
 let markup='';for(let i=0;i<=4;i++){const v=min+(max-min)*i/4;markup+=`<line x1="${pad}" x2="${W-pad}" y1="${y(v)}" y2="${y(v)}" stroke="#e5eaf2"/><text x="${pad-8}" y="${y(v)+4}" text-anchor="end" fill="#66748b" font-size="11">${anNumber(v,1)}</text>`;}
 value.groups.forEach((g,i)=>{markup+=`<text x="${x(i)}" y="${H-15}" text-anchor="middle" fill="#526079" font-size="12">G${i+1}</text>`;const mean=g.statistics.seed_balanced.mean;if(mean!==null)markup+=`<line x1="${x(i)-28}" x2="${x(i)+28}" y1="${y(mean)}" y2="${y(mean)}" stroke="${colors[i%4]}" stroke-width="3"/>`;});
 points.forEach((p,i)=>{markup+=`<circle cx="${x(p.group)+(i%5-2)*8}" cy="${y(p.value)}" r="5" fill="${colors[p.group%4]}" opacity=".8"><title>G${p.group+1}, semilla ${escape(p.seed)}: ${anNumber(p.value)} ${escape(value.unit)}</title></circle>`;});svg.innerHTML=markup;
}
function analyticsSeries(detail){
 const svg=$('analysis-series'),rows=detail.series.filter(x=>x.payload_mbps!==null);if(!rows.length){svg.innerHTML='';$('analysis-series-state').textContent='No hay serie de tráfico ejecutado disponible.';return;}
 const max=Math.max(1,...rows.flatMap(x=>[x.payload_mbps||0,x.planned_mbps||0])),duration=detail.run.duration_s,W=1000,H=240,pad=45,x=t=>pad+t/duration*(W-2*pad),y=v=>H-pad-v/max*(H-2*pad);
 const path=field=>rows.map((r,i)=>`${i?'L':'M'}${x(r.elapsed_s).toFixed(2)},${y(r[field]||0).toFixed(2)}`).join(' ');
 svg.innerHTML=`<path d="${path('planned_mbps')}" fill="none" stroke="#94a3b8" stroke-width="2" stroke-dasharray="5 4"/><path d="${path('payload_mbps')}" fill="none" stroke="#286fe8" stroke-width="2"/>`+Array.from({length:5},(_,i)=>`<text x="${x(duration*i/4)}" y="${H-12}" text-anchor="middle" fill="#66748b" font-size="11">${Math.round(duration*i/4)} s</text>`).join('');
 $('analysis-series-state').textContent=`Azul: payload por intervalo. Gris: carga nominal del plan. Máximo del eje: ${anNumber(max)} Mbps. Los huecos y el muestreo limitan la resolución.`;
}
async function loadAnalyticsDetail(id){
 $('analysis-inspector').hidden=false;$('analysis-inspector-title').textContent='Leyendo '+id;
 const detail=await api('/analytics/runs/'+id+'?domain='+$('analysis-domain').value);analyticsState.detail=detail;$('analysis-inspector-title').textContent=id;
 $('analysis-run-metadata').textContent=JSON.stringify({seed:detail.run.seed,plan_hash:detail.run.plan_hash,execution_hash:detail.run.execution_hash,pipeline:detail.run.pipeline,capacities:detail.run.capacity_mbps,context:detail.run.context,exclusions:detail.run.exclusion_reasons},null,2);
 $('analysis-resource-table').innerHTML=detail.resources.map(r=>`<tr><td>${escape(r.host)}<small>${escape(r.platform)}</small></td><td>${anNumber(r.cpu_mean_pct)} %</td><td>${anNumber(r.cpu_p95_pct)} %</td><td>${anNumber(r.ready_mean_pct)} %</td><td>${r.samples}</td></tr>`).join('')||'<tr><td colspan="5" class="empty">No hay recursos registrados para el período.</td></tr>';
 $('analysis-error-table').innerHTML=Object.entries(detail.selected_metric.error_types||{}).map(([name,count])=>`<tr><td>${escape(name)}</td><td>${count}</td></tr>`).join('')||'<tr><td colspan="2">Sin eventos fallidos registrados.</td></tr>';
 $('analysis-fp-detail').textContent=JSON.stringify({domains:detail.evaluation.domains,ip_changes:detail.evaluation.ip_changes,available:detail.evaluation.available},null,2);analyticsSeries(detail);
}
async function buildAnalyticsReport(){if(!analyticsState.selected.size)throw Error('Selecciona ejecuciones para comparar.');renderAnalyticsReport(await api('/analytics/report',analysisBody()));}
$('analysis-refresh').onclick=()=>loadAnalyticsCatalog().catch(e=>notice(e.message,true));
$('analysis-compare').onclick=()=>buildAnalyticsReport().catch(e=>notice(e.message,true));
$('analysis-select-visible').onclick=()=>{anFiltered().filter(x=>x.eligible).forEach(x=>analyticsState.selected.add(x.id));renderAnalyticsCatalog();};
$('analysis-clear').onclick=()=>{analyticsState.selected.clear();renderAnalyticsCatalog();};
for(const id of ['analysis-search','analysis-mode','analysis-pipeline','analysis-status','analysis-diagnostics','analysis-from','analysis-to'])$(id).oninput=renderAnalyticsCatalog;
$('analysis-domain').onchange=()=>{renderAnalyticsCatalog();if(analyticsState.detail)loadAnalyticsDetail(analyticsState.detail.run.id).catch(e=>notice(e.message,true));};
$('analysis-download').onclick=async()=>{try{const response=await fetch('/api/analytics/export',{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(analysisBody())});if(!response.ok)throw Error((await response.json()).detail||'No se pudo exportar');const url=URL.createObjectURL(await response.blob()),a=document.createElement('a');a.href=url;a.download='experimental_analytics.zip';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){notice(e.message,true);}};
$('analysis-import').onclick=()=>$('analysis-file').click();
$('analysis-file').onchange=async()=>{try{const file=$('analysis-file').files[0];if(!file)return;const response=await fetch('/api/analytics/import',{method:'POST',headers:{...(token?{Authorization:'Bearer '+token}:{})},body:file});if(!response.ok)throw Error((await response.json()).detail||'No se pudo importar');const value=await response.json();notice(value.duplicate?'La ejecución ya existe; no se cuenta dos veces.':'Archivo importado para análisis histórico.');await loadAnalyticsCatalog();}catch(e){notice(e.message,true);}finally{$('analysis-file').value='';}};
document.querySelector('[data-view="analytics"]').addEventListener('click',()=>{if(!analyticsState.catalog.length)loadAnalyticsCatalog().catch(e=>notice(e.message,true));});

if(typeof location!=='undefined'&&location.hash==='#analytics')document.querySelector('[data-view="analytics"]').click();
