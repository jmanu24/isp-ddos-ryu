'use strict';
let thresholdConfig=null;
const fpPercent=n=>n===null||n===undefined?'Sin evidencia':(100*n).toFixed(2)+' %';
async function refreshDetection(){
 const id=selectedRunId||run?.id;
 if(!id){$('fp-status').textContent='Selecciona una ejecución en el historial.';return;}
 const value=await api('/runs/'+id+'/detection-evaluation');
 $('fp-status').textContent=value.available?'Evidencia registrada · ventanas benignas de 5 s · warmup excluido':'Sin ciclos evaluados registrados. Las ventanas sin evidencia no se cuentan como aciertos.';
 $('fp-table').innerHTML=value.domains.map(d=>`<tr><td>${escape(d.domain)}</td><td>${d.eligible_benign_windows}</td><td>${d.unknown_or_excluded_windows}</td><td>${d.detection_fp} / ${fpPercent(d.detection_fpr)}</td><td>${d.decision_fp} / ${fpPercent(d.decision_fpr)}</td><td>${d.mitigation_positive_windows}</td><td>${d.reported_restricted_seconds} s</td></tr>`).join('');
 $('fp-impact').textContent=value.impact.map(d=>`${d.domain}: ${d.payload_pct===null?'—':d.payload_pct.toFixed(2)+' %'} de payload, ${d.address_errors} errores de IP`).join(' · ');
 $('fp-changes').textContent=JSON.stringify(value.ip_changes,null,2);
 $('fp-thresholds').textContent=JSON.stringify(value.threshold_snapshots||[],null,2);
 $('fp-policy').textContent='La detección, la decisión de mitigar y el déficit de tráfico son medidas diferentes. Las acciones registradas reflejan respuesta del backend; no prueban por sí solas el bloqueo efectivo. Cambios de IP: asociación temporal, no causalidad.';
}
async function loadThresholds(){
 thresholdConfig=await api('/calibration/thresholds');
 for(const name of ['DECISION_THRESHOLD','SYN_THRESHOLD','UDP_THRESHOLD','ICMP_THRESHOLD','DIST_PPS_THRESHOLD'])$('threshold-'+name).value=thresholdConfig.values[name];
 $('threshold-apply').disabled=false;
 $('threshold-status').textContent='Configuración del orquestador cargada. Aplicar reinicia el controlador y solo está permitido fuera de las pruebas.';
}
async function refreshCalibrationRuns(){
 const list=await api('/runs');const candidates=list.filter(r=>r.mode==='lab'&&r.scenario==='B0'&&r.pipeline==='enabled'&&r.purpose==='baseline_plan'&&r.audit_available&&['completed','completed_with_errors'].includes(r.status));
 if(!candidates.length)$('cal-warning').textContent='Aún no hay pruebas completas con evidencia nueva. Ejecuta B0 con pipeline activo y distintas semillas.';
 const options=candidates.map(r=>`<option value="${escape(r.id)}">${escape(r.id)} · semilla ${r.seed}</option>`).join('');$('cal-train').innerHTML=options;$('cal-validation').innerHTML=options;
}
$('fp-refresh').onclick=()=>refreshDetection().catch(e=>notice(e.message,true));
$('threshold-load').onclick=()=>loadThresholds().catch(e=>notice(e.message,true));
$('cal-load').onclick=()=>refreshCalibrationRuns().catch(e=>notice(e.message,true));
$('threshold-apply').onclick=async()=>{
 const button=$('threshold-apply');button.disabled=true;
 try{
  if(!thresholdConfig)throw Error('Carga los umbrales actuales primero.');
  const values=Object.fromEntries(['DECISION_THRESHOLD','SYN_THRESHOLD','UDP_THRESHOLD','ICMP_THRESHOLD','DIST_PPS_THRESHOLD'].map(n=>[n,Number($('threshold-'+n).value)]));
  if(Object.values(values).some(x=>!Number.isFinite(x)||x<=0))throw Error('Introduce umbrales positivos.');
  $('threshold-status').textContent='Aplicando configuración y esperando al controlador…';
  const applied=await api('/calibration/thresholds',{values,expected_hash:thresholdConfig.config_sha256});await loadThresholds();notice(applied.changed===false?'Sin cambios: el controlador conserva su configuración.':'Umbrales aplicados. Las pruebas siguientes usarán esta configuración.');
 }catch(e){notice(e.message,true);$('threshold-status').textContent=e.message;}finally{button.disabled=false;}
};
$('cal-replay').onclick=async()=>{
 try{
  const training_ids=[...$('cal-train').selectedOptions].map(x=>x.value),validation_ids=[...$('cal-validation').selectedOptions].map(x=>x.value);
  const thresholds=$('cal-candidates').value.split(',').map(x=>Number(x.trim()));
  const value=await api('/calibration/replay',{training_ids,validation_ids,thresholds});
  $('cal-result').innerHTML='<table><thead><tr><th>Umbral de decisión</th><th>FP en entrenamiento</th><th>FP en validación</th></tr></thead><tbody>'+value.results.map(r=>`<tr><td>${r.threshold}</td><td>${fpPercent(r.training.decision_fpr)}</td><td>${r.validation?fpPercent(r.validation.decision_fpr):'No consultada'}</td></tr>`).join('')+'</tbody></table>';
  $('cal-warning').textContent=(value.recommended_threshold===null?'Ningún candidato cumple el objetivo del 1 % en entrenamiento. ':`Candidato elegido solo con entrenamiento: ${value.recommended_threshold}. `)+'La validación se consulta solo para el candidato elegido en entrenamiento. No reutilices esas semillas para ajustar. El replay no predice la entrega de tráfico y todavía debes validar sensibilidad con ataques.';$('cal-download').disabled=false;
 }catch(e){notice(e.message,true);}
};
$('cal-download').onclick=()=>download('/calibration/download','threshold_calibration.json').catch(e=>notice(e.message,true));
setInterval(()=>{if(!document.hidden&&run&&!terminal(run.status)&&$('fp-panel').offsetParent!==null)refreshDetection().catch(()=>{});},10000);
