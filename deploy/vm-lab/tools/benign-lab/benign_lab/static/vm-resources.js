'use strict';
let vmRows=[],vmCursor=0,vmKey='',vmBusy=false;
async function updateVMResources(){
 if(vmBusy||$('view-vm-resources').hidden)return;vmBusy=true;
 try{
  const historic=$('vm-source').value==='run',minutes=Number($('vm-minutes').value);
  if(historic&&!selectedRunId){$('vm-state').textContent='Selecciona una ejecución en Control de ejecución.';$('vm-cards').innerHTML='';return;}
  const key=(historic?selectedRunId:'live')+':'+minutes;if(key!==vmKey){vmRows=[];vmCursor=0;vmKey=key;}
  const result=await api(historic?`/runs/${selectedRunId}/vm-resources?after=${vmCursor}`:`/vm-resources?minutes=${minutes}&after=${vmCursor}`);vmRows.push(...result.items);vmCursor=result.cursor;
  const end=historic&&vmRows.length?Math.max(...vmRows.map(r=>r.timestamp)):Date.now()/1000,start=end-minutes*60;vmRows=vmRows.filter(r=>r.timestamp>=start);
  const names=[...new Set([...vmRows.map(r=>r.host.replace(/^ESXi\//,'')),...(result.hosts||[]).map(n=>n.name.replace(/^ESXi\//,''))])].sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
  const pct=v=>v==null?'—':v.toFixed(2)+' %';
  $('vm-cards').innerHTML=names.map(name=>{
   const rows=vmRows.filter(r=>r.host===name).sort((a,b)=>a.timestamp-b.timestamp),ready=vmRows.filter(r=>r.host==='ESXi/'+name).sort((a,b)=>a.timestamp-b.timestamp),last=rows[rows.length-1],lr=ready[ready.length-1];
   if($('vm-domain').value&&(last?.domain||lr?.domain)!==$('vm-domain').value)return '';
   const stale=!historic&&(!last||end-last.timestamp>20),rs=!historic&&(!lr||end-lr.timestamp>60);
   const processes=(last?.processes||[]).slice().sort((a,b)=>b.cpu_pct-a.cpu_pct).slice(0,10);
   return `<section class="panel traffic-card"><h2>${escape(name)}</h2><p class="help">${escape(last?.domain||lr?.domain||'')} · ${last?.logical_cpus||lr?.logical_cpus||'—'} vCPU</p><div class="traffic-values"><strong>CPU ${stale?'—':pct(last?.cpu_pct)}</strong><strong>RAM ${stale?'—':pct(last?.memory_pct)}</strong></div>${rows.length?`<svg viewBox="0 0 450 160" role="img" aria-label="CPU de la VM ${escape(name)}">${cpuSVG(rows,start,end)}</svg><p>Media CPU ${(rows.reduce((s,r)=>s+r.cpu_pct,0)/rows.length).toFixed(2)} % · máximo ${Math.max(...rows.map(r=>r.cpu_pct)).toFixed(2)} %</p>`:''}<p>I/O wait ${stale?'—':pct(last?.iowait_pct)} · steal ${stale?'—':pct(last?.steal_pct)}</p><p>CPU Ready por vCPU: ${rs?'—':pct(lr?.ready_vcpu_pct)} ${lr?'(ESXi)':'· no disponible'}</p>${ready.length?`<svg viewBox="0 0 450 160" role="img" aria-label="CPU Ready de ${escape(name)}">${cpuSVG(ready.filter(r=>r.ready_vcpu_pct!=null).map(r=>({...r,cpu_pct:r.ready_vcpu_pct})),start,end)}</svg>`:''}<p>RAM disponible ${last?human(last.memory_available_bytes):'—'} / ${last?human(last.memory_total_bytes):'—'}</p><details><summary>Disco y procesos (última muestra)</summary><p>Disco: contadores dentro del invitado, por dispositivo; no sumar capas.</p>${(last?.disks||[]).map(d=>`<p>${escape(d.device)} · lectura ${human(d.read_bytes_per_s)}/s · escritura ${human(d.write_bytes_per_s)}/s · ocupado ${pct(d.busy_pct)}</p>`).join('')||'<p>Sin métricas de disco.</p>'}<table><thead><tr><th>PID / proceso</th><th>CPU</th><th>RAM RSS</th><th>I/O lectura / escritura</th></tr></thead><tbody>${processes.map(p=>`<tr><td>${p.pid} · ${escape(p.name)}<small>${escape(p.namespace||'VM')} · PPID ${p.ppid}</small></td><td>${pct(p.cpu_pct)}</td><td>${human(p.rss_bytes)}</td><td>${p.read_bytes_per_s==null?'—':human(p.read_bytes_per_s)+'/s'} / ${p.write_bytes_per_s==null?'—':human(p.write_bytes_per_s)+'/s'}</td></tr>`).join('')}</tbody></table><p>Los 15 procesos con más CPU y los 8 con más RSS se conservan en el archivo. I/O por proceso puede no estar disponible por permisos.</p></details><p class="${stale?'stale':'muted'}">${stale?'Sin muestra reciente':historic?'Historial de ejecución':'Conectado'}${last?' · '+escape(new Date(last.timestamp*1000).toLocaleTimeString()):''}</p></section>`;
  }).join('')||'<div class="panel empty">Sin métricas para este origen o dominio.</div>';
  const connected=(result.hosts||[]).filter(n=>n.status==='connected'&&end-n.timestamp<60).length;
  $('vm-state').textContent=historic?'Recursos registrados durante la ejecución.':`${connected} colectores con muestras recientes. Las interrupciones aparecen como huecos.`;
 }catch(e){$('vm-state').textContent=e.message;}finally{vmBusy=false;}
}
for(const id of ['vm-source','vm-minutes','vm-domain'])$(id).onchange=()=>{if(id!=='vm-domain')vmKey='';updateVMResources();};document.querySelector('[data-view="vm-resources"]').addEventListener('click',updateVMResources);setInterval(updateVMResources,5000);
