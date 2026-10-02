'use strict';
let resourceRows=[],resourceCursor=0,resourceKey='',resourceBusy=false;
function cpuSVG(rows,start,end){
 const W=390,H=125,X=45,Y=12;let svg='',points=[],last=0;
 for(const pct of [0,50,100]){const y=Y+H-pct*H/100;svg+=`<line x1="${X}" x2="${X+W}" y1="${y}" y2="${y}" stroke="#e8edf4"/><text x="0" y="${y+4}">${pct}%</text>`;}
 const flush=()=>{if(points.length)svg+=`<polyline fill="none" stroke="#286fe8" stroke-width="2" points="${points.join(' ')}"/>`;points=[];};
 for(const r of rows){if(last&&r.timestamp-last>Math.max(15,r.interval_s*2.5))flush();const x=X+(r.timestamp-start)/Math.max(1,end-start)*W,y=Y+H-r.cpu_pct*H/100;points.push(`${x},${y}`);svg+=`<circle cx="${x}" cy="${y}" r="2" fill="#286fe8"><title>${escape(new Date(r.timestamp*1000).toLocaleTimeString())} · ${r.cpu_pct.toFixed(2)}%</title></circle>`;last=r.timestamp;}flush();return svg;
}
async function updateResources(){
 if(resourceBusy||$('view-resources').hidden)return;resourceBusy=true;
 try{
  const historic=$('resource-source').value==='run',minutes=Number($('resource-minutes').value);
  if(historic&&!selectedRunId){$('resource-state').textContent='Selecciona una ejecución en Control de ejecución.';$('resource-cards').innerHTML='';return;}
  const key=(historic?selectedRunId:'live')+':'+minutes;if(key!==resourceKey){resourceRows=[];resourceCursor=0;resourceKey=key;}
  const response=await api(historic?`/runs/${selectedRunId}/resources?after=${resourceCursor}`:`/resources?minutes=${minutes}&after=${resourceCursor}`);
  resourceRows.push(...response.items);resourceCursor=response.cursor;
  const end=historic&&resourceRows.length?Math.max(...resourceRows.map(r=>r.timestamp)):Date.now()/1000,start=end-minutes*60;resourceRows=resourceRows.filter(r=>r.timestamp>=start);
  const names=[...new Set([...resourceRows.map(r=>r.host),...(response.hosts||[]).map(n=>n.name)])];
  $('resource-cards').innerHTML=names.map(name=>{const rows=resourceRows.filter(r=>r.host===name).sort((a,b)=>a.timestamp-b.timestamp),last=rows[rows.length-1],state=(response.hosts||[]).find(n=>n.name===name),stale=!historic&&(!last||end-last.timestamp>Math.max(25,last.interval_s*3)||state?.status==='disconnected');const average=rows.length?rows.reduce((s,r)=>s+r.cpu_pct,0)/rows.length:0;
   return `<section class="panel traffic-card"><h2>${escape(name)}</h2><p class="help">${last?.platform==='esxi'?'Servidor ESXi':'PC Windows'} · CPU total del host</p><div class="traffic-values"><strong>${last&&!stale?last.cpu_pct.toFixed(2)+' %':'—'}</strong></div>${last?`<svg viewBox="0 0 450 160" role="img" aria-label="CPU de ${escape(name)}">${cpuSVG(rows,start,end)}</svg><p>Media ${average.toFixed(2)} % · máximo ${Math.max(...rows.map(r=>r.cpu_pct)).toFixed(2)} %</p><small>${last.logical_cpus} procesadores lógicos · intervalo ${last.interval_s.toFixed(1)} s · ${escape(new Date(last.timestamp*1000).toLocaleTimeString())}</small>`:''}<p class="${stale?'stale':'muted'}">${stale?'Sin muestra reciente':historic?'Historial de ejecución':'Conectado'}</p></section>`;
  }).join('')||'<div class="panel empty">Sin métricas de CPU registradas para este origen.</div>';
  $('resource-state').textContent=historic?'CPU registrada durante la ejecución.':response.enabled?'Monitoreo de ambos hosts activo.':'Monitoreo de hosts no configurado.';
 }catch(e){$('resource-state').textContent=e.message;}finally{resourceBusy=false;}
}
for(const id of ['resource-source','resource-minutes'])$(id).onchange=()=>{resourceKey='';updateResources();};
document.querySelector('[data-view="resources"]').addEventListener('click',updateResources);setInterval(updateResources,5000);
