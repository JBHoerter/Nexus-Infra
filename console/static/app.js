'use strict';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '—').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const views = ['overview', 'workloads', 'storage', 'network', 'activity'];
let csrf = null, state = null, fetching = false, selectedAction = null;
const pending = new Map();
const bytes = n => n == null ? '—' : n >= 1073741824 ? (n/1073741824).toFixed(1)+' GiB' : (n/1048576).toFixed(0)+' MiB';
const pct = n => n == null ? '—' : n.toFixed(1)+'%';
const when = n => n ? new Date(n*1000).toLocaleTimeString() : 'Never';
const badge = (label, tone='') => `<span class="badge ${tone}">${esc(label)}</span>`;
function toast(message) { $('toast').textContent=message; $('toast').hidden=false; clearTimeout(toast.timer); toast.timer=setTimeout(()=>$('toast').hidden=true, 7000); }
async function api(path, body) {
  const response = await fetch('/console/api/v1'+path, {method:body===undefined?'GET':'POST', credentials:'same-origin', headers:body===undefined?{}:{'Content-Type':'application/json','X-Nexus-CSRF':csrf||''}, body:body===undefined?undefined:JSON.stringify(body), signal:AbortSignal.timeout(10000)});
  const data = await response.json();
  if (!response.ok) { const e=new Error(data.error || 'Request failed'); e.status=response.status; throw e; }
  return data;
}
function loginScreen() { csrf=null; state=null; pending.clear(); $('shell').hidden=true; $('login-screen').hidden=false; }
async function signedIn(session) { csrf=session.csrf; $('password').value=''; $('login-screen').hidden=true; $('shell').hidden=false; await refresh(); }
$('login-form').addEventListener('submit', async event => {
  event.preventDefault(); $('login-submit').disabled=true; $('login-error').textContent='';
  try { await signedIn(await api('/session',{password:$('password').value})); }
  catch(e) { $('login-error').textContent=e.message; }
  finally { $('login-submit').disabled=false; }
});
$('logout').onclick=async()=>{ try { await api('/logout',{}); loginScreen(); } catch(e) { toast(e.message); } };
$('refresh').onclick=()=>refresh();
window.addEventListener('hashchange',render);
document.addEventListener('visibilitychange',()=>{if(!document.hidden && csrf) refresh();});
function vms(host) { return (host.observation?.vms || host.inventory.vms).map(vm=>({...vm,host, state:host.observation?vm.state:'unknown'})); }
function meter(label, value, detail, blue=false) { return `<div><div class="meter-line"><span>${esc(label)}</span><strong>${esc(detail)}</strong></div><div class="meter ${blue?'blue':''}"><i style="width:${Math.min(100,Math.max(0,Number(value)||0))}%"></i></div></div>`; }
function page(title, subtitle) { return `<div class="page-head"><div><p class="eyebrow">${esc(state.clusterName)}</p><h1>${title}</h1><p class="muted">${subtitle}</p></div></div>`; }
function vmBadge(vm) { return vm.host.stale ? badge('Stale observation','warn') : badge(vm.state, vm.state==='running'?'':vm.state==='failed'?'bad':'warn'); }
function workloadTable(all) {
 return `<div class="panel"><div class="panel-top"><div><h2>Workload placement</h2><p class="panel-subtitle">Activated declarations alongside observed runtime state</p></div>${badge(all.length+' VMs','neutral')}</div><div class="table-wrap"><table><thead><tr><th>Workload / identity</th><th>Host</th><th>Live state</th><th>Allocation / observed use</th><th>Desired state</th><th>Controls</th></tr></thead><tbody>${all.map(vm=>{
 const key=vm.host.id+'/'+vm.id, busy=pending.has(key), enabled=vm.controllable && vm.host.online && !busy;
 const actions=vm.controllable ? ['start','stop','restart'].map(action=>`<button class="${action==='stop'?'stop':''}" data-action="${action}" data-host="${esc(vm.host.id)}" data-vm="${esc(vm.id)}" ${!enabled || (action==='start' && vm.state==='running') || (action==='stop' && vm.state==='stopped')?'disabled':''}>${action[0].toUpperCase()+action.slice(1)}</button>`).join('') : '<span class="protected">Protected infrastructure</span>';
 return `<tr><td><div class="vm-name"><i class="role-dot ${esc(vm.role)}"></i>${esc(vm.id)}</div><small>${esc(vm.role)} · ${esc(vm.ip)}</small></td><td>${esc(vm.host.id)}</td><td>${vmBadge(vm)}<small>${busy?'Action pending observation':vm.health?'HTTP '+esc(vm.health.state):'No service probe'}</small></td><td>${esc(vm.vcpu)} vCPU · ${esc(vm.memoryMiB)} MiB<small>${pct(vm.cpuPercent)} core CPU · ${bytes(vm.memoryBytes)} process memory</small></td><td>${vm.declared===false?'Undeclared':vm.autostart?'Autostart':'Manual start'}<small class="${vm.drift?'attention':''}">${vm.host.stale?'Comparison unavailable':vm.drift?'Runtime differs from declaration':'Matches activated declaration'}</small></td><td><div class="actions">${actions}</div></td></tr>`;
 }).join('')}</tbody></table></div></div>`;
}
function hostCard(host) {
 const o=host.observation, m=o?.metrics, ratio=m?100*m.memoryUsedBytes/m.memoryTotalBytes:null;
 return `<section class="panel ${host.stale?'stale':''}"><div class="panel-top"><div class="host-name"><div class="host-symbol">▣</div><div><h2>${esc(o?.hostname||host.inventory.hostname||host.id)}</h2><p class="panel-subtitle">${esc(host.id)} · ${esc(host.inventory.network.hostAddress)}</p></div></div>${badge(host.online?'Online':'Unreachable',host.online?'':'bad')}</div>${host.stale?'<p class="stale-warning">Host agent unavailable. Values below may be stale.</p>':''}<div class="host-machine">${esc(o?.machine.cpuModel||'Awaiting machine observation')}<br><span class="muted">${esc(o?.machine.architecture)} · ${esc(o?.machine.logicalCPUs)} logical CPUs</span></div><div class="host-metrics">${meter('CPU utilization',m?.cpuPercent,pct(m?.cpuPercent))}${meter('Memory utilization',ratio,m?bytes(m.memoryUsedBytes)+' / '+bytes(m.memoryTotalBytes):'—',true)}</div><div class="host-foot"><span>Uptime ${m?Math.floor(m.uptimeSeconds/3600)+'h '+Math.floor(m.uptimeSeconds%3600/60)+'m':'—'}</span><span>Load ${m?m.load.map(n=>n.toFixed(2)).join(' / '):'—'}</span><span>Seen ${when(host.lastSeen)}</span></div></section>`;
}
function overview(all) {
 const online=state.hosts.filter(h=>h.online).length, running=all.filter(v=>v.state==='running'&&!v.host.stale).length;
 const faults=all.filter(v=>!v.host.stale && (v.state!=='running'||v.health && v.health.state!=='healthy'||v.drift));
 const infraFault=state.hosts.some(h=>h.observation?.services.some(s=>s.state!=='active') || h.observation?.backends.some(b=>!b.mounted));
 const healthy=online===state.hosts.length && faults.length===0 && !infraFault;
 const volumes=all.reduce((n,v)=>n+(v.volumes||[]).length,0);
 return page('Cluster overview','Understand what is running, where it lives, and what needs attention.')+`<div class="stats"><div class="stat"><div class="stat-label">CLUSTER HEALTH</div><div class="stat-value">${healthy?'Operational':'Needs attention'}</div><div class="stat-note">${healthy?'All hosts, workloads and probes healthy':'Check host reachability and workload state'}</div></div><div class="stat"><div class="stat-label">PHYSICAL HOSTS</div><div class="stat-value">${online}<span> / ${state.hosts.length}</span></div><div class="stat-note">Online and reporting</div></div><div class="stat"><div class="stat-label">RUNNING WORKLOADS</div><div class="stat-value">${running}<span> / ${all.length}</span></div><div class="stat-note">${faults.length} workload discrepancies</div></div><div class="stat"><div class="stat-label">PERSISTENT ATTACHMENTS</div><div class="stat-value">${volumes}</div><div class="stat-note">Named storage, independent of VM lifecycle</div></div></div><div class="columns"><div>${state.hosts.map(hostCard).join('')}</div><section class="panel"><div class="panel-top"><div><h2>Infrastructure health</h2><p class="panel-subtitle">Host units and private HTTP probes</p></div></div>${state.hosts.map(h=>(h.observation?.services||h.inventory.services.map(id=>({id,state:'unknown'}))).map(s=>`<div class="health-item"><div>${esc(s.id)}<small>${esc(h.id)}</small></div>${badge(h.stale?'Unknown':s.state,h.stale?'warn':s.state==='active'?'':'bad')}</div>`).join('')).join('')}${all.filter(v=>v.healthUrl).map(v=>`<div class="health-item"><div>${esc(v.id)}<small>${esc(v.healthUrl)}</small></div>${badge(v.host.stale?'Unknown':v.health?.state||'Awaiting probe',v.host.stale?'warn':v.health?.state==='healthy'?'':'warn')}</div>`).join('')}</section></div>`+workloadTable(all)+`<p class="note">Resource figures come from the owning physical host. VM CPU is percent of one core; process memory includes hypervisor overhead.</p>`;
}
function storage(all) {
 return page('Persistent storage','Logical requests mapped to host-local backends. State outlives the VM.')+state.hosts.map(h=>(h.observation?.backends||h.inventory.backends).map(b=>`<section class="panel"><div class="panel-top"><div><h2>${esc(b.id)}</h2><p class="panel-subtitle">${esc(h.id)} · ${esc(b.kind)} · <span class="mono">${esc(b.mountPoint)}</span></p></div>${badge(h.stale?'Unknown':b.mounted?'Mounted':'Unavailable',h.stale?'warn':b.mounted?'':'bad')}</div><div class="storage-usage">${meter('Backend capacity',b.capacityBytes?100*b.usedBytes/b.capacityBytes:null,bytes(b.usedBytes)+' used / '+bytes(b.capacityBytes)+' total')}<p class="muted">${bytes(b.availableBytes)} available to non-root processes · shared capacity, no per-volume quota</p></div><div class="table-wrap"><table><thead><tr><th>Named request</th><th>Attached VM</th><th>Guest mount</th><th>Host backing directory</th></tr></thead><tbody>${all.filter(v=>v.host.id===h.id).flatMap(v=>(v.volumes||[]).filter(s=>s.backendId===b.id).map(s=>`<tr><td>${esc(s.id)}</td><td>${esc(v.id)}</td><td class="mono">${esc(s.mountPoint)}</td><td class="mono">${esc(s.source)}</td></tr>`)).join('')||'<tr><td colspan="4">System filesystem; no VM attachments.</td></tr>'}</tbody></table></div></section>`).join('')).join('')+'<p class="note">Directory-level usage is not scanned on every refresh. Values describe the backing filesystem, not reserved VM capacity.</p>';
}
function network(all) {
 return page('Network topology','Placement and traffic paths across the private cluster network.')+state.hosts.map(h=>{const n=h.inventory.network;return `<section class="panel"><div class="panel-top"><div><h2>${esc(h.id)}</h2><p class="panel-subtitle">${esc(n.hostAddress)} · ${esc(n.ingressEndpoint)}</p></div>${badge(h.online?'Agent connected':'Agent unreachable',h.online?'':'warn')}</div><div class="topology"><div class="fabric"><strong>${esc(n.bridge)}</strong><span>${esc(n.cidr)} · host ${esc(n.gateway)}</span></div><div class="vm-nodes">${all.filter(v=>v.host.id===h.id).map(v=>`<div class="vm-node"><i class="role-dot ${esc(v.role)}"></i><strong>${esc(v.id)}</strong><span>${esc(v.role)}</span><code>${esc(v.ip)}</code>${vmBadge(v)}</div>`).join('')}</div></div><div class="network-flows">${(n.flows||[]).map(f=>`<div class="flow"><strong>${esc(f.from)} → ${esc(f.to)}</strong><span>${esc(f.purpose)}</span></div>`).join('')}</div><details><summary>Observed host interfaces</summary><div class="table-wrap"><table><thead><tr><th>Interface</th><th>Link state</th><th>Addresses</th></tr></thead><tbody>${(h.observation?.interfaces||[]).filter(i=>i.name!=='lo').map(i=>`<tr><td>${esc(i.name)}</td><td>${esc(i.state)}</td><td class="mono">${esc(i.addresses.join(', '))}</td></tr>`).join('')}</tbody></table></div></details></section>`;}).join('')+'<p class="note">Topology expresses declared relationships; HTTP probes provide service reachability. Headscale coordinates peers and is not the general traffic path. Workload movement is not implemented.</p>';
}
function activity() {
 return page('Management activity','A persistent record of accepted requests and unconfirmed outcomes.')+`<section class="panel"><div class="panel-top"><h2>Recent actions</h2>${badge('Last 50','neutral')}</div>${state.events.length?state.events.map(e=>`<div class="activity-row"><div class="activity-icon">↻</div><div class="activity-main"><strong>${esc(e.action)} ${esc(e.vmId)}</strong><p>${esc(e.hostId)} · ${esc(e.result)}</p></div><time class="activity-time">${esc(new Date(e.time*1000).toLocaleString())}</time></div>`).join(''):'<div class="empty">No VM actions have been submitted yet.</div>'}</section><p class="note">Accepted means systemd accepted the request. Use workload observations to confirm the resulting state. Requests are never automatically retried.</p>`;
}
function render() {
 if(!state || !csrf) return;
 const view=views.includes(location.hash.slice(1))?location.hash.slice(1):'overview';
 document.querySelectorAll('nav a').forEach(a=>a.classList.toggle('active',a.dataset.view===view));
 $('breadcrumb').textContent=view[0].toUpperCase()+view.slice(1);
 const all=state.hosts.flatMap(vms);
 $('content').innerHTML=({overview:()=>overview(all),workloads:()=>page('Workloads','Explicit placement, bounded controls, and visible differences from desired state.')+workloadTable(all),storage:()=>storage(all),network:()=>network(all),activity})[view]();
 $('connection').textContent=state.hosts.every(h=>h.online)?'Live observations':'Partial / stale';
 $('connection').className='status-chip '+(state.hosts.every(h=>h.online)?'':'warn');
 $('updated').textContent='Cluster state fetched '+when(state.generatedAt);
}
$('content').addEventListener('click',event=>{
 const button=event.target.closest('button[data-action]'); if(!button || button.disabled) return;
 const vm=state.hosts.flatMap(vms).find(v=>v.host.id===button.dataset.host && v.id===button.dataset.vm);
 if(!vm) return;
 selectedAction={host:vm.host.id,vm:vm.id,action:button.dataset.action,activation:vm.activation};
 $('action-title').textContent=`${button.textContent} ${vm.id}?`;
 $('action-description').textContent=`Host: ${vm.host.id}. ${selectedAction.action==='start'?'Start this workload using its activated runner.':'Existing connections to this workload will be interrupted.'}`;
 $('action-dialog').showModal();
});
$('action-dialog').addEventListener('close',async()=>{
 if($('action-dialog').returnValue!=='confirm'||!selectedAction) return;
 const a=selectedAction; selectedAction=null; const key=a.host+'/'+a.vm;
 pending.set(key,{...a,time:Date.now()});render();
 try { await api(`/hosts/${encodeURIComponent(a.host)}/vms/${encodeURIComponent(a.vm)}/actions`,{action:a.action}); toast('Request accepted. Waiting for live state to confirm.'); await refresh(); }
 catch(e) { pending.delete(key);toast(e.message+'; check live state before retrying.');render(); }
});
async function refresh() {
 if(!csrf || fetching) return; fetching=true;
 try {
  state=await api('/state');
  for(const [key,a] of pending) {
   const vm=state.hosts.flatMap(vms).find(v=>v.host.id===a.host&&v.id===a.vm);
   const done=vm && vm.host.online && (a.action==='stop'?vm.state==='stopped':vm.state==='running'&&(a.action==='start'||vm.activation!==a.activation));
   if(done) {pending.delete(key);toast(`${a.vm}: ${a.action} confirmed by host observation.`);}
   else if(Date.now()-a.time>30000) {pending.delete(key);toast(`${a.vm}: outcome not confirmed within 30 seconds. Inspect live state.`);}
  }
  render();
 } catch(e) {
  if(e.status===401) loginScreen();
  else {$('connection').textContent='Connection lost';$('connection').className='status-chip bad';if(state){state.hosts.forEach(h=>{h.online=false;h.stale=true;});render();$('connection').textContent='Connection lost';}}
 } finally {fetching=false;}
}
setInterval(()=>{if(!document.hidden) refresh();},5000);
api('/session').then(signedIn).catch(()=>loginScreen());
