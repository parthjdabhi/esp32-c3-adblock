#pragma once
// Dashboard HTML for the C3 AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>C3 AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}th.srt{cursor:pointer;user-select:none}th.srt:hover{color:#c9d1d9}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
</style></head><body>
<header><h1>🛡️ C3 AdBlock <span id=host></span></h1></header><div class=wrap>
<div id=credwarn style="display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px">
⚠️ <b>Default credentials in use.</b> WEB_PASS/OTA_PASS in <code>secrets.h</code> are still the placeholder values — anyone can read them in the public repo. Set real values and reflash.
</div>
<div id=blockbar style="display:flex;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px">
<span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate style=flex:1 data-on=1>Blocking active</b>
<select id=pausedur style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"><option value=30>30s</option><option value=300 selected>5 min</option><option value=1800>30 min</option><option value=0>until I re-enable</option></select>
<button id=pausebtn onclick=togglePause()>Pause</button></div>
<div class=cards id=sys></div>
<h2>CLIENTS <span style=font-weight:400;font-size:12px>(click a column to sort)</span></h2><table id=ct><thead><tr><th class=srt data-s=name>Name</th><th class=srt data-s=ip>Client</th><th>MAC</th><th class=srt data-s=blocked>Blocked</th><th class=srt data-s=allowed>Allowed</th><th></th></tr></thead><tbody></tbody></table>
<details id=lkd ontoggle="if(lkd.open)loadQ()"><summary style="cursor:pointer;color:#8b949e;font-size:14px;margin:18px 0 8px">RECENT LOOKUPS <span style=font-size:12px>(last 20 per device, needs login)</span></summary>
<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px"><select id=qcl onchange=drawQ()><option value="">all devices</option></select>
<select id=qst onchange=drawQ()><option value="">all</option><option value=b>blocked</option><option value=a>allowed</option></select>
<input id=qtx placeholder="search domain" oninput=drawQ() size=18> <button onclick=loadQ()>Refresh</button> <span id=qmsg style=color:#8b949e></span></div>
<table id=qt><thead><tr><th>When</th><th>Device</th><th>Domain</th><th>Type</th><th>Result</th><th></th></tr></thead><tbody></tbody></table></details>
<h2>CUSTOM BLOCKED DOMAINS</h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com or a URL" size=30><button onclick=addDom()>Block domain</button></div>
<table id=cl><tbody></tbody></table>
<h2>BLOCKLIST &mdash; UPLOAD</h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button>Upload blocklist</button> <span id=upmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">build <code>blocklist.bin</code> with <code>tools/build_blocklist.py</code>, then upload here &mdash; no USB</div>
<h2>BLOCKLIST &mdash; REMOTE AUTO-UPDATE</h2>
<div style=margin-bottom:6px><input id=uurl placeholder="https://host/blocklist.bin" size=40> every <input id=uiv size=2 value=24>h
<button onclick=saveUpd()>Save</button> <button onclick=fetchNow()>Fetch now</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">device pulls a prebuilt <code>blocklist.bin</code> on a schedule (e.g. a GitHub release asset). last: <span id=ustat>&mdash;</span></div>
<h2>FIRMWARE &mdash; OTA UPDATE</h2>
<form id=fwf style=margin-bottom:6px><input type=file id=fwb accept=.bin><button>Flash firmware</button> <span id=fwmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">upload <code>.pio/build/&lt;env&gt;/firmware.bin</code> (env = c3, c3-supermini or esp32dev) &mdash; device verifies it and reboots into it. running: <code id=fwver>&mdash;</code></div>
<h2>IPV6 DNS</h2>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">this device also answers DNS over IPv6 at <code id=ip6>&mdash;</code> (<span id=q6>0</span> IPv6 queries).
If your router hands out its own IPv6 DNS, devices can skip the blocker: in the router, set IPv6 DNS to one of these addresses (or leave it empty). Prefer the <code>fe80::</code> one, it never changes.</div>
<h2>UPSTREAM DNS</h2>
<div style=margin-bottom:6px>primary <input id=dns1 placeholder="9.9.9.9" size=15> backup <input id=dns2 placeholder="none" size=15>
<button onclick=saveDns()>Save</button> <button onclick=defDns()>Defaults</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">allowed lookups go to the primary; if it doesn't answer in 0.8 s the backup is tried. <span id=dnsst></span></div>
<h2>WIFI</h2>
<div style=margin-bottom:18px><button onclick="if(confirm('Forget saved WiFi and reboot into the setup portal?'))forgetWifi()">Forget WiFi</button></div>
<h2>DEVICE</h2>
<div style=margin-bottom:6px><button onclick="if(confirm('Restart the device? DNS stops for about 10 seconds.'))reboot()">Restart</button>
<button onclick="if(confirm('Set all blocked/allowed counters to zero and clear recent lookups?'))resetStats()">Reset stats</button>
<button onclick=exportCfg()>Export settings</button> <span id=devmsg></span></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">restart keeps everything. Reset stats only clears counters and lookups. Export downloads custom domains, names, bans, DNS and auto-update as a JSON file.</div>
<h2 style=color:#f85149>DANGER ZONE</h2>
<div style=margin-bottom:6px><button class=ban onclick=resetSettings()>Reset settings</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">clears custom blocked domains, bans, device names (yours and learned), upstream DNS and auto-update, then restarts. WiFi and the blocklist stay. Export first.</div>
</div><script>
function fmt(n){return n.toLocaleString()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// A plain <img>/<form> CSRF can't set a custom header, only same-origin fetch()
// can — so requiring this on every mutating request blocks drive-by CSRF even
// though the server can't otherwise tell a forged request from a real one over
// plain HTTP Basic Auth (browsers auto-replay cached Basic Auth cross-origin).
const CSRF_HDRS={'X-Requested-With':'c3-adblock'}
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load);}
async function load(){let s=await(await fetch('/stats.json')).json();
host.textContent='@ '+s.ip;fwver.textContent=(s.ver||'?').replace(/^v(?=\d)/,'')+' on '+(s.chip||'?');
if(document.activeElement!=dns1)dns1.value=s.dns1||'';if(document.activeElement!=dns2)dns2.value=s.dns2||'';
dnsst.textContent=s.dnsok?('answered '+fmt(s.dnsok[0])+' / '+fmt(s.dnsok[1])+', timeouts '+fmt(s.dnsto[0])+' / '+fmt(s.dnsto[1])+(s.dnsbackup?' - primary is slow, using backup first':'')):'';
credwarn.style.display=s.defcreds?'block':'none';
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
blockstate.textContent=on?'Blocking active':(s.resumeIn>0?'Paused — resumes in '+s.resumeIn+'s':'Paused');
pausebtn.textContent=on?'Pause':'Resume';pausedur.style.display=on?'':'none';
sys.innerHTML=[['Total blocked',fmt(s.blocked),'b'],['Total allowed',fmt(s.allowed),'a'],['From cache',fmt(s.cachehits||0),'a'],['Blocklist',fmt(s.domains)+' domains<div class=l>'+esc(s.blformat||'')+'</div>',''],
['Clients',s.clients.length,''],['WiFi',s.rssi+' dBm',''],[s.chip=='ESP32'?'Temp (approx)':'Temp',s.temp+' °C',''],['Free RAM',Math.round(s.heap/1024)+' KB',''],['Uptime',s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort(cmpClients).map(c=>
`<tr><td><a href=# class=nm data-k="${esc(c.key)}" data-ip="${esc(c.ip)}" data-n="${esc(c.name||c.auto||'')}" style="color:${c.name?'#c9d1d9':'#8b949e'};text-decoration:none;${!c.name&&c.auto?'font-style:italic':''}" title="${c.name?'set by you':(c.auto?'from the device (click to set your own)':'click to name')}">${c.name?esc(c.name):(c.auto?esc(c.auto):'+ name')}</a>${c.hint?` <span class=tag>${esc(c.hint)}</span>`:''}${c.priv?' <span class=tag title="phone/laptop private Wi-Fi address" style=color:#8b949e>private MAC</span>':''}</td><td>${c.ip}${(c.ips||[]).length>1?` <span class=tag title="${esc(c.ips.slice(1).join('\n'))}" style=color:#8b949e>+${c.ips.length-1} more</span>`:''}${c.banned?' <span class=tag style=color:#f85149>BANNED</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=lkb data-k="${esc(c.key)}">lookups</button> ${c.ip.includes(':')?'':`<button class=ban data-ip="${c.ip}">${c.banned?'Unban':'Ban'}</button>`}</td></tr>`).join('');
ip6.textContent=(s.ip6&&s.ip6.length)?s.ip6.join('  '):'none yet (the router may not offer IPv6)';q6.textContent=fmt(s.q6||0);
CUST=s.custom;CL={};ROW={};let RL={};s.clients.forEach(c=>{let l=(c.name||c.auto||c.ip)+(c.name||c.auto?' ('+c.ip+')':'');RL[c.key]=l;(c.ips||[c.ip]).forEach(ip=>{CL[ip]=l;ROW[ip]=c.key})});
{let o='<option value="">all devices</option>'+s.clients.map(c=>`<option value="${esc(c.key)}">${esc(RL[c.key])}</option>`).join('');
if(o!=window.QOPT&&document.activeElement!=qcl){let v=qcl.value;qcl.innerHTML=o;qcl.value=v;window.QOPT=o}}
if(lkd.open&&!document.hidden&&Date.now()-(window.QLAST||0)>5000){window.QLAST=Date.now();loadQ()}
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=rmbtn data-d="${esc(d)}">remove</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>none yet</td></tr>';
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
ustat.textContent=s.upstat||'—';}
let CL={},ROW={},QD=[],CUST=[];
// clients table sort: column + direction, remembered in this browser (default: busiest first)
let SORT={k:'total',d:-1};try{let v=JSON.parse(localStorage.ctsort);if(['name','ip','blocked','allowed','total'].includes(v.k)&&(v.d==1||v.d==-1))SORT=v}catch(_){}
function ipKey(ip){let p=ip.split('.');return p.length==4?p.reduce((n,x)=>n*256+ +x,0):1e10}
function cmpClients(a,b){let k=SORT.k,v=k=='name'?String(a.name||a.auto||'~'+a.ip).toLowerCase().localeCompare(String(b.name||b.auto||'~'+b.ip).toLowerCase())
:k=='ip'?ipKey(a.ip)-ipKey(b.ip)||a.ip.localeCompare(b.ip):k=='total'?(a.blocked+a.allowed)-(b.blocked+b.allowed):a[k]-b[k];return v*SORT.d}
function drawSort(){document.querySelectorAll('#ct th.srt').forEach(h=>{h.textContent=h.textContent.replace(/ [▲▼]$/,'')+(h.dataset.s==SORT.k?(SORT.d>0?' ▲':' ▼'):'')})}
ct.tHead.addEventListener('click',e=>{let k=e.target.dataset.s;if(!k)return;
SORT=SORT.k==k?{k,d:-SORT.d}:{k,d:k=='name'||k=='ip'?1:-1};try{localStorage.ctsort=JSON.stringify(SORT)}catch(_){}drawSort();load()});
const QT={1:'A',5:'CNAME',12:'PTR',16:'TXT',28:'AAAA',33:'SRV',64:'SVCB',65:'HTTPS'};
const QS={b:['blocked','b'],n:['banned client','b'],c:['allowed (cache)','a'],f:['allowed','a'],x:['no answer','']};
function ago(s){return s<60?s+'s':s<3600?Math.floor(s/60)+'m':Math.floor(s/3600)+'h'}
async function loadQ(){try{let r=await fetch('/queries.json',{headers:CSRF_HDRS});if(!r.ok){qmsg.textContent='✗ '+r.status;return}
QD=(await r.json()).q.sort((a,b)=>a[0]-b[0]);qmsg.textContent=QD.length+' lookups';drawQ()}catch(_){qmsg.textContent='✗ failed'}}
function drawQ(){let cl=qcl.value,st=qst.value,tx=qtx.value.trim().toLowerCase();
qt.tBodies[0].innerHTML=QD.filter(q=>(!cl||(ROW[q[1]]||q[1])==cl)&&(!st||(QS[q[4]]||['',''])[1]==st)&&(!tx||q[2].includes(tx))).map(q=>{let s=QS[q[4]]||[q[4],''],bl=s[1]=='b';
let act=bl?(CUST.includes(q[2])?`<button class=qub data-d="${esc(q[2])}">unblock</button>`:''):`<button class=qbl data-d="${esc(q[2])}">block</button>`;
return `<tr><td>${ago(q[0])}</td><td>${esc(CL[q[1]]||q[1])}</td><td>${esc(q[2])}</td><td>${QT[q[3]]||q[3]}</td><td class=${s[1]}>${s[0]}</td><td>${act}</td></tr>`}).join('')||'<tr><td colspan=6 style=color:#8b949e>nothing yet</td></tr>'}
qt.addEventListener('click',e=>{let d=e.target.dataset.d;if(!d)return;
if(e.target.classList.contains('qbl')&&confirm('Block '+d+' (and its subdomains) for everyone?'))fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{load();setTimeout(loadQ,300)});
if(e.target.classList.contains('qub'))fetch('/unblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{load();setTimeout(loadQ,300)})});
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(async r=>{if(r.ok)dom.value='';else alert('✗ '+await r.text());load()})}}
ct.addEventListener('click',e=>{if(e.target.classList.contains('nm')){e.preventDefault();let n=prompt('Name for '+e.target.dataset.k+' (empty = remove)',e.target.dataset.n);if(n!==null)fetch('/setname?k='+encodeURIComponent(e.target.dataset.k)+'&ip='+encodeURIComponent(e.target.dataset.ip)+'&n='+encodeURIComponent(n.trim()),{headers:CSRF_HDRS}).then(load);return}
if(e.target.classList.contains('lkb')){lkd.open=true;qcl.value=e.target.dataset.k;loadQ();lkd.scrollIntoView({behavior:'smooth'});return}
if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24),{headers:CSRF_HDRS}).then(load)}
function fetchNow(){ustat.textContent='fetching...';fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
function saveDns(){fetch('/setdns?p='+encodeURIComponent(dns1.value.trim())+'&b='+encodeURIComponent(dns2.value.trim()),{headers:CSRF_HDRS}).then(async r=>{if(!r.ok)alert('✗ '+await r.text());load()})}
function defDns(){fetch('/setdns?def=1',{headers:CSRF_HDRS}).then(load)}
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>alert(t))}
// after a restart, poll until the device answers again, then reload
function waitBack(){devmsg.textContent='restarting...';let t0=Date.now();setTimeout(function p(){fetch('/stats.json',{cache:'no-store'}).then(r=>{if(r.ok)location.reload();else throw 0}).catch(()=>{if(Date.now()-t0<60000)setTimeout(p,2000);else devmsg.textContent='✗ not back after 60s, check the device'})},4000)}
function reboot(){fetch('/reboot',{headers:CSRF_HDRS}).then(r=>{if(r.ok)waitBack();else devmsg.textContent='✗ '+r.status}).catch(waitBack)}
function resetStats(){fetch('/resetstats',{headers:CSRF_HDRS}).then(r=>{devmsg.textContent=r.ok?'✓ stats reset':'✗ '+r.status;load()})}
async function exportCfg(){let r=await fetch('/export.json',{headers:CSRF_HDRS});if(!r.ok){devmsg.textContent='✗ '+r.status;return}
let a=document.createElement('a');a.href=URL.createObjectURL(await r.blob());a.download='c3adblock-settings-'+new Date().toISOString().slice(0,10)+'.json';a.click();URL.revokeObjectURL(a.href)}
function resetSettings(){if(prompt('This clears custom domains, bans, names, DNS and auto-update, then restarts.\nType RESET to confirm.')!=='RESET')return;
fetch('/resetsettings?c=RESET',{headers:CSRF_HDRS}).then(r=>{if(r.ok)waitBack();else r.text().then(t=>devmsg.textContent='✗ '+t)}).catch(waitBack)}
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent='flashing '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});fwmsg.textContent=r.ok?'✓ rebooting, reconnect in ~15s':'✗ '+await r.text();}
catch(_){fwmsg.textContent='✓ rebooting, reconnect in ~15s';}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent='uploading '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg.textContent=r.ok?'✓ updated':'✗ '+await r.text();}
catch(_){upmsg.textContent='✗ upload failed';}
blf.value='';setTimeout(load,600);};
drawSort();load();setInterval(load,3000);
</script></body></html>)HTML";
