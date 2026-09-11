package main

import (
	"encoding/base64"
	"os"
	"strings"
)

// ---- Dashboard (same port as the proxy) ----
// Browser traffic aimed directly at the proxy listener (origin-form request
// with Host == listen addr) gets the dashboard + JSON API. CONNECT and
// absolute-URI proxy traffic are untouched. Everything is inline (no CDN,
// no external fonts) so it works offline from a single binary.

type dashPeer struct {
	Index      int     `json:"index"`
	Name       string  `json:"name"`
	Endpoint   string  `json:"endpoint"`
	Requests   int64   `json:"requests"`
	Today      int64   `json:"today"`
	LastDay    int64   `json:"last_day"`
	RxMB       float64 `json:"rx_mb"`
	TxMB       float64 `json:"tx_mb"`
	Status     string  `json:"status"`
	Active     bool    `json:"active"`
	Iface      string  `json:"iface"`
	HandshakeS int64   `json:"handshake_s"`
}

type dashStatus struct {
	ActivePeer     string  `json:"active_peer"`
	ActiveEndpoint string  `json:"active_endpoint"`
	Iface          string  `json:"iface"`
	HandshakeS     int64   `json:"handshake_s"`
	ReqTotal       int64   `json:"req_total"`
	ReqToday       int64   `json:"req_today"`
	RxMB           float64 `json:"rx_mb"`
	TxMB           float64 `json:"tx_mb"`
	Peers          int     `json:"peers"`
	Cooldowns      int     `json:"cooldowns"`
	IntervalS      int     `json:"interval_s"`
	UptimeS        int64   `json:"uptime_s"`
	Routes         string  `json:"routes"`
	Listen         string  `json:"listen"`
}

// dashSnapshot reads the stats FILE (like `list` does), so dashboard polling
// never races the proxy's in-memory map.
func dashSnapshot(peers []Peer, iface, statsPath string) ([]dashPeer, dashStatus) {
	stats := loadStats(statsPath)
	ifaces := liveIfaces(iface)
	active, activeIface, age := -1, "", int64(-1)
	for _, ifname := range ifaces {
		dump, err := sh("wg", "show", ifname, "endpoints")
		if err != nil {
			continue
		}
		for i, p := range peers {
			if strings.Contains(dump, p.Endpoint) {
				if activeIface == "" || egressIface(ifname) {
					active, activeIface = i, ifname
					age = handshakeAge(ifname)
				}
				break
			}
		}
	}
	today := istToday()
	var st dashStatus
	st.Peers = len(peers)
	out := make([]dashPeer, 0, len(peers))
	for i, p := range peers {
		dp := dashPeer{Index: i, Name: p.Name, Endpoint: p.Endpoint, HandshakeS: -1}
		if pst := stats[p.Name]; pst != nil {
			dp.Requests = pst.Requests
			dr, lr := pst.DayRequests, pst.LastDayRequests
			if pst.Day != "" && pst.Day != today {
				lr, dr = dr, 0
			}
			dp.Today, dp.LastDay = dr, lr
			dp.RxMB = float64(pst.RxBytes) / 1048576
			dp.TxMB = float64(pst.TxBytes) / 1048576
			if skip, left := peerCooldown(stats, p.Name); skip {
				dp.Status = "cooldown " + left
				st.Cooldowns++
			}
		}
		if i == active {
			dp.Active = true
			dp.Iface = activeIface
			dp.HandshakeS = age
			dp.Status = "active"
			if age < 0 {
				dp.Status = "warming"
			}
			st.ActivePeer, st.ActiveEndpoint = p.Name, p.Endpoint
			st.Iface, st.HandshakeS = activeIface, age
		}
		st.ReqTotal += dp.Requests
		st.ReqToday += dp.Today
		st.RxMB += dp.RxMB
		st.TxMB += dp.TxMB
		out = append(out, dp)
	}
	return out, st
}

func dashLogTail(path string, maxLines int) []string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return []string{}
	}
	if len(data) > 131072 {
		data = data[len(data)-131072:]
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines
}

// ---- PWA (manifest + service worker + icons, all inline) ----

func mustDecodeIcon(b64 string) []byte {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic("bad embedded icon: " + err.Error())
	}
	return data
}

// Decoded once at startup; served from memory.
var (
	icon192PNG  = mustDecodeIcon(icon192B64)
	icon512PNG  = mustDecodeIcon(icon512B64)
	iconMaskPNG = mustDecodeIcon(iconMaskableB64)
)

const dashManifest = `{"name":"WGTunnel","short_name":"WGTunnel","id":"/","start_url":"/","scope":"/","display":"standalone","orientation":"any","theme_color":"#0b1020","background_color":"#0b1020","description":"Rotating WireGuard peer pool dashboard","icons":[{"src":"/icon-192.png","sizes":"192x192","type":"image/png","purpose":"any"},{"src":"/icon-512.png","sizes":"512x512","type":"image/png","purpose":"any"},{"src":"/icon-maskable-512.png","sizes":"512x512","type":"image/png","purpose":"maskable"}]}`

const dashSW = `'use strict';
var CACHE='wgtunnel-v1';
self.addEventListener('install',function(e){
  e.waitUntil(caches.open(CACHE).then(function(c){return c.addAll(['/', '/manifest.webmanifest'])}).then(function(){return self.skipWaiting()}));
});
self.addEventListener('activate',function(e){
  e.waitUntil(caches.keys().then(function(ks){return Promise.all(ks.map(function(k){if(k!==CACHE)return caches.delete(k)}))}).then(function(){return self.clients.claim()}));
});
self.addEventListener('fetch',function(e){
  var r=e.request;
  if(r.method!=='GET')return;
  var u=new URL(r.url);
  if(u.origin!==location.origin)return;
  if(r.mode==='navigate'||u.pathname==='/'){
    e.respondWith(fetch(r).then(function(res){var cp=res.clone();caches.open(CACHE).then(function(c){c.put('/',cp)});return res}).catch(function(){return caches.match('/')}));
    return;
  }
  if(u.pathname.indexOf('/api/')===0){
    e.respondWith(fetch(r).then(function(res){if(res.ok){var cp=res.clone();caches.open(CACHE).then(function(c){c.put(r,cp)})}return res}).catch(function(){return caches.match(r)}));
    return;
  }
});`

const dashHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WGTunnel Dashboard</title>
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#0b1020" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f1f5f9" media="(prefers-color-scheme: light)">
<link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png">
<link rel="apple-touch-icon" href="/icon-192.png">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="WGTunnel">
<script>(function(){try{var t=localStorage.getItem('wgt-theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t)}catch(e){}})();</script>
<style>
:root{color-scheme:light;--bg:#f1f5f9;--card:#ffffff;--line:#e2e8f0;--txt:#0f172a;--dim:#64748b;--acc:#2563eb;--acc2:#7c3aed;--ok:#059669;--warn:#b45309;--bad:#dc2626;--code:#334155;--glow:rgba(37,99,235,.18)}
:root[data-theme="dark"]{color-scheme:dark;--bg:#0b1020;--card:#141b33;--line:#232c4d;--txt:#e8ecf8;--dim:#8b94b3;--acc:#5b8cff;--acc2:#9d6bff;--ok:#34d399;--warn:#fbbf24;--bad:#f87171;--code:#b9c2e2;--glow:rgba(91,140,255,.25)}
@media (prefers-color-scheme:dark){:root:not([data-theme]){color-scheme:dark;--bg:#0b1020;--card:#141b33;--line:#232c4d;--txt:#e8ecf8;--dim:#8b94b3;--acc:#5b8cff;--acc2:#9d6bff;--ok:#34d399;--warn:#fbbf24;--bad:#f87171;--code:#b9c2e2;--glow:rgba(91,140,255,.25)}}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font:14px/1.5 -apple-system,'Segoe UI',Roboto,Inter,Arial,sans-serif;padding:24px;max-width:1100px;margin:0 auto}
header{display:flex;align-items:center;gap:12px;margin-bottom:20px}
.logo{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,var(--acc),var(--acc2));display:flex;align-items:center;justify-content:center;font-size:20px;box-shadow:0 4px 20px var(--glow)}
h1{font-size:22px;font-weight:700}
.sub{color:var(--dim);font-size:12px}
.spacer{margin-left:auto}
.tbtn{background:var(--card);border:1px solid var(--line);color:var(--txt);font-weight:600;padding:6px 12px;border-radius:99px;cursor:pointer;font-size:12px;box-shadow:none}
.tbtn:hover{border-color:var(--acc)}
.pill{padding:5px 14px;border-radius:99px;font-size:12px;font-weight:600;background:color-mix(in srgb,var(--ok) 12%,transparent);color:var(--ok);border:1px solid color-mix(in srgb,var(--ok) 35%,transparent)}
.pill.down{background:color-mix(in srgb,var(--bad) 12%,transparent);color:var(--bad);border-color:color-mix(in srgb,var(--bad) 35%,transparent)}
.pill.stale{background:color-mix(in srgb,var(--warn) 14%,transparent);color:var(--warn);border-color:color-mix(in srgb,var(--warn) 35%,transparent)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
.card .k{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim)}
.card .v{font-size:22px;font-weight:700;margin-top:4px}
.card .u{font-size:12px;color:var(--dim);font-weight:400}
.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:20px}
.panel h2{font-size:14px;margin-bottom:12px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--dim);font-weight:600;padding:8px;border-bottom:1px solid var(--line);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
td{padding:8px;border-bottom:1px solid var(--line)}
tr.active td{background:color-mix(in srgb,var(--acc) 8%,transparent)}
tr:last-child td{border-bottom:none}
.badge{padding:2px 10px;border-radius:99px;font-size:11px;font-weight:600;white-space:nowrap}
.badge.active{background:color-mix(in srgb,var(--ok) 15%,transparent);color:var(--ok)}
.badge.cool{background:color-mix(in srgb,var(--warn) 15%,transparent);color:var(--warn)}
.badge.idle{background:color-mix(in srgb,var(--dim) 15%,transparent);color:var(--dim)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
button.cta{background:linear-gradient(135deg,var(--acc),var(--acc2));border:none;color:#fff;font-weight:600;padding:10px 22px;border-radius:10px;cursor:pointer;font-size:14px}
button.cta:hover{filter:brightness(1.12)}
button.cta:disabled{opacity:.5;cursor:wait}
#msg{font-size:13px;color:var(--dim)}
pre{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:12px;font-size:12px;max-height:260px;overflow:auto;white-space:pre-wrap;color:var(--code)}
.routes{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--dim)}
footer{text-align:center;color:var(--dim);font-size:12px;margin-top:8px}
</style>
</head>
<body>
<header>
<div class="logo">&#128737;</div>
<div><h1>WGTunnel</h1><div class="sub" id="sub">rotating WireGuard peer pool</div></div>
<div class="spacer"></div>
<button class="tbtn" id="theme" type="button" aria-label="Theme: system">&#9681; system</button>
<div class="pill" id="pill">checking…</div>
</header>
<div class="grid" id="cards"></div>
<div class="panel"><h2>Peers</h2><div style="overflow-x:auto"><table>
<thead><tr><th>#</th><th>Name</th><th>Endpoint</th><th>Total</th><th>Today</th><th>Yday</th><th>Transfer</th><th>Status</th></tr></thead>
<tbody id="peers"></tbody>
</table></div></div>
<div class="panel"><h2>Control</h2><div class="row">
<button class="cta" id="rot" onclick="rotate()">&#128260; Rotate now</button>
<span id="msg"></span>
</div><div style="margin-top:10px" class="routes" id="routes"></div></div>
<div class="panel"><h2>Live log</h2><pre id="log">loading…</pre></div>
<footer>wgtunnel dashboard &middot; auto-refresh 3s &middot; localhost only</footer>
<script>
var busy=false,hadData=false,lastSig='';
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function fmtUptime(s){s=Math.floor(s);var h=Math.floor(s/3600),m=Math.floor(s%3600/60);if(h>0)return h+'h '+m+'m';if(m>0)return m+'m '+Math.floor(s%60)+'s';return s+'s'}
var THEMES=['system','light','dark'],GLYPH={system:'&#9681;',light:'&#9728;',dark:'&#9729;'};
function themeMode(){try{var t=localStorage.getItem('wgt-theme');if(t==='light'||t==='dark')return t}catch(e){}return 'system'}
function applyTheme(m){var b=document.getElementById('theme');if(m==='system'){document.documentElement.removeAttribute('data-theme')}else{document.documentElement.setAttribute('data-theme',m)}b.innerHTML=GLYPH[m]+' '+m;b.setAttribute('aria-label','Theme: '+m)}
function cycleTheme(){var m=THEMES[(THEMES.indexOf(themeMode())+1)%THEMES.length];try{if(m==='system'){localStorage.removeItem('wgt-theme')}else{localStorage.setItem('wgt-theme',m)}}catch(e){}applyTheme(m)}
document.getElementById('theme').addEventListener('click',cycleTheme);
applyTheme(themeMode());
function badge(p){
  if(p.active)return '<span class="badge active">active'+(p.iface?' &middot; '+esc(p.iface):'')+'</span>';
  if(p.status&&p.status.indexOf('cooldown')===0)return '<span class="badge cool">'+esc(p.status)+'</span>';
  return '<span class="badge idle">standby</span>';
}
function card(k,v,u){return '<div class="card"><div class="k">'+k+'</div><div class="v">'+v+' <span class="u">'+u+'</span></div></div>'}
function setPill(mode,text){var pill=document.getElementById('pill');pill.textContent=text;pill.className='pill'+(mode==='ok'?'':mode==='stale'?' stale':' down')}
async function refresh(){
  try{
    var r=await fetch('/api/status');if(!r.ok)throw 0;var s=await r.json();
    var r2=await fetch('/api/peers');var peers=await r2.json();
    var ok=s.handshake_s>=0&&s.handshake_s<180;
    setPill(ok?'ok':'down',ok?'● tunnel up':'● tunnel down');
    document.getElementById('sub').textContent='peer '+esc(s.active_peer||'?')+' on '+esc(s.iface||'?')+' · '+esc(s.listen||'');
    var sig=JSON.stringify([s,peers]);
    if(sig!==lastSig){
      lastSig=sig;
      document.getElementById('cards').innerHTML=
        card('Active peer',esc(s.active_peer||'—'),esc(s.active_endpoint||''))+
        card('Handshake',s.handshake_s>=0?s.handshake_s+'s':'never','ago')+
        card('Requests today',s.req_today,'/ total '+s.req_total)+
        card('Transfer today','&#8595;'+s.rx_mb.toFixed(1)+' &#8593;'+s.tx_mb.toFixed(1),'MB')+
        card('Uptime',fmtUptime(s.uptime_s),'')+
        card('Rotation','every '+s.interval_s+'s',s.cooldowns+' cooling');
      document.getElementById('routes').textContent='routed: '+(s.routes||'(none)')+' · '+s.peers+' peers';
      var html='';
      for(var i=0;i<peers.length;i++){var p=peers[i];
        html+='<tr'+(p.active?' class="active"':'')+'><td>'+p.index+'</td><td>'+esc(p.name)+'</td><td>'+esc(p.endpoint)+'</td><td>'+p.requests+'</td><td>'+p.today+'</td><td>'+p.last_day+'</td><td>&#8595;'+p.rx_mb.toFixed(1)+' &#8593;'+p.tx_mb.toFixed(1)+' MB</td><td>'+badge(p)+'</td></tr>';
      }
      document.getElementById('peers').innerHTML=html;
    }
    var r3=await fetch('/api/log');var lg=await r3.json();
    document.getElementById('log').textContent=lg.lines.join('\n')||'(empty)';
    hadData=true;
  }catch(e){
    if(hadData){setPill('stale','● stale — retrying')}else{setPill('down','● unreachable')}
  }
}
async function rotate(){
  if(busy)return;busy=true;
  var b=document.getElementById('rot');b.disabled=true;
  document.getElementById('msg').textContent='rotating…';
  try{
    var r=await fetch('/api/rotate',{method:'POST'});
    var j=await r.json();
    document.getElementById('msg').textContent=j.ok?'rotation started — warming standby peer':'busy: '+j.error;
  }catch(e){document.getElementById('msg').textContent='request failed';}
  setTimeout(function(){busy=false;b.disabled=false;refresh();},4000);
}
function tick(){if(!document.hidden)refresh()}
if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js').catch(function(){})}
refresh();setInterval(tick,3000);
</script>
</body>
</html>`
