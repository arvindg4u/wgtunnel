package main

import (
	"encoding/base64"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
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

type dashVIP struct {
	IP    string `json:"ip"`
	Host  string `json:"host"`
	OK    bool   `json:"ok"`
	AgeS  int64  `json:"age_s"`
	Stale bool   `json:"stale"`
}

type dashStatus struct {
	ActivePeer     string    `json:"active_peer"`
	ActiveEndpoint string    `json:"active_endpoint"`
	Iface          string    `json:"iface"`
	HandshakeS     int64     `json:"handshake_s"`
	ReqTotal       int64     `json:"req_total"`
	ReqToday       int64     `json:"req_today"`
	RxMB           float64   `json:"rx_mb"`
	TxMB           float64   `json:"tx_mb"`
	Peers          int       `json:"peers"`
	Cooldowns      int       `json:"cooldowns"`
	IntervalS      int       `json:"interval_s"`
	UptimeS        int64     `json:"uptime_s"`
	Routes         string    `json:"routes"`
	Listen         string    `json:"listen"`
	Vips           []dashVIP `json:"vips"`
	Killswitch     bool      `json:"killswitch"`
	Rotating       bool      `json:"rotating"`
	RotateInS      int64     `json:"rotate_in_s"`
}

// fillDashLive sets the live (non-snapshot) status fields.
func fillDashLive(st *dashStatus, interval int, routes, listen string, start time.Time) {
	st.IntervalS = interval
	st.UptimeS = int64(time.Since(start).Seconds())
	st.Routes = routes
	st.Listen = listen
	st.Killswitch = atomic.LoadInt64(&killswitchOn) == 1
	st.Rotating = atomic.LoadInt64(&rotating) == 1
	if interval > 0 {
		st.RotateInS = int64(interval) - (time.Now().Unix() - atomic.LoadInt64(&lastRotateUnix))
		if st.RotateInS < 0 {
			st.RotateInS = 0
		}
	} else {
		st.RotateInS = -1
	}
}

// snapshotVIPs copies the VIP health map for the dashboard.
func snapshotVIPs() []dashVIP {
	vipMu.RLock()
	defer vipMu.RUnlock()
	now := time.Now()
	out := make([]dashVIP, 0, len(vipHealth))
	for ip, r := range vipHealth {
		age := int64(now.Sub(r.At).Seconds())
		out = append(out, dashVIP{IP: ip, Host: r.Host, OK: r.OK, AgeS: age, Stale: age > 300})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].IP < out[b].IP })
	return out
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
	st.Vips = snapshotVIPs()
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

const dashManifest = `{"name":"WGTunnel","short_name":"WGTunnel","id":"/","start_url":"/","scope":"/","display":"standalone","orientation":"any","theme_color":"#0b1020","background_color":"#0b1020","description":"Rotating WireGuard peer pool dashboard","shortcuts":[{"name":"View log","url":"/#logpanel","icons":[{"src":"/icon-192.png","sizes":"192x192","type":"image/png"}]}],"icons":[{"src":"/icon-192.png","sizes":"192x192","type":"image/png","purpose":"any"},{"src":"/icon-512.png","sizes":"512x512","type":"image/png","purpose":"any"},{"src":"/icon-maskable-512.png","sizes":"512x512","type":"image/png","purpose":"maskable"}]}`

const dashSW = `'use strict';
var CACHE='wgtunnel-v2';
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
<title>WGTunnel</title>
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#04060c" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f7f5ef" media="(prefers-color-scheme: light)">
<link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png">
<link rel="apple-touch-icon" href="/icon-192.png">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="WGTunnel">
<script>(function(){try{var t=localStorage.getItem('wgt-theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t)}catch(e){}})();</script>
<style>
:root{color-scheme:light;--bg:#f7f5ef;--panel:#fffdf8;--line:rgba(16,24,40,.12);--txt:#101418;--dim:#5b6572;--faint:#8b94a1;--acc:#0a7d6c;--acc-ink:#ffffff;--ok:#0a7d4f;--warn:#9a5b00;--bad:#c92a2a;--code:#33414f;--dots:rgba(16,24,40,.08);--wash:rgba(10,125,108,.08)}
:root[data-theme="dark"]{color-scheme:dark;--bg:#04060c;--panel:#090d16;--line:rgba(148,197,255,.12);--txt:#e6f1ff;--dim:#8494ab;--faint:#525f76;--acc:#38e1c6;--acc-ink:#03211c;--ok:#3ddc84;--warn:#ffb224;--bad:#ff5d5d;--code:#9fb4d0;--dots:rgba(148,197,255,.07);--wash:rgba(56,225,198,.07)}
@media (prefers-color-scheme:dark){:root:not([data-theme]){color-scheme:dark;--bg:#04060c;--panel:#090d16;--line:rgba(148,197,255,.12);--txt:#e6f1ff;--dim:#8494ab;--faint:#525f76;--acc:#38e1c6;--acc-ink:#03211c;--ok:#3ddc84;--warn:#ffb224;--bad:#ff5d5d;--code:#9fb4d0;--dots:rgba(148,197,255,.07);--wash:rgba(56,225,198,.07)}}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);background-image:radial-gradient(circle,var(--dots) 1px,transparent 1px);background-size:22px 22px;color:var(--txt);font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Inter,Arial,sans-serif;padding:0 20px 32px;max-width:1060px;margin:0 auto}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace}
.num{font-variant-numeric:tabular-nums}
.topbar{display:flex;align-items:center;gap:10px;padding:14px 2px;border-bottom:1px solid var(--line)}
.brand{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-weight:700;font-size:13px;letter-spacing:.14em}
.brand b{color:var(--acc)}
.topbar .spacer{margin-left:auto}
.ghost{background:transparent;border:1px solid var(--line);color:var(--txt);font:600 12px/1 -apple-system,'Segoe UI',Roboto,Arial,sans-serif;padding:7px 13px;border-radius:99px;cursor:pointer}
.ghost:hover{border-color:var(--acc);color:var(--acc)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--dim);display:inline-block;flex:none}
.dot.ok{background:var(--ok);box-shadow:0 0 8px var(--ok);animation:pulse 2s infinite}
.dot.bad{background:var(--bad);box-shadow:0 0 8px var(--bad)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
.hero{display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap;padding:26px 2px 18px;border-bottom:1px solid var(--line)}
.eyebrow{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}
.hero h1{font-size:clamp(30px,5vw,46px);font-weight:750;letter-spacing:-.02em;line-height:1.05;margin:6px 0 4px}
.hero .end{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;color:var(--dim)}
.hero .side{margin-left:auto;text-align:right}
.hero .hs{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:clamp(24px,4vw,34px);font-weight:700;font-variant-numeric:tabular-nums}
.hero .hs small{font-size:12px;color:var(--dim);font-weight:400}
.pill{display:inline-flex;align-items:center;gap:7px;padding:5px 13px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid color-mix(in srgb,var(--ok) 40%,transparent);color:var(--ok)}
.pill.down{border-color:color-mix(in srgb,var(--bad) 40%,transparent);color:var(--bad)}
.pill.stale{border-color:color-mix(in srgb,var(--warn) 40%,transparent);color:var(--warn)}
.meter{display:flex;flex-wrap:wrap;border-bottom:1px solid var(--line)}
.meter div{padding:12px 20px 12px 2px;margin-right:20px;border-right:1px solid var(--line)}
.meter div:last-child{border-right:none}
.meter .k{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:10px;letter-spacing:.1em;color:var(--faint);text-transform:uppercase}
.meter .v{font-size:19px;font-weight:650;font-variant-numeric:tabular-nums;margin-top:2px}
.meter .v small{font-size:12px;color:var(--dim);font-weight:400}
section{padding:18px 2px}
section h2{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;letter-spacing:.12em;color:var(--dim);text-transform:uppercase;margin-bottom:10px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--faint);font-weight:600;padding:7px 10px 7px 2px;border-bottom:1px solid var(--line);font-size:11px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.08em;text-transform:uppercase}
td{padding:9px 10px 9px 2px;border-bottom:1px solid var(--line);font-variant-numeric:tabular-nums}
tbody tr:hover{background:var(--wash)}
tr.active td{box-shadow:inset 2px 0 0 var(--acc)}
tbody tr:last-child td{border-bottom:none}
.st{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;white-space:nowrap}
.st:before{content:'';width:7px;height:7px;border-radius:50%;background:var(--dim)}
.st.on{color:var(--ok)}.st.on:before{background:var(--ok);box-shadow:0 0 6px var(--ok)}
.st.cool{color:var(--warn)}.st.cool:before{background:var(--warn)}
.vip{display:inline-flex;align-items:center;gap:7px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;padding:5px 12px 5px 9px;border:1px solid var(--line);border-radius:99px;margin:0 8px 8px 0;background:var(--panel)}
.vip i{width:8px;height:8px;border-radius:50%;background:var(--dim)}
.vip.ok i{background:var(--ok);box-shadow:0 0 6px var(--ok)}
.vip.bad i{background:var(--bad);box-shadow:0 0 6px var(--bad)}
.vip .age{color:var(--faint);font-size:11px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
button.cta{background:var(--acc);border:none;color:var(--acc-ink);font-weight:700;padding:10px 22px;border-radius:8px;cursor:pointer;font-size:14px}
button.cta:hover{filter:brightness(1.08)}
button.cta:disabled{opacity:.45;cursor:wait}
#msg{font-size:13px;color:var(--dim)}
.ks{display:none;background:color-mix(in srgb,var(--bad) 14%,transparent);border:1px solid color-mix(in srgb,var(--bad) 45%,transparent);color:var(--bad);font-weight:700;font-size:13px;padding:9px 14px;border-radius:10px;margin:12px 0 0}
.sel{background:var(--panel);border:1px solid var(--line);color:var(--txt);border-radius:8px;padding:9px 10px;font-size:13px;max-width:220px}
.chk{font-size:13px;color:var(--dim);display:inline-flex;align-items:center;gap:6px;cursor:pointer}
pre{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;font-size:12px;max-height:260px;overflow:auto;white-space:pre-wrap;color:var(--code)}
.routes{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--dim)}
footer{text-align:center;color:var(--faint);font-size:12px;margin-top:14px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (max-width:640px){
thead{display:none}
table,tbody,tr,td{display:block;width:100%}
tbody tr{border:1px solid var(--line);border-radius:10px;margin-bottom:8px;padding:4px 10px}
tbody td{border:none;padding:5px 8px;display:flex;justify-content:space-between;align-items:center;gap:10px}
tbody td:before{content:attr(data-l);color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.08em;font-family:ui-monospace,Menlo,Consolas,monospace}
tr.active td{box-shadow:inset 0 2px 0 var(--acc)}
.hero .side{margin-left:0;text-align:left}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body>
<div class="topbar">
<span class="brand">WG<b>TUNNEL</b></span>
<span class="spacer"></span>
<button class="ghost" id="theme" type="button" aria-label="Theme: system">&#9681; system</button>
<span class="pill" id="pill" role="status" aria-live="polite"><span class="dot" id="pdot"></span><span id="ptxt">checking…</span></span>
</div>
<div class="hero">
<div><div class="eyebrow">Active egress</div><h1 id="hPeer">—</h1><div class="end mono" id="hEnd">—</div></div>
<div class="side"><div class="eyebrow">Handshake · next rotation</div><div class="hs num"><span id="hHs">—</span> <small>ago</small> · <span id="cd">—</span></div><div class="eyebrow mono" id="sub" style="margin-top:4px">—</div></div>
</div>
<div class="ks" id="ks" role="alert">⛔ KILLSWITCH ON — routed traffic held, proxy failing over</div>
<div class="meter" id="meter"></div>
<section><h2>Probe targets</h2><div id="vips"><span class="routes">probing…</span></div></section>
<section><h2>Peers</h2><div style="overflow-x:auto"><table>
<thead><tr><th scope="col">#</th><th scope="col">Peer</th><th scope="col">Endpoint</th><th scope="col">Total</th><th scope="col">Today</th><th scope="col">Yday</th><th scope="col">Xfer</th><th scope="col">Status</th></tr></thead>
<tbody id="peers"></tbody>
</table></div></section>
<section><h2>Control</h2><div class="row">
<button class="cta" id="rot" onclick="rotate()">Rotate now</button>
<select class="sel" id="peersel" aria-label="Route a specific peer"></select>
<button class="ghost" id="routebtn" type="button" onclick="routePeer()">Route</button>
<span id="msg"></span>
</div><div style="margin-top:10px" class="routes" id="routes"></div></section>
<section id="logpanel"><h2>Live log</h2><div class="row" style="margin-bottom:8px"><label class="chk"><input type="checkbox" id="erronly"> errors only</label></div><pre id="log" role="log" aria-label="Proxy log">loading…</pre></section>
<footer>wgtunnel · localhost only</footer>
<script>
var busy=false,hadData=false,lastSig='',lastLines=[],cdLeft=-1;
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')}
function fmtUptime(s){s=Math.floor(s);var h=Math.floor(s/3600),m=Math.floor(s%3600/60);if(h>0)return h+'h '+m+'m';if(m>0)return m+'m '+Math.floor(s%60)+'s';return s+'s'}
function fmtCD(s){if(s<0)return 'off';s=Math.floor(s);var m=Math.floor(s/60);return m+':'+('0'+Math.floor(s%60)).slice(-2)}
var THEMES=['system','light','dark'],GLYPH={system:'&#9681;',light:'&#9728;',dark:'&#9729;'};
function themeMode(){try{var t=localStorage.getItem('wgt-theme');if(t==='light'||t==='dark')return t}catch(e){}return 'system'}
function applyTheme(m){var b=document.getElementById('theme');if(m==='system'){document.documentElement.removeAttribute('data-theme')}else{document.documentElement.setAttribute('data-theme',m)}b.innerHTML=GLYPH[m]+' '+m;b.setAttribute('aria-label','Theme: '+m)}
function cycleTheme(){var m=THEMES[(THEMES.indexOf(themeMode())+1)%THEMES.length];try{if(m==='system'){localStorage.removeItem('wgt-theme')}else{localStorage.setItem('wgt-theme',m)}}catch(e){}applyTheme(m)}
document.getElementById('theme').addEventListener('click',cycleTheme);
applyTheme(themeMode());
function stHTML(p){
  if(p.active)return '<span class="st on">active'+(p.iface?' · '+esc(p.iface):'')+'</span>';
  if(p.status&&p.status.indexOf('cooldown')===0)return '<span class="st cool">'+esc(p.status)+'</span>';
  return '<span class="st">standby</span>';
}
function vipHTML(v){
  var cls=v.ok?'ok':'bad';
  var age=v.age_s<60?v.age_s+'s':Math.floor(v.age_s/60)+'m';
  return '<span class="vip '+cls+'" title="'+esc(v.host||'')+' · '+age+' ago'+(v.stale?' (stale)':'')+'"><i></i>'+esc(v.ip)+'<span class="age">'+age+'</span></span>';
}
function meter(k,v){return '<div><div class="k">'+k+'</div><div class="v num">'+v+'</div></div>'}
function setPill(mode,text){document.getElementById('ptxt').textContent=text;var p=document.getElementById('pill');p.className='pill'+(mode==='ok'?'':mode==='stale'?' stale':' down');document.getElementById('pdot').className='dot'+(mode==='ok'?' ok':mode==='stale'?'':' bad')}
function renderLog(){
  var lines=lastLines;
  if(document.getElementById('erronly').checked){lines=lines.filter(function(l){return /⚠️|✗|❌|⛔|error|fail|warn|down|stale|skip|kill|prohibit/i.test(l)})}
  document.getElementById('log').textContent=lines.join('\n')||'(empty)';
}
async function refresh(){
  try{
    var r=await fetch('/api/snapshot');if(!r.ok)throw 0;var j=await r.json();
    var s=j.status,peers=j.peers;lastLines=j.lines||[];
    var ok=s.handshake_s>=0&&s.handshake_s<180;
    setPill(ok?'ok':'down',ok?'tunnel up':'tunnel down');
    document.getElementById('hPeer').textContent=s.active_peer||'—';
    document.getElementById('hEnd').textContent=s.active_endpoint||'—';
    document.getElementById('hHs').textContent=s.handshake_s>=0?s.handshake_s+'s':'never';
    document.getElementById('sub').textContent=(s.iface||'?')+' · '+esc(s.listen||'');
    var sig=JSON.stringify([s,peers]);
    if(sig!==lastSig){
      lastSig=sig;
      document.getElementById('meter').innerHTML=
        meter('Req today',s.req_today+' <small>/ '+s.req_total+'</small>')+
        meter('Xfer today','&#8595;'+s.rx_mb.toFixed(1)+' &#8593;'+s.tx_mb.toFixed(1)+' <small>MB</small>')+
        meter('Uptime',fmtUptime(s.uptime_s)+' <small></small>')+
        meter('Cooling',s.cooldowns+' <small>peers</small>');
      cdLeft=s.rotate_in_s;
      var vh='';
      for(var vi=0;vi<(s.vips||[]).length;vi++){vh+=vipHTML(s.vips[vi])}
      document.getElementById('vips').innerHTML=vh||'<span class="routes">no probe data yet</span>';
      document.getElementById('ks').style.display=s.killswitch?'block':'none';
      document.getElementById('routes').textContent='routed: '+(s.routes||'(none)')+' · '+s.peers+' peers';
      var rb=document.getElementById('rot');
      fillPeerSelect(peers);
      if(s.rotating){rb.disabled=true;document.getElementById('routebtn').disabled=true;document.getElementById('msg').textContent='warming standby peer…'}
      else if(!busy){rb.disabled=false;document.getElementById('routebtn').disabled=false}
      var html='';
      for(var i=0;i<peers.length;i++){var p=peers[i];
        html+='<tr'+(p.active?' class="active"':'')+'><td data-l="#">'+p.index+'</td><td data-l="Peer"><b>'+esc(p.name)+'</b></td><td data-l="Endpoint" class="mono">'+esc(p.endpoint)+'</td><td data-l="Total" class="num">'+p.requests+'</td><td data-l="Today" class="num">'+p.today+'</td><td data-l="Yday" class="num">'+p.last_day+'</td><td data-l="Xfer" class="num">&#8595;'+p.rx_mb.toFixed(1)+' &#8593;'+p.tx_mb.toFixed(1)+'</td><td data-l="Status">'+stHTML(p)+'</td></tr>';
      }
      document.getElementById('peers').innerHTML=html;
    }
    renderLog();
    hadData=true;
  }catch(e){
    if(hadData){setPill('stale','stale — retrying')}else{setPill('down','unreachable')}
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
  setTimeout(function(){busy=false;refresh();},4000);
}
function fillPeerSelect(peers){
  var sel=document.getElementById('peersel');
  var keep=sel.value;
  var html='';
  for(var i=0;i<peers.length;i++){var p=peers[i];
    var label=p.index+' · '+p.name+(p.active?' (active)':'');
    html+='<option value="'+p.index+'"'+(p.active?' disabled':'')+'>'+esc(label)+'</option>';
  }
  sel.innerHTML=html;
  if(keep!==''&&sel.querySelector('option[value="'+keep+'"]:not([disabled])')){sel.value=keep}
}
async function routePeer(){
  var sel=document.getElementById('peersel');
  if(busy||!sel||sel.value==='')return;busy=true;
  var b=document.getElementById('routebtn');b.disabled=true;
  document.getElementById('msg').textContent='warming peer '+sel.value+'…';
  try{
    var r=await fetch('/api/rotate?peer='+encodeURIComponent(sel.value),{method:'POST'});
    var j=await r.json();
    document.getElementById('msg').textContent=j.ok?'warming peer '+sel.value+' — standby proving itself':'busy: '+j.error;
  }catch(e){document.getElementById('msg').textContent='request failed';}
  setTimeout(function(){busy=false;refresh();},4000);
}
document.getElementById('erronly').addEventListener('change',renderLog);
function tick(){if(!document.hidden)refresh()}
setInterval(function(){if(cdLeft>0){cdLeft--;var el=document.getElementById('cd');if(el)el.textContent=fmtCD(cdLeft)}},1000);
if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js').catch(function(){})}
refresh();setInterval(tick,3000);
</script>
</body>
</html>`
