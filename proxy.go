package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func sh(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// logMemStats records Go heap stats for post-mortem diagnosis (the proxy
// twice vanished without a last word; supervisor exit codes + these numbers
// distinguish OOM from external kills).
func logMemStats(tag string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("📊 mem[%s]: alloc=%.1fMB sys=%.1fMB heap_objects=%d gc=%d goroutines=%d\n",
		tag, float64(m.Alloc)/1048576, float64(m.Sys)/1048576,
		m.HeapObjects, m.NumGC, runtime.NumGoroutine())
}

// killStaleDaemon kills orphaned wireguard-go processes for iface whose
// interface is gone (typical after reboot: daemon reparented, iface lost).
func killStaleDaemon(iface string) {
	if _, err := sh("wg", "show", iface); err == nil {
		return // live interface, daemon fine
	}
	if out, err := sh("pgrep", "-f", "wireguard-go "+iface); err == nil && out != "" {
		for _, pidStr := range strings.Fields(out) {
			if pid, err := strconv.Atoi(pidStr); err == nil && pid != os.Getpid() {
				fmt.Printf("🧹 killing stale wireguard-go for %s (PID %d)\n", iface, pid)
				if p, err := os.FindProcess(pid); err == nil {
					p.Signal(syscall.SIGTERM)
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
}

// ensureDaemon starts wireguard-go userspace if the iface is missing and
// waits until the interface actually answers. Returns error on cold-start
// failure instead of letting setconf fail cryptically later.
// No-op on kernels with native WireGuard (interface creatable via ip).
func ensureDaemon(iface string) error {
	if _, err := sh("wg", "show", iface); err == nil {
		return nil
	}
	killStaleDaemon(iface)
	cmd := exec.Command("wireguard-go", iface)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil { // daemonizes itself; child outlives us
		return fmt.Errorf("wireguard-go start: %v", err)
	}
	for i := 0; i < 15; i++ {
		time.Sleep(2 * time.Second)
		if _, err := sh("wg", "show", iface); err == nil {
			return nil
		}
	}
	return fmt.Errorf("wireguard-go for %s never came up (check /dev/net/tun, wireguard-go binary)", iface)
}

// applyPeer writes a stripped wg config for peers[i] and activates it.
func applyPeer(iface string, p Peer) error {
	addr := p.Address
	if addr == "" {
		addr = "10.2.0.2/32"
	}
	conf := fmt.Sprintf("[Interface]\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s\nPersistentKeepalive = 25\n",
		p.PrivateKey, p.PublicKey, p.Endpoint)
	tmp, err := os.CreateTemp("", "wgtunnel-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(conf); err != nil {
		return err
	}
	tmp.Close()
	// Retry: right after daemon start the iface can still be settling.
	var setOut string
	var setErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(3 * time.Second)
		}
		setOut, setErr = sh("wg", "setconf", iface, tmp.Name())
		if setErr == nil {
			break
		}
	}
	if setErr != nil {
		hint := ""
		if _, derr := sh("wg", "show", iface); derr != nil {
			hint = " (interface missing — wireguard-go daemon not running?)"
		}
		if strings.TrimSpace(setOut) != "" {
			return fmt.Errorf("wg setconf: %v: %s%s", setErr, strings.TrimSpace(setOut), hint)
		}
		return fmt.Errorf("wg setconf: %v%s", setErr, hint)
	}
	// Address may already exist when re-applying; ignore that error.
	addrOut, _ := sh("ip", "-4", "address", "add", addr, "dev", iface)
	_ = addrOut
	if _, err := sh("ip", "link", "set", "mtu", "1320", "up", "dev", iface); err != nil {
		return fmt.Errorf("ip link up: %v", err)
	}
	return nil
}
func handshakeAge(iface string) int64 {
	out, err := sh("wg", "show", iface, "latest-handshakes")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || f[1] == "0" {
			continue
		}
		ts, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		return time.Now().Unix() - ts
	}
	return -1
}

// probeHostIP caches the resolved probe target for probeDataPath.
var probeHostIP = ""
var probeHostName = ""

// pickProbeHosts returns every routed hostname to verify the data path
// against, else ["opencode.ai"]. We probe what we route — any single host
// can go dark via tunnel egress while others work.
func pickProbeHosts(routed []string) []string {
	var hosts []string
	seen := map[string]bool{}
	for _, r := range routed {
		r = strings.TrimSpace(r)
		if r == "" || strings.Contains(r, "/") {
			continue
		}
		for _, c := range r {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				if !seen[r] {
					seen[r] = true
					hosts = append(hosts, r)
				}
				break
			}
		}
	}
	if len(hosts) == 0 {
		hosts = []string{"opencode.ai"}
	}
	return hosts
}

// resolveProbeIPs returns up to 4 distinct IPv4 addresses for host.
func resolveProbeIPs(host string) []string {
	out, err := sh("python3", "-c",
		"import socket;print(' '.join(sorted(set(r[4][0] for r in socket.getaddrinfo('"+host+"',443,socket.AF_INET)))))")
	if err != nil {
		return nil
	}
	ips := []string{}
	for _, ip := range strings.Fields(out) {
		if ip != "" && len(ips) < 4 {
			ips = append(ips, ip)
		}
	}
	return ips
}

// probeDataPath sends real payload through iface to prove the data path
// works, not just the handshake (servers throttle handshakes-ok/data-dead).
// Tries every resolved IP of every given host: anycast frontends may block
// tunnel egress on some VIPs while others work (observed: 2 of 4
// opencode.ai IPs dead), and whole hosts can go dark too.
// Returns true if bytes flow both ways within timeout.
func probeDataPath(iface string, timeoutSec int, hosts []string) bool {
	if len(hosts) == 0 {
		hosts = []string{"opencode.ai"}
	}
	perIP := timeoutSec
	if perIP > 8 {
		perIP = 8
	}
	for _, probeHost := range hosts {
		for _, ip := range resolveProbeIPs(probeHost) {
			probeHostIP = ip
			probeHostName = probeHost
			routeDst := ip + "/32"
			sh("ip", "route", "replace", routeDst, "dev", iface)
			sh("ip", "rule", "add", "to", routeDst, "lookup", "main", "pref", "99")
			time.Sleep(2 * time.Second)
			ok := false
			if pathOK(ip, iface) {
				for attempt := 0; attempt < 2; attempt++ {
					out, err := sh("curl", "-s", "--max-time", fmt.Sprint(perIP),
						"--resolve", probeHost+":443:"+ip, "https://"+probeHost)
					if err == nil && strings.TrimSpace(out) != "" {
						ok = true
						break
					}
					time.Sleep(2 * time.Second)
				}
			}
			sh("ip", "route", "del", routeDst, "dev", iface)
			sh("ip", "rule", "del", "to", routeDst, "lookup", "main", "pref", "99")
			if ok {
				return true
			}
		}
	}
	return false
}

// ifaceTransfer returns (rx, tx) totals for iface, or (0,0,err).
func ifaceTransfer(iface string) (uint64, uint64, error) {
	out, err := sh("wg", "show", iface, "transfer")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		rx, _ := strconv.ParseUint(f[1], 10, 64)
		tx, _ := strconv.ParseUint(f[2], 10, 64)
		return rx, tx, nil
	}
	return 0, 0, fmt.Errorf("no transfer data")
}

// peerReady waits for a handshake then verifies the data path with a real
// probe. Returns true only if payload actually flows through iface.
func peerReady(iface string, timeout int, probe bool, verbose bool, probeHosts []string) bool {
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	probedOnce := false
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		if age := handshakeAge(iface); age >= 0 && age < 120 {
			if !probe {
				return true
			}
			if probeDataPath(iface, 15, probeHosts) {
				return true
			}
			if probedOnce {
				return false // throttled peer: handshake ok, data dead
			}
			probedOnce = true
			if verbose {
				fmt.Println("   ⚠️  handshake ok but data probe failed, one retry...")
			}
		}
	}
	return false
}

// activate walks peers round-robin from start and activates the first
// that completes a handshake within timeout. Returns peer index.
// Pass nil stats to disable cooldown skipping (e.g. manual rotate).
// Desperation mode: if a full pass fails and peers were skipped for
// cooldown, a second pass tries everyone — any tunnel beats total outage.
func activate(iface string, peers []Peer, start, timeout int, verbose bool, stats map[string]*PeerStats, probeHosts []string) (int, error) {
	n := len(peers)
	skippedCooldown := 0
	for pass := 0; pass < 2; pass++ {
		if pass == 1 {
			if skippedCooldown == 0 {
				break // nothing was skipped; retry would be identical
			}
			fmt.Printf("⚠️  all peers failed (%d in cooldown) — desperation pass, ignoring cooldowns\n", skippedCooldown)
		}
		for k := 0; k < n; k++ {
			i := (start + k) % n
			p := peers[i]
			if stats != nil && pass == 0 {
				if skip, left := peerCooldown(stats, p.Name); skip && n > 1 {
					if verbose {
						fmt.Printf("   ⏭️  peer [%d] %s in cooldown (%s), skipping\n", i, p.Name, left)
					}
					skippedCooldown++
					continue
				}
			}
			if verbose {
				fmt.Printf("🔄 Trying peer [%d] %s (%s)\n", i, p.Name, p.Endpoint)
			}
			if err := applyPeer(iface, p); err != nil {
				fmt.Printf("   ✗ apply failed: %v\n", err)
				continue
			}
			if peerReady(iface, timeout, true, verbose, probeHosts) {
				if verbose {
					fmt.Printf("   ✅ peer [%d] %s handshake + data ok\n", i, p.Name)
				}
				return i, nil
			}
			fmt.Printf("   ✗ peer [%d] %s no handshake/data, skipping\n", i, p.Name)
		}
	}
	return -1, fmt.Errorf("no healthy peer")
}

// ---- Blocklist (FlareTunnel idea: block telemetry/trackers before VPN) ----

func loadBlocklist(path string) []string {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("⚠️  blocklist not loaded (%s): %v\n", path, err)
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.ToLower(line))
	}
	return out
}

func blocked(host string, list []string) bool {
	h := strings.ToLower(strings.Split(host, ":")[0])
	if net.ParseIP(h) != nil {
		return false
	}
	for _, p := range list {
		if strings.Contains(h, p) {
			return true
		}
	}
	return false
}

// ---- DNS via tunnel ----
// Proton exposes DNS at 10.2.0.1 inside the tunnel. Routing system DNS
// there kills the last direct leak (plain lookups expose destinations).

const resolvConf = "/etc/resolv.conf"
const resolvBackup = "/tmp/resolv.conf.wgtunnel.bak"
const vpnDNS = "10.2.0.1"

func enableDNS(egress string) {
	if _, err := os.Stat(resolvBackup); os.IsNotExist(err) {
		if data, err := os.ReadFile(resolvConf); err == nil {
			_ = os.WriteFile(resolvBackup, data, 0644)
		}
	}
	_ = os.WriteFile(resolvConf, []byte("# managed by wgtunnel --dns\nnameserver "+vpnDNS+"\n"), 0644)
	sh("ip", "route", "replace", vpnDNS+"/32", "dev", egress)
	sh("ip", "rule", "add", "to", vpnDNS+"/32", "lookup", "main", "pref", "100")
	fmt.Println("🔒 DNS via tunnel (" + vpnDNS + "), backup at " + resolvBackup)
}

func restoreDNS() {
	if data, err := os.ReadFile(resolvBackup); err == nil {
		_ = os.WriteFile(resolvConf, data, 0644)
		fmt.Println("🔓 DNS restored from backup")
	} else {
		fmt.Println("⚠️  no DNS backup found, leaving resolv.conf as-is")
	}
}

// cmdBoot brings up the full stack in order: proxy -> gateway.
// Safe to re-run: already-running pieces are detected and skipped.
func cmdBoot(args []string) {
	fs := flag.NewFlagSet("boot", flag.ExitOnError)
	interval := fs.Int("interval", 1800, "peer rotation seconds")
	routes := fs.String("route", "opencode.ai", "hosts/CIDRs to route via tunnel")
	fs.Parse(args)

	// 1. Proxy (detached, logs to /tmp/wgtunnel.log).
	pid, _ := readProcFiles()
	proxyUp := procAlive(pid)
	if !proxyUp {
		if out, err := sh("pgrep", "-f", "wgtunnel pro[x]y"); err == nil && out != "" {
			proxyUp = true
		}
	}
	if proxyUp {
		fmt.Println("✅ proxy already running, skipping start")
	} else {
		fmt.Println("🚀 starting proxy ...")
		logF, err := os.OpenFile("/tmp/wgtunnel.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Println("❌ log file:", err)
			os.Exit(1)
		}
		defer logF.Close()
		cmd := exec.Command(os.Args[0], "proxy", "--iface", "flare",
			"--listen", "127.0.0.1:8080", "--interval", strconv.Itoa(*interval),
			"--route", *routes, "--verbose")
		cmd.Stdout = logF
		cmd.Stderr = logF
		if err := cmd.Start(); err != nil {
			fmt.Println("❌ proxy start failed:", err)
			os.Exit(1)
		}
		cmd.Process.Release()
	}
	// 2. Wait for :8080.
	ok := false
	for i := 0; i < 30; i++ {
		if c, err := net.DialTimeout("tcp", "127.0.0.1:8080", time.Second); err == nil {
			c.Close()
			ok = true
			break
		}
		time.Sleep(time.Second)
	}
	if !ok {
		fmt.Println("❌ proxy :8080 not listening after 30s — check /tmp/wgtunnel.log")
		os.Exit(1)
	}
	fmt.Println("✅ proxy listening on 127.0.0.1:8080")

	// 3. Gateway.
	if out, err := sh("claude-zen", "start"); err != nil {
		fmt.Println("❌ gateway start failed:", err)
		fmt.Println(out)
		os.Exit(1)
	} else {
		fmt.Println(out)
	}

	// 4. Summary.
	fmt.Println("────────────────────────────────")
	if out, err := sh("wg", "show", "flare", "endpoints"); err == nil && out != "" {
		if f := strings.Fields(out); len(f) >= 2 {
			fmt.Println("🔗 tunnel endpoint:", f[1])
		}
	}
	if age := handshakeAge("flare"); age >= 0 {
		fmt.Printf("🤝 handshake: %ds ago\n", age)
	} else {
		fmt.Println("⚠️  no handshake yet (warming up)")
	}
	fmt.Println("📡 proxy:   127.0.0.1:8080")
	fmt.Println("🤖 gateway: 127.0.0.1:4013 (ANTHROPIC_BASE_URL)")
	fmt.Println("✅ all up")
}

func cmdDNS(args []string) {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	off := fs.Bool("off", false, "restore system DNS from backup")
	egress := fs.String("iface", "flare", "wireguard interface carrying DNS")
	fs.Parse(args)
	if *off {
		restoreDNS()
		return
	}
	enableDNS(*egress)
}

// ---- Standby rotation (zero-downtime, throttle-friendly) ----

// removePeer drops a peer from an interface (frees the server-side slot).
func removePeer(iface, pubkey string) {
	sh("wg", "set", iface, "peer", pubkey, "remove")
}

// rotateStandby brings the next peer up on the standby iface and verifies
// handshake AND data path. Recently-failed peers are skipped (cooldown).
// Caller flips routes to the standby first, then drops the old peer.
// Desperation mode: if every candidate is cooling down, a second pass tries
// everyone — any tunnel beats total outage.
// rotateStandby brings the next peer up on the standby iface and verifies
// handshake AND data path. Recently-failed peers are skipped (cooldown).
// Caller flips routes to the standby first, then drops the old peer.
// Desperation mode: if every candidate is cooling down, a second pass tries
// everyone — any tunnel beats total outage.
func rotateStandby(peers []Peer, cur int, standby string, timeout int, verbose bool, stats map[string]*PeerStats, probeHosts []string) (int, error) {
	n := len(peers)
	skippedCooldown := 0
	for pass := 0; pass < 2; pass++ {
		if pass == 1 {
			if skippedCooldown == 0 {
				break
			}
			fmt.Printf("⚠️  all standby candidates failed (%d in cooldown) — desperation pass, ignoring cooldowns\n", skippedCooldown)
		}
		for k := 1; k <= n; k++ {
			next := (cur + k) % n
			p := peers[next]
			if pass == 0 {
				if skip, left := peerCooldown(stats, p.Name); skip {
					if verbose {
						fmt.Printf("   ⏭️  peer [%d] %s in cooldown (%s), skipping\n", next, p.Name, left)
					}
					skippedCooldown++
					continue
				}
			}
			if verbose {
				fmt.Printf("🔄 Warming standby peer [%d] %s on %s\n", next, p.Name, standby)
			}
			if err := applyPeer(standby, p); err != nil {
				fmt.Printf("   ✗ apply failed: %v\n", err)
				continue
			}
			if !peerReady(standby, timeout, true, verbose, probeHosts) {
				fmt.Printf("   ✗ peer [%d] no handshake/data, trying next\n", next)
				continue
			}
			// Standby verified; caller flips routes, then drops old peer.
			if verbose {
				fmt.Printf("   ✅ peer [%d] %s warmed on %s\n", next, p.Name, standby)
			}
			return next, nil
		}
	}
	return cur, fmt.Errorf("no healthy standby peer")
}

// ---- HTTP proxy (plain CONNECT passthrough, no MITM) ----

var reqCount int64

// dialFailCount counts consecutive upstream dial failures across all
// handler goroutines. The health monitor reads it to detect a data-path
// blackhole (handshake alive, payload dead) that handshakeAge can't see.
var dialFailCount int64

// noteDialFail bumps the consecutive-failure counter; noteDialOK resets it.
func noteDialFail() { atomic.AddInt64(&dialFailCount, 1) }
func noteDialOK()   { atomic.StoreInt64(&dialFailCount, 0) }

func handleCONNECT(w http.ResponseWriter, r *http.Request, verbose bool, block []string, onReq func()) {
	host := r.Host
	if blocked(host, block) {
		if verbose {
			fmt.Printf("\n🚫 BLOCKED (blocklist): %s\n", host)
		}
		http.Error(w, "blocked by wgtunnel blocklist", http.StatusForbidden)
		return
	}
	onReq()
	if verbose {
		n := atomic.AddInt64(&reqCount, 1)
		fmt.Printf("\n🔒 [CONNECT #%d] %s\n", n, host)
	}
	// Force IPv4: tunnel policy routes are v4-only, so a v6 dial here
	// would bypass the tunnel and leak direct.
	serverConn, err := net.DialTimeout("tcp4", host, 15*time.Second)
	if err != nil {
		noteDialFail()
		if verbose {
			fmt.Printf("   ✗ dial failed: %v\n", err)
		}
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	noteDialOK()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		serverConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		serverConn.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() {
		defer serverConn.Close()
		defer clientConn.Close()
		io.Copy(serverConn, clientConn)
	}()
	go func() {
		defer serverConn.Close()
		defer clientConn.Close()
		io.Copy(clientConn, serverConn)
	}()
}

func handleHTTP(w http.ResponseWriter, r *http.Request, verbose bool, block []string, onReq func()) {
	host := r.Host
	if host == "" && r.URL != nil {
		host = r.URL.Host
	}
	if blocked(host, block) {
		if verbose {
			fmt.Printf("\n🚫 BLOCKED (blocklist): %s\n", host)
		}
		http.Error(w, "blocked by wgtunnel blocklist", http.StatusForbidden)
		return
	}
	onReq()
	if verbose {
		n := atomic.AddInt64(&reqCount, 1)
		fmt.Printf("\n📤 [#%d %s] %s\n", n, r.Method, r.URL.String())
	}
	r.RequestURI = ""
	r.URL.Scheme = "http"
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		noteDialFail()
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	noteDialOK()
	defer resp.Body.Close()
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

const proxyPIDFile = "/tmp/wgtunnel-proxy.pid"
const proxyArgsFile = "/tmp/wgtunnel-proxy.args"

func writeProcFiles() {
	_ = os.WriteFile(proxyPIDFile, []byte(strconv.Itoa(os.Getpid())), 0644)
	_ = os.WriteFile(proxyArgsFile, []byte(strings.Join(os.Args[1:], "\n")), 0600)
}

func readProcFiles() (int, []string) {
	pid := 0
	if data, err := os.ReadFile(proxyPIDFile); err == nil {
		pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
	}
	var args []string
	if data, err := os.ReadFile(proxyArgsFile); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" && l != "restart" {
				args = append(args, l)
			}
		}
	}
	return pid, args
}

func procAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func cmdStop(args []string) {
	pid, saved := readProcFiles()
	if !procAlive(pid) {
		// Fallback: scan process list.
		if out, err := sh("pgrep", "-f", "wgtunnel pro[x]y"); err == nil && out != "" {
			fmt.Sscanf(strings.Fields(out)[0], "%d", &pid)
		}
	}
	if !procAlive(pid) {
		fmt.Println("wgtunnel proxy not running")
		os.Remove(proxyPIDFile)
	} else {
		fmt.Printf("Stopping wgtunnel proxy (PID %d) ...\n", pid)
		p, _ := os.FindProcess(pid)
		p.Signal(syscall.SIGTERM)
		for i := 0; i < 10 && procAlive(pid); i++ {
			time.Sleep(500 * time.Millisecond)
		}
		if procAlive(pid) {
			fmt.Println("Still alive, forcing kill ...")
			p.Signal(syscall.SIGKILL)
			time.Sleep(time.Second)
		}
		os.Remove(proxyPIDFile)
		fmt.Println("wgtunnel proxy stopped")
	}
	// Remove policy routes/rules the proxy added so a later start (or
	// plain traffic) never trips over stale entries.
	cleanupRoutes(savedProxyRoutes(saved))
}

func savedProxyRoutes(saved []string) []string {
	var routes []string
	for i, a := range saved {
		if a == "--route" && i+1 < len(saved) {
			for _, r := range strings.Split(saved[i+1], ",") {
				if r = strings.TrimSpace(r); r != "" {
					routes = append(routes, r)
				}
			}
		}
		if a == "--dns" {
			restoreDNS()
		}
	}
	return routes
}

func cmdRestart(args []string) {
	cmdStop(args)
	_, saved := readProcFiles()
	if len(saved) == 0 || saved[0] != "proxy" {
		saved = []string{"proxy", "--iface", "flare", "--listen", "127.0.0.1:8080",
			"--interval", "1800", "--route", "opencode.ai", "--verbose"}
	}
	fmt.Println("Starting:", "wgtunnel", strings.Join(saved, " "))
	logF, err := os.OpenFile("/tmp/wgtunnel.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("❌ log file:", err)
		os.Exit(1)
	}
	cmd := exec.Command(os.Args[0], saved...)
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.Stdin = nil
	if err := cmd.Start(); err != nil {
		fmt.Println("❌ start failed:", err)
		os.Exit(1)
	}
	fmt.Printf("wgtunnel proxy starting (PID %d) — safe to close this terminal with nohup\n", cmd.Process.Pid)
}

func cmdProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	peersPath := fs.String("peers", "/root/wgtunnel/peers.json", "peer pool JSON")
	listen := fs.String("listen", "127.0.0.1:8080", "proxy listen address")
	iface := fs.String("iface", "flare", "wireguard interface")
	interval := fs.Int("interval", 1800, "peer rotation seconds, 0 disables (min 600 recommended)")
	timeout := fs.Int("timeout", 25, "handshake wait seconds per peer")
	routes := fs.String("route", "", "comma-separated hosts/CIDRs to route via tunnel (re-applied every 60s)")
	blocklist := fs.String("blocklist", "/root/wgtunnel/blocklist.txt", "domain blocklist file (empty to disable)")
	statsPath := fs.String("stats", "/tmp/wgtunnel-stats.json", "peer stats file")
	useDNS := fs.Bool("dns", false, "route system DNS via tunnel (rewrites resolv.conf, restores on exit)")
	verbose := fs.Bool("verbose", false, "verbose logging")
	fs.Parse(args)
	if *interval > 0 && *interval < 600 {
		fmt.Println("⚠️  interval < 600s risks server-side session throttling; using 600s")
		*interval = 600
	}

	peers, err := loadPeers(*peersPath)
	if err != nil || len(peers) == 0 {
		fmt.Println("❌ load peers:", err)
		os.Exit(1)
	}
	// Arm the rotate-signal channel BEFORE activation: a SIGUSR1 arriving
	// during the (slow) first activation must not kill the process with the
	// default disposition. Early signals are dropped after activation.
	sigRotate := make(chan os.Signal, 1)
	signal.Notify(sigRotate, syscall.SIGUSR1)
	// Dashboard rotate button (POST /api/rotate) feeds the same path.
	rotateHTTP := make(chan string, 1)
	proxyStart := time.Now()
	if err := ensureDaemon(*iface); err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}
	standby := *iface + "2"
	// Load stats before first activation so cooldown skips recently-failed
	// peers instead of re-picking the blackholed one after a restart.
	bootStats := loadStats(*statsPath)
	egress := *iface // interface currently carrying routed traffic
	routed := []string{}
	if *routes != "" {
		for _, r := range strings.Split(*routes, ",") {
			if r = strings.TrimSpace(r); r != "" {
				routed = append(routed, r)
			}
		}
	}
	// Data-path probes hit the routed host itself: generic IP-echo hosts
	// may be blocked via tunnel egress while the real destination works.
	probeHosts := pickProbeHosts(routed)
	fmt.Printf("🔍 data-path probe targets: %s\n", strings.Join(probeHosts, ", "))
	idx, err := activate(*iface, peers, 0, *timeout, *verbose, bootStats, probeHosts)
	if err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}
	flipRoutes := func(dev string) {
		for _, r := range routed {
			ensureRoute(r, dev)
		}
		if *useDNS {
			sh("ip", "route", "replace", vpnDNS+"/32", "dev", dev)
		}
	}
	flipRoutes(egress)
	if *useDNS {
		enableDNS(egress)
	}
	// Always clean up on SIGINT/SIGTERM/SIGHUP: policy routes/rules must
	// not outlive the proxy (stale entries shadow later probes), DNS
	// restored. SIGHUP is caught (not reload) so it can never kill the
	// proxy silently with the default disposition.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		sig := <-sigc
		fmt.Printf("\n🛑 shutting down on %s, cleaning routes...\n", sig)
		logMemStats("exit")
		cleanupRoutes(routed)
		if *useDNS {
			restoreDNS()
		}
		os.Remove(proxyPIDFile)
		os.Exit(0)
	}()
	block := loadBlocklist(*blocklist)
	stats := bootStats
	var activeIdx int64 = int64(idx)
	markActive := func() {
		i := int(atomic.LoadInt64(&activeIdx))
		st := stats[peers[i].Name]
		if st == nil {
			st = &PeerStats{}
			stats[peers[i].Name] = st
		}
		st.Requests++
		rollDay(st)
		st.DayRequests++
		st.LastActive = time.Now().UTC().Format(time.RFC3339)
		saveStats(*statsPath, stats)
	}
	markActive()
	fmt.Println("================================================================================")
	fmt.Println("🚀 WGTunnel Proxy Started")
	fmt.Println("================================================================================")
	fmt.Printf("🧰 runtime: %s pid=%d\n", runtime.Version(), os.Getpid())
	logMemStats("baseline")
	fmt.Printf("📡 Listening: %s\n", *listen)
	fmt.Printf("🔗 Active peer: [%d] %s\n", idx, peers[idx].Name)
	fmt.Printf("🔄 Rotation: every %ds across %d peers\n", *interval, len(peers))
	fmt.Printf("🚫 Blocklist: %d pattern(s)\n", len(block))
	if *routes != "" {
		fmt.Printf("🛣️  Routed: %s (re-applied every 15s)\n", *routes)
		for _, r := range strings.Split(*routes, ",") {
			ensureRoute(strings.TrimSpace(r), *iface)
		}
	}
	fmt.Println("📝 Proxy Configuration:")
	fmt.Printf("   HTTP Proxy:  %s\n", *listen)
	fmt.Printf("   HTTPS Proxy: %s\n", *listen)
	fmt.Println("📻 SIGUSR1 (kill -USR1 <pid>) forces immediate rotation (e.g. on API 429)")

	// Drop any rotate signals that arrived during activation.
	select {
	case <-sigRotate:
		fmt.Println("📻 dropped early rotate signal from startup")
	default:
	}

	if *interval > 0 || *routes != "" || true {
		go func() {
			cur := idx
			failStreak := 0
			healthTicks := 0
			var lastRx, lastTx uint64
			lastReqCount := atomic.LoadInt64(&reqCount)
			tr := &transferTracker{}
			tr.reset(egress)
			if rx, tx, err := ifaceTransfer(egress); err == nil {
				lastRx, lastTx = rx, tx
			}
			// Re-apply routes frequently (Android netd flushes ip rules).
			routeTick := time.NewTicker(15 * time.Second)
			defer routeTick.Stop()
			// Health monitor doubles as killswitch enforcer.
			// Three signals: handshake freshness, upstream dial failures
			// (data blackhole with live handshake), and transfer stall.
			healthTick := time.NewTicker(30 * time.Second)
			defer healthTick.Stop()
			rotTick := time.NewTicker(time.Duration(*interval) * time.Second)
			if *interval <= 0 {
				rotTick.Stop()
			} else {
				defer rotTick.Stop()
			}
			recordFail := func(peerName, reason string) {
				st := stats[peerName]
				if st == nil {
					st = &PeerStats{}
					stats[peerName] = st
				}
				st.DialFails++
				st.LastFail = time.Now().UTC().Format(time.RFC3339) + " " + reason
				saveStats(*statsPath, stats)
			}
			failover := func(reason string) {
				failStreak++
				fmt.Printf("⚠️  tunnel unhealthy (%s, streak %d) — killswitch ON, re-activating\n", reason, failStreak)
				recordFail(peers[cur].Name, reason)
				setKillswitch(routed, true, egress)
				backoff(failStreak)
				if next, err := activate(egress, peers, cur+1, *timeout, *verbose, stats, probeHosts); err == nil {
					cur = next
					atomic.StoreInt64(&activeIdx, int64(cur))
					markActive()
					tr.reset(egress)
					if rx, tx, err := ifaceTransfer(egress); err == nil {
						lastRx, lastTx = rx, tx
					}
					lastReqCount = atomic.LoadInt64(&reqCount)
					// Fresh peer just proved its data path; don't let
					// in-flight failures on the dead peer trip another
					// failover on the next tick.
					atomic.StoreInt64(&dialFailCount, 0)
				}
			}
			// Shared rotation path: warm standby, flip egress, drop old peer.
			// markFail=true records the current peer as rate-limited/failed
			// so cooldown skips it on the next pick.
			doRotate := func(reason string, markFail bool) {
				if markFail {
					fmt.Printf("📻 rotate trigger (%s) — marking [%d] %s rate-limited\n", reason, cur, peers[cur].Name)
					recordFail(peers[cur].Name, reason)
				} else if *verbose {
					fmt.Printf("🔄 interval rotation from [%d] %s\n", cur, peers[cur].Name)
				}
				if err := ensureDaemon(standby); err != nil {
					fmt.Println("⚠️  standby daemon:", err)
					backoff(1)
					return
				}
				next, err := rotateStandby(peers, cur, standby, *timeout, *verbose, stats, probeHosts)
				if err != nil {
					fmt.Println("⚠️  rotation failed, keeping current peer:", err)
					backoff(1)
					return
				}
				// Credit the OLD peer's final delta before flipping, or
				// its traffic gets attributed to the new peer.
				snapshotTransfer(tr, egress, peers[cur].Name, stats)
				// Flip traffic to warmed standby, drop old peer, swap roles.
				oldEgress, oldPeer := egress, cur
				egress = standby
				standby = oldEgress
				flipRoutes(egress)
				removePeer(standby, peers[oldPeer].PublicKey)
				cur = next
				atomic.StoreInt64(&activeIdx, int64(cur))
				markActive()
				tr.reset(egress)
				saveStats(*statsPath, stats)
				fmt.Printf("🔄 Rotated to peer [%d] %s (egress %s, reason: %s)\n", cur, peers[cur].Name, egress, reason)
			}
			// Jitter rotation start so restarts don't thunder.
			time.Sleep(time.Duration(time.Now().UnixNano()%10) * time.Second)
			for {
				select {
				case <-routeTick.C:
					flipRoutes(egress)
				case <-sigRotate:
					doRotate("429/manual SIGUSR1", true)
				case reason := <-rotateHTTP:
					doRotate(reason, true)
				case <-healthTick.C:
					healthTicks++
					if healthTicks%10 == 0 {
						logMemStats("health") // ~every 5min: OOM forensics
					}
					// Signal 1: consecutive upstream dial failures =
					// blackhole even with a fresh handshake. React now,
					// don't wait for handshake expiry.
					if fails := atomic.LoadInt64(&dialFailCount); fails >= 3 {
						atomic.StoreInt64(&dialFailCount, 0)
						failover(fmt.Sprintf("%d consecutive dial failures", fails))
						continue
					}
					// Signal 2: transfer counters frozen across two ticks
					// while NEW requests arrived = data stall. (Idle
					// periods freeze counters normally, so gate on
					// fresh requests since the last tick.)
					// Also credits this tick's delta to the active peer.
					tr.credit(egress, peers[cur].Name, stats)
					saveStats(*statsPath, stats)
					rx, tx, terr := ifaceTransfer(egress)
					reqs := atomic.LoadInt64(&reqCount)
					if terr == nil {
						if rx == lastRx && tx == lastTx && reqs > lastReqCount && lastRx+lastTx > 0 {
							lastReqCount = reqs
							failover("transfer stall (counters frozen)")
							continue
						}
						lastRx, lastTx = rx, tx
						lastReqCount = reqs
					}
					// Signal 3: handshake freshness (original check).
					if vpnHealthy(egress) {
						if failStreak > 0 && *verbose {
							fmt.Println("✅ tunnel healthy again, killswitch off")
						}
						failStreak = 0
						setKillswitch(routed, false, egress)
						continue
					}
					failover("stale handshake")
				case <-rotTick.C:
					doRotate("interval", false)
				}
			}
		}()
	}

	isDashHost := func(host string) bool {
		if host == *listen {
			return true
		}
		if strings.HasPrefix(*listen, "127.0.0.1:") && host == "localhost"+strings.TrimPrefix(*listen, "127.0.0.1") {
			return true
		}
		return false
	}
	dashServe := func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/" && (r.Method == "GET" || r.Method == "HEAD"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(dashHTML))
		case r.URL.Path == "/api/status" && r.Method == "GET":
			_, st := dashSnapshot(peers, *iface, *statsPath)
			st.IntervalS = *interval
			st.UptimeS = int64(time.Since(proxyStart).Seconds())
			st.Routes = *routes
			st.Listen = *listen
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(st)
		case r.URL.Path == "/api/peers" && r.Method == "GET":
			list, _ := dashSnapshot(peers, *iface, *statsPath)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(list)
		case r.URL.Path == "/api/log" && r.Method == "GET":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string][]string{"lines": dashLogTail("/tmp/wgtunnel.log", 40)})
		case r.URL.Path == "/manifest.webmanifest" && r.Method == "GET":
			w.Header().Set("Content-Type", "application/manifest+json")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			_, _ = w.Write([]byte(dashManifest))
		case r.URL.Path == "/sw.js" && r.Method == "GET":
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Service-Worker-Allowed", "/")
			_, _ = w.Write([]byte(dashSW))
		case r.URL.Path == "/icon-192.png" && r.Method == "GET":
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			_, _ = w.Write(icon192PNG)
		case r.URL.Path == "/icon-512.png" && r.Method == "GET":
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			_, _ = w.Write(icon512PNG)
		case r.URL.Path == "/icon-maskable-512.png" && r.Method == "GET":
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			_, _ = w.Write(iconMaskPNG)
		case r.URL.Path == "/api/rotate" && r.Method == "POST":
			select {
			case rotateHTTP <- "dashboard":
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":true}`))
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"ok":false,"error":"rotation already in progress"}`))
			}
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleCONNECT(w, r, *verbose, block, markActive)
			return
		}
		// Browser aimed directly at the proxy listener -> dashboard.
		if r.URL.Host == "" && isDashHost(r.Host) {
			dashServe(w, r)
			return
		}
		// Absolute-URI request targeting ourselves (proxy loop) -> refuse.
		if r.URL.Host != "" && isDashHost(r.URL.Host) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		handleHTTP(w, r, *verbose, block, markActive)
	})
	writeProcFiles()
	defer os.Remove(proxyPIDFile)
	srv := &http.Server{Addr: *listen, Handler: handler}
	// Suppress per-request server error spam on hijacked conns.
	srv.ErrorLog = nil
	if err := srv.ListenAndServe(); err != nil {
		fmt.Println("server stopped:", err)
	}
}
