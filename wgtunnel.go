// WGTunnel - rotating WireGuard peer pool with a local HTTP proxy.
// WireGuard counterpart to FlareTunnel: instead of Cloudflare Workers,
// egress rotates across N WireGuard peers (one active at a time).
//
// Usage:
//   ./wgtunnel proxy --peers peers.json --listen 127.0.0.1:8080 --interval 300 --verbose
//   ./wgtunnel rotate --peers peers.json --iface flare --once
//   ./wgtunnel status --iface flare
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type Peer struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Endpoint   string `json:"endpoint"`
	Address    string `json:"address"` // e.g. 10.2.0.2/32 (default if empty)
}

func loadPeers(path string) ([]Peer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var peers []Peer
	if err := json.Unmarshal(data, &peers); err != nil {
		return nil, err
	}
	return peers, nil
}

func sh(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ensureDaemon starts wireguard-go userspace if the iface is missing.
// No-op on kernels with native WireGuard (interface creatable via ip).
func ensureDaemon(iface string) {
	if _, err := sh("wg", "show", iface); err == nil {
		return
	}
	cmd := exec.Command("wireguard-go", iface)
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Start() // daemonizes itself; child outlives us
	time.Sleep(2 * time.Second)
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
	if _, err := sh("wg", "setconf", iface, tmp.Name()); err != nil {
		return fmt.Errorf("wg setconf: %v", err)
	}
	// Address may already exist when re-applying; ignore that error.
	addrOut, _ := sh("ip", "-4", "address", "add", addr, "dev", iface)
	_ = addrOut
	if _, err := sh("ip", "link", "set", "mtu", "1320", "up", "dev", iface); err != nil {
		return fmt.Errorf("ip link up: %v", err)
	}
	return nil
}

// ensureRoute routes hostOrCIDR via dev (main table + policy rule).
// Idempotent; safe to call periodically (Android flushes rules).
func ensureRoute(hostOrCIDR, dev string) {
	dst := hostOrCIDR
	if !strings.Contains(dst, "/") {
		ips, err := net.LookupHost(dst)
		if err != nil || len(ips) == 0 {
			fmt.Printf("   ⚠️  dns failed for %s: %v\n", dst, err)
			return
		}
		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				continue // v4 only for now
			}
			ensureRoute(ip+"/32", dev)
		}
		return
	}
	sh("ip", "route", "replace", dst, "dev", dev)
	sh("ip", "rule", "add", "to", dst, "lookup", "main", "pref", "100")
}

// pathOK reports whether kernel would send ip via dev.
func pathOK(ip, dev string) bool {
	out, err := sh("ip", "route", "get", ip)
	return err == nil && strings.Contains(out, "dev "+dev)
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

// activate walks peers round-robin from start and activates the first
// that completes a handshake within timeout. Returns peer index.
func activate(iface string, peers []Peer, start, timeout int, verbose bool) (int, error) {
	n := len(peers)
	for k := 0; k < n; k++ {
		i := (start + k) % n
		p := peers[i]
		if verbose {
			fmt.Printf("🔄 Trying peer [%d] %s (%s)\n", i, p.Name, p.Endpoint)
		}
		if err := applyPeer(iface, p); err != nil {
			fmt.Printf("   ✗ apply failed: %v\n", err)
			continue
		}
		deadline := time.Now().Add(time.Duration(timeout) * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(2 * time.Second)
			if age := handshakeAge(iface); age >= 0 && age < 120 {
				if verbose {
					fmt.Printf("   ✅ peer [%d] %s handshake ok (%ds ago)\n", i, p.Name, age)
				}
				return i, nil
			}
		}
		fmt.Printf("   ✗ peer [%d] %s no handshake, skipping\n", i, p.Name)
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

// ---- Peer stats (persisted) ----

type PeerStats struct {
	Requests   int64  `json:"requests"`
	LastActive string `json:"last_active"`
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
}

func loadStats(path string) map[string]*PeerStats {
	m := map[string]*PeerStats{}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &m)
	}
	return m
}

func saveStats(path string, m map[string]*PeerStats) {
	data, _ := json.MarshalIndent(m, "", "  ")
	_ = os.WriteFile(path, data, 0600)
}

// snapshotTransfer records current wg transfer totals for peerName.
func snapshotTransfer(iface, peerName string, m map[string]*PeerStats) {
	out, err := sh("wg", "show", iface, "transfer")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		rx, _ := strconv.ParseUint(f[1], 10, 64)
		tx, _ := strconv.ParseUint(f[2], 10, 64)
		st := m[peerName]
		if st == nil {
			st = &PeerStats{}
			m[peerName] = st
		}
		// Single-peer-at-a-time: totals belong to the active peer.
		if rx >= st.RxBytes {
			st.RxBytes = rx
		}
		if tx >= st.TxBytes {
			st.TxBytes = tx
		}
		break // only one peer configured at a time
	}
}

// ---- Killswitch (fail-closed): routed destinations must never leak direct.
// When VPN is unhealthy we point them at a prohibit route instead of
// removing routes (absence would fall through to the direct tables).

func setKillswitch(dsts []string, on bool, egress string) {
	for _, d := range dsts {
		d = strings.TrimSpace(d)
		if strings.Contains(d, "/") {
			if on {
				sh("ip", "route", "replace", d, "prohibit")
			} else {
				sh("ip", "route", "replace", d, "dev", egress)
			}
			continue
		}
		// Hostname: expand each resolved IP.
		if ips, err := net.LookupHost(d); err == nil {
			for _, ip := range ips {
				if strings.Contains(ip, ":") {
					continue
				}
				setKillswitch([]string{ip + "/32"}, on, egress)
			}
		}
	}
}

// vpnHealthy reports whether iface has a fresh handshake.
func vpnHealthy(iface string) bool {
	age := handshakeAge(iface)
	return age >= 0 && age < 180
}

// backoff sleeps with exponential backoff + jitter.
func backoff(attempt int) {
	base := 5 << attempt // 5,10,20,40...
	if base > 120 {
		base = 120
	}
	jitter := time.Duration(500+time.Now().UnixNano()%1500) * time.Millisecond
	time.Sleep(time.Duration(base)*time.Second + jitter)
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

func cmdDNS(args []string) {	fs := flag.NewFlagSet("dns", flag.ExitOnError)
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

// rotateStandby brings the next peer up on the standby iface and verifies it.
// Caller flips routes to the standby first, then drops the old peer.
func rotateStandby(peers []Peer, cur int, standby string, timeout int, verbose bool) (int, error) {
	n := len(peers)
	for k := 1; k <= n; k++ {
		next := (cur + k) % n
		p := peers[next]
		if verbose {
			fmt.Printf("🔄 Warming standby peer [%d] %s on %s\n", next, p.Name, standby)
		}
		if err := applyPeer(standby, p); err != nil {
			fmt.Printf("   ✗ apply failed: %v\n", err)
			continue
		}
		ok := false
		deadline := time.Now().Add(time.Duration(timeout) * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(2 * time.Second)
			if age := handshakeAge(standby); age >= 0 && age < 120 {
				ok = true
				break
			}
		}
		if !ok {
			fmt.Printf("   ✗ peer [%d] no handshake, trying next\n", next)
			continue
		}
		// Standby verified; caller flips routes, then drops old peer.
		if verbose {
			fmt.Printf("   ✅ peer [%d] %s warmed on %s\n", next, p.Name, standby)
		}
		return next, nil
	}
	return cur, fmt.Errorf("no healthy standby peer")
}

// ---- HTTP proxy (plain CONNECT passthrough, no MITM) ----

var reqCount int64

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
		if verbose {
			fmt.Printf("   ✗ dial failed: %v\n", err)
		}
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
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
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
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
	pid, _ := readProcFiles()
	if !procAlive(pid) {
		// Fallback: scan process list.
		if out, err := sh("pgrep", "-f", "wgtunnel pro[x]y"); err == nil && out != "" {
			fmt.Sscanf(strings.Fields(out)[0], "%d", &pid)
		}
	}
	if !procAlive(pid) {
		fmt.Println("wgtunnel proxy not running")
		os.Remove(proxyPIDFile)
		return
	}
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
	ensureDaemon(*iface)
	standby := *iface + "2"
	idx, err := activate(*iface, peers, 0, *timeout, *verbose)
	if err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}
	egress := *iface // interface currently carrying routed traffic
	routed := []string{}
	if *routes != "" {
		for _, r := range strings.Split(*routes, ",") {
			if r = strings.TrimSpace(r); r != "" {
				routed = append(routed, r)
			}
		}
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
		// Restore system DNS on clean shutdown.
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigc
			fmt.Println("\n🛑 shutting down, restoring DNS...")
			restoreDNS()
			os.Exit(0)
		}()
	}
	block := loadBlocklist(*blocklist)
	stats := loadStats(*statsPath)
	var activeIdx int64 = int64(idx)
	markActive := func() {
		i := int(atomic.LoadInt64(&activeIdx))
		st := stats[peers[i].Name]
		if st == nil {
			st = &PeerStats{}
			stats[peers[i].Name] = st
		}
		st.Requests++
		st.LastActive = time.Now().UTC().Format(time.RFC3339)
		saveStats(*statsPath, stats)
	}
	markActive()
	fmt.Println("================================================================================")
	fmt.Println("🚀 WGTunnel Proxy Started")
	fmt.Println("================================================================================")
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

	if *interval > 0 || *routes != "" || true {
		go func() {
			cur := idx
			failStreak := 0
			// Re-apply routes frequently (Android netd flushes ip rules).
			routeTick := time.NewTicker(15 * time.Second)
			defer routeTick.Stop()
			// Health monitor doubles as killswitch enforcer.
			healthTick := time.NewTicker(30 * time.Second)
			defer healthTick.Stop()
			rotTick := time.NewTicker(time.Duration(*interval) * time.Second)
			if *interval <= 0 {
				rotTick.Stop()
			} else {
				defer rotTick.Stop()
			}
			// Jitter rotation start so restarts don't thunder.
			time.Sleep(time.Duration(time.Now().UnixNano()%10) * time.Second)
			for {
				select {
				case <-routeTick.C:
					flipRoutes(egress)
				case <-healthTick.C:
					if vpnHealthy(egress) {
						if failStreak > 0 && *verbose {
							fmt.Println("✅ tunnel healthy again, killswitch off")
						}
						failStreak = 0
						setKillswitch(routed, false, egress)
						continue
					}
					failStreak++
					fmt.Printf("⚠️  tunnel unhealthy (streak %d) — killswitch ON, re-activating\n", failStreak)
					setKillswitch(routed, true, egress)
					backoff(failStreak)
					if next, err := activate(egress, peers, cur+1, *timeout, *verbose); err == nil {
						cur = next
						atomic.StoreInt64(&activeIdx, int64(cur))
						markActive()
					}
				case <-rotTick.C:
					ensureDaemon(standby)
					next, err := rotateStandby(peers, cur, standby, *timeout, *verbose)
					if err != nil {
						fmt.Println("⚠️  rotation failed, keeping current peer:", err)
						backoff(1)
						continue
					}
					// Flip traffic to warmed standby, drop old peer, swap roles.
					oldEgress, oldPeer := egress, cur
					egress = standby
					standby = oldEgress
					flipRoutes(egress)
					removePeer(standby, peers[oldPeer].PublicKey)
					cur = next
					atomic.StoreInt64(&activeIdx, int64(cur))
					markActive()
					snapshotTransfer(egress, peers[cur].Name, stats)
					saveStats(*statsPath, stats)
					fmt.Printf("🔄 Rotated to peer [%d] %s (egress %s)\n", cur, peers[cur].Name, egress)
				}
			}
		}()
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleCONNECT(w, r, *verbose, block, markActive)
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

func cmdRotate(args []string) {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	peersPath := fs.String("peers", "/root/wgtunnel/peers.json", "peer pool JSON")
	iface := fs.String("iface", "flare", "wireguard interface")
	timeout := fs.Int("timeout", 25, "handshake wait seconds per peer")
	verbose := fs.Bool("verbose", true, "verbose logging")
	fs.Parse(args)
	peers, err := loadPeers(*peersPath)
	if err != nil || len(peers) == 0 {
		fmt.Println("❌ load peers:", err)
		os.Exit(1)
	}
	ensureDaemon(*iface)
	// Start search after currently-implied peer is unknowable; just rotate to next
	// by reading a state file.
	state := "/tmp/wgtunnel.idx"
	start := 1
	if data, err := os.ReadFile(state); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			start = v + 1
		}
	}
	idx, err := activate(*iface, peers, start, *timeout, *verbose)
	if err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}
	os.WriteFile(state, []byte(strconv.Itoa(idx)), 0644)
	fmt.Printf("✅ Active peer [%d] %s\n", idx, peers[idx].Name)
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	peersPath := fs.String("peers", "/root/wgtunnel/peers.json", "peer pool JSON")
	iface := fs.String("iface", "flare", "wireguard interface")
	statsPath := fs.String("stats", "/tmp/wgtunnel-stats.json", "peer stats file")
	fs.Parse(args)
	peers, err := loadPeers(*peersPath)
	if err != nil || len(peers) == 0 {
		fmt.Println("❌ load peers:", err)
		os.Exit(1)
	}
	// Detect active peer by matching the configured endpoint.
	active := -1
	if dump, err := sh("wg", "show", *iface, "endpoints"); err == nil {
		for i, p := range peers {
			if strings.Contains(dump, p.Endpoint) {
				active = i
				break
			}
		}
	}
	age := handshakeAge(*iface)
	stats := loadStats(*statsPath)
	fmt.Printf("%-4s %-22s %-24s %-10s %-12s %s\n", "#", "NAME", "ENDPOINT", "REQUESTS", "TRANSFER", "STATUS")
	for i, p := range peers {
		pst := stats[p.Name]
		reqs, xfer := "-", "-"
		if pst != nil {
			reqs = strconv.FormatInt(pst.Requests, 10)
			xfer = fmt.Sprintf("↓%.1fMB ↑%.1fMB", float64(pst.RxBytes)/1048576, float64(pst.TxBytes)/1048576)
		}
		st := ""
		if i == active {
			if age >= 0 {
				st = fmt.Sprintf("✅ ACTIVE (handshake %ds ago)", age)
			} else {
				st = "⚠️  ACTIVE (no handshake yet)"
			}
		}
		fmt.Printf("%-4d %-22s %-24s %-10s %-12s %s\n", i, p.Name, p.Endpoint, reqs, xfer, st)
	}
}

func cmdExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	peersPath := fs.String("peers", "/root/wgtunnel/peers.json", "peer pool JSON")
	output := fs.String("output", "peers-backup.json", "backup file")
	fs.Parse(args)
	data, err := os.ReadFile(*peersPath)
	if err != nil {
		fmt.Println("❌ read:", err)
		os.Exit(1)
	}
	var peers []Peer
	if err := json.Unmarshal(data, &peers); err != nil {
		fmt.Println("❌ invalid peers.json:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*output, data, 0600); err != nil {
		fmt.Println("❌ write:", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Exported %d peers to %s (keep it secret!)\n", len(peers), *output)
}

func cmdImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	peersPath := fs.String("peers", "/root/wgtunnel/peers.json", "peer pool JSON")
	input := fs.String("input", "", "backup file to import")
	fs.Parse(args)
	if *input == "" {
		fmt.Println("❌ --input required")
		os.Exit(1)
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Println("❌ read:", err)
		os.Exit(1)
	}
	var peers []Peer
	if err := json.Unmarshal(data, &peers); err != nil || len(peers) == 0 {
		fmt.Println("❌ invalid backup (no peers)")
		os.Exit(1)
	}
	for _, p := range peers {
		if p.PrivateKey == "" || p.PublicKey == "" || p.Endpoint == "" {
			fmt.Println("❌ invalid backup (peer missing keys/endpoint)")
			os.Exit(1)
		}
	}
	if err := os.WriteFile(*peersPath, data, 0600); err != nil {
		fmt.Println("❌ write:", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Imported %d peers into %s\n", len(peers), *peersPath)
}

// cmdTest checks exit IP per peer on a scratch interface (default wgtest)
// without touching the live proxy interface. Restores test routes after.
func cmdTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	peersPath := fs.String("peers", "/root/wgtunnel/peers.json", "peer pool JSON")
	iface := fs.String("iface", "wgtest", "scratch wireguard interface")
	peerIdx := fs.Int("peer", -1, "test single peer index (default: all)")
	delay := fs.Int("delay", 8, "seconds between peers (avoids server-side session throttling)")
	timeout := fs.Int("timeout", 25, "handshake wait seconds per peer")
	fs.Parse(args)
	peers, err := loadPeers(*peersPath)
	if err != nil || len(peers) == 0 {
		fmt.Println("❌ load peers:", err)
		os.Exit(1)
	}
	targets := []int{}
	if *peerIdx >= 0 {
		if *peerIdx >= len(peers) {
			fmt.Println("❌ peer index out of range")
			os.Exit(1)
		}
		targets = append(targets, *peerIdx)
	} else {
		for i := range peers {
			targets = append(targets, i)
		}
	}
	ensureDaemon(*iface)
	// Resolve probe host once (direct DNS).
	probeIPOut, err := sh("python3", "-c", "import socket;print(socket.gethostbyname('api.ipify.org'))")
	if err != nil {
		fmt.Println("❌ dns failed:", err)
		os.Exit(1)
	}
	probeIP := strings.TrimSpace(probeIPOut)
	defer func() {
		sh("ip", "route", "del", probeIP+"/32", "dev", *iface)
		sh("ip", "rule", "del", "to", probeIP+"/32", "lookup", "main", "pref", "99")
		sh("ip", "link", "del", "dev", *iface)
	}()
	fmt.Printf("%-4s %-22s %-16s %s\n", "#", "NAME", "ENDPOINT", "EXIT IP")
	for ti, i := range targets {
		p := peers[i]
		if err := applyPeer(*iface, p); err != nil {
			fmt.Printf("%-4d %-22s %-16s ✗ apply: %v\n", i, p.Name, p.Endpoint, err)
			continue
		}
		ok := false
		deadline := time.Now().Add(time.Duration(*timeout) * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(2 * time.Second)
			if age := handshakeAge(*iface); age >= 0 && age < 120 {
				ok = true
				break
			}
		}
		if !ok {
			fmt.Printf("%-4d %-22s %-16s ✗ no handshake\n", i, p.Name, p.Endpoint)
			continue
		}
		sh("ip", "route", "replace", probeIP+"/32", "dev", *iface)
		sh("ip", "rule", "add", "to", probeIP+"/32", "lookup", "main", "pref", "99")
		time.Sleep(2 * time.Second)
		if !pathOK(probeIP, *iface) {
			fmt.Printf("%-4d %-22s %-16s ✗ kernel path not via %s\n", i, p.Name, p.Endpoint, *iface)
			continue
		}
		var out string
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			out, err = sh("curl", "-s", "--max-time", "15",
				"--resolve", "api.ipify.org:443:"+probeIP, "https://api.ipify.org")
			if err == nil && out != "" && !strings.Contains(out, "<") {
				break
			}
			time.Sleep(3 * time.Second)
		}
		if err != nil || out == "" || strings.Contains(out, "<") {
			fmt.Printf("%-4d %-22s %-16s ✗ probe failed\n", i, p.Name, p.Endpoint)
			continue
		}
		fmt.Printf("%-4d %-22s %-16s ✅ %s\n", i, p.Name, p.Endpoint, out)
		if ti < len(targets)-1 {
			time.Sleep(time.Duration(*delay) * time.Second)
		}
	}
}

func cmdStatus(args []string) {	fs := flag.NewFlagSet("status", flag.ExitOnError)
	iface := fs.String("iface", "flare", "wireguard interface")
	fs.Parse(args)
	out, err := sh("wg", "show", *iface)
	if err != nil {
		fmt.Println("interface down:", err)
		os.Exit(1)
	}
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "private key") {
			fmt.Println("  private key: (hidden)")
			continue
		}
		fmt.Println(" ", line)
	}
	if age := handshakeAge(*iface); age >= 0 {
		fmt.Printf("  last handshake: %ds ago\n", age)
	} else {
		fmt.Println("  last handshake: never")
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: wgtunnel <proxy|rotate|status|list|test|export|import|dns|stop|restart|boot> [options]")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "proxy":
		cmdProxy(os.Args[2:])
	case "rotate":
		cmdRotate(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "test":
		cmdTest(os.Args[2:])
	case "export":
		cmdExport(os.Args[2:])
	case "import":
		cmdImport(os.Args[2:])
	case "dns":
		cmdDNS(os.Args[2:])
	case "stop":
		cmdStop(os.Args[2:])
	case "restart":
		cmdRestart(os.Args[2:])
	case "boot":
		cmdBoot(os.Args[2:])
	default:
		fmt.Println("Unknown command:", os.Args[1])
		os.Exit(1)
	}
}
