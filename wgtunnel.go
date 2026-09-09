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
	"strconv"
	"strings"
	"sync/atomic"
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

// ---- HTTP proxy (plain CONNECT passthrough, no MITM) ----

var reqCount int64

func handleCONNECT(w http.ResponseWriter, r *http.Request, verbose bool) {
	host := r.Host
	if verbose {
		n := atomic.AddInt64(&reqCount, 1)
		fmt.Printf("\n🔒 [CONNECT #%d] %s\n", n, host)
	}
	serverConn, err := net.DialTimeout("tcp", host, 15*time.Second)
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

func handleHTTP(w http.ResponseWriter, r *http.Request, verbose bool) {
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

func cmdProxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	peersPath := fs.String("peers", "peers.json", "peer pool JSON")
	listen := fs.String("listen", "127.0.0.1:8080", "proxy listen address")
	iface := fs.String("iface", "flare", "wireguard interface")
	interval := fs.Int("interval", 300, "peer rotation seconds (0 = no rotation)")
	timeout := fs.Int("timeout", 25, "handshake wait seconds per peer")
	routes := fs.String("route", "", "comma-separated hosts/CIDRs to route via tunnel (re-applied every 60s)")
	verbose := fs.Bool("verbose", false, "verbose logging")
	fs.Parse(args)

	peers, err := loadPeers(*peersPath)
	if err != nil || len(peers) == 0 {
		fmt.Println("❌ load peers:", err)
		os.Exit(1)
	}
	ensureDaemon(*iface)
	idx, err := activate(*iface, peers, 0, *timeout, *verbose)
	if err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}
	fmt.Println("================================================================================")
	fmt.Println("🚀 WGTunnel Proxy Started")
	fmt.Println("================================================================================")
	fmt.Printf("📡 Listening: %s\n", *listen)
	fmt.Printf("🔗 Active peer: [%d] %s\n", idx, peers[idx].Name)
	fmt.Printf("🔄 Rotation: every %ds across %d peers\n", *interval, len(peers))
	if *routes != "" {
		fmt.Printf("🛣️  Routed: %s (re-applied every 15s)\n", *routes)
		for _, r := range strings.Split(*routes, ",") {
			ensureRoute(strings.TrimSpace(r), *iface)
		}
	}
	fmt.Println("📝 Proxy Configuration:")
	fmt.Printf("   HTTP Proxy:  %s\n", *listen)
	fmt.Printf("   HTTPS Proxy: %s\n", *listen)

	if *interval > 0 || *routes != "" {
		go func() {
			cur := idx
			// Re-apply routes frequently (Android netd flushes ip rules).
			routeTick := time.NewTicker(15 * time.Second)
			defer routeTick.Stop()
			rotTick := time.NewTicker(time.Duration(*interval) * time.Second)
			if *interval <= 0 {
				rotTick.Stop()
			} else {
				defer rotTick.Stop()
			}
			for {
				select {
				case <-routeTick.C:
					if *routes != "" {
						for _, r := range strings.Split(*routes, ",") {
							ensureRoute(strings.TrimSpace(r), *iface)
						}
					}
				case <-rotTick.C:
					next, err := activate(*iface, peers, cur+1, *timeout, *verbose)
					if err != nil {
						fmt.Println("⚠️  rotation failed, keeping current peer:", err)
						continue
					}
					cur = next
					fmt.Printf("🔄 Rotated to peer [%d] %s\n", cur, peers[cur].Name)
					if *routes != "" {
						for _, r := range strings.Split(*routes, ",") {
							ensureRoute(strings.TrimSpace(r), *iface)
						}
					}
				}
			}
		}()
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			handleCONNECT(w, r, *verbose)
			return
		}
		handleHTTP(w, r, *verbose)
	})
	srv := &http.Server{Addr: *listen, Handler: handler}
	// Suppress per-request server error spam on hijacked conns.
	srv.ErrorLog = nil
	if err := srv.ListenAndServe(); err != nil {
		fmt.Println("server stopped:", err)
	}
}

func cmdRotate(args []string) {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	peersPath := fs.String("peers", "peers.json", "peer pool JSON")
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
	peersPath := fs.String("peers", "peers.json", "peer pool JSON")
	iface := fs.String("iface", "flare", "wireguard interface")
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
	fmt.Printf("%-4s %-22s %-24s %s\n", "#", "NAME", "ENDPOINT", "STATUS")
	for i, p := range peers {
		st := ""
		if i == active {
			if age >= 0 {
				st = fmt.Sprintf("✅ ACTIVE (handshake %ds ago)", age)
			} else {
				st = "⚠️  ACTIVE (no handshake yet)"
			}
		}
		fmt.Printf("%-4d %-22s %-24s %s\n", i, p.Name, p.Endpoint, st)
	}
}

// cmdTest checks exit IP per peer on a scratch interface (default wgtest)
// without touching the live proxy interface. Restores test routes after.
func cmdTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	peersPath := fs.String("peers", "peers.json", "peer pool JSON")
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
		fmt.Println("Usage: wgtunnel <proxy|rotate|status|list|test> [options]")
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
	default:
		fmt.Println("Unknown command:", os.Args[1])
		os.Exit(1)
	}
}
