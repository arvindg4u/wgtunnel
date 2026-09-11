package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
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
	if err := ensureDaemon(*iface); err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}
	// Start search after currently-implied peer is unknowable; just rotate to next
	// by reading a state file.
	state := "/tmp/wgtunnel.idx"
	start := 1
	if data, err := os.ReadFile(state); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			start = v + 1
		}
	}
	idx, err := activate(*iface, peers, start, *timeout, *verbose, nil, "opencode.ai")
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
	// Detect active peer across all live flare ifaces (egress alternates
	// between flare/flare2 on rotation; checking one misses the live one).
	ifaces := liveIfaces(*iface)
	active := -1
	activeIface := ""
	var age int64 = -1
	for _, ifname := range ifaces {
		dump, err := sh("wg", "show", ifname, "endpoints")
		if err != nil {
			continue
		}
		for i, p := range peers {
			if strings.Contains(dump, p.Endpoint) {
				// Prefer the iface actually carrying routed traffic.
				if activeIface == "" || egressIface(ifname) {
					active, activeIface = i, ifname
					age = handshakeAge(ifname)
				}
				break
			}
		}
	}
	stats := loadStats(*statsPath)
	fmt.Printf("%-4s %-22s %-24s %-10s %-10s %-10s %-22s %s\n", "#", "NAME", "ENDPOINT", "REQUESTS", "TODAY(IST)", "LASTDAY", "TRANSFER", "STATUS")
	for i, p := range peers {
		pst := stats[p.Name]
		reqs, today, lastday, xfer := "-", "-", "-", "-"
		if pst != nil {
			reqs = strconv.FormatInt(pst.Requests, 10)
			// Show live day bucket; roll display-only so `list` never
			// shows yesterday's count as today.
			dr, lr := pst.DayRequests, pst.LastDayRequests
			if pst.Day != "" && pst.Day != istToday() {
				lr, dr = dr, 0
			}
			today = strconv.FormatInt(dr, 10)
			lastday = strconv.FormatInt(lr, 10)
			xfer = fmt.Sprintf("↓%.1fMB ↑%.1fMB", float64(pst.RxBytes)/1048576, float64(pst.TxBytes)/1048576)
		}
		st := ""
		if skip, left := peerCooldown(stats, p.Name); skip {
			pst := stats[p.Name]
			st = fmt.Sprintf("⏭️  COOLDOWN (%s, %d fails)", left, pst.DialFails)
		}
		if i == active {
			if age >= 0 {
				st = fmt.Sprintf("✅ ACTIVE on %s (handshake %ds ago)", activeIface, age)
			} else {
				st = fmt.Sprintf("⚠️  ACTIVE on %s (no handshake yet)", activeIface)
			}
		}
		fmt.Printf("%-4d %-22s %-24s %-10s %-10s %-10s %-22s %s\n", i, p.Name, p.Endpoint, reqs, today, lastday, xfer, st)
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
	if err := ensureDaemon(*iface); err != nil {
		fmt.Println("❌", err)
		os.Exit(1)
	}
	// Data-path check hits opencode.ai (what we route): generic IP-echo
	// hosts may be blocked via tunnel egress while real traffic works.
	probeHost := "opencode.ai"
	defer func() {
		sh("ip", "link", "del", "dev", *iface)
	}()
	fmt.Printf("%-4s %-22s %-16s %s\n", "#", "NAME", "ENDPOINT", "PROBE "+probeHost)
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
		if !probeDataPath(*iface, 15, probeHost) {
			fmt.Printf("%-4d %-22s %-16s ✗ probe failed\n", i, p.Name, p.Endpoint)
			continue
		}
		fmt.Printf("%-4d %-22s %-16s ✅ data ok\n", i, p.Name, p.Endpoint)
		if ti < len(targets)-1 {
			time.Sleep(time.Duration(*delay) * time.Second)
		}
	}
}

// egressIface reports whether kernel routes opencode.ai via ifname.
// Used to pick the traffic-carrying interface when several are up.
func egressIface(ifname string) bool {
	out, err := sh("ip", "route", "get", "172.65.90.22")
	if err != nil {
		return false
	}
	return strings.Contains(out, "dev "+ifname)
}

// liveIfaces returns flare-family interfaces that exist, defaulting to
// the requested one when nothing else is up.
func liveIfaces(want string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		if _, err := sh("wg", "show", name, "endpoints"); err != nil {
			return
		}
		seen[name] = true
		out = append(out, name)
	}
	add(want)
	// The proxy alternates egress between flare and flare2 on rotation.
	for _, alt := range []string{"flare", "flare2"} {
		add(alt)
	}
	if len(out) == 0 {
		return []string{want}
	}
	return out
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	iface := fs.String("iface", "flare", "wireguard interface (default shows all live flare ifaces)")
	fs.Parse(args)
	// Was --iface explicitly passed? If so, honor exactly that.
	explicit := false
	for _, a := range args {
		if strings.HasPrefix(a, "--iface") || strings.HasPrefix(a, "-iface") {
			explicit = true
			break
		}
	}
	ifaces := []string{*iface}
	if !explicit {
		ifaces = liveIfaces(*iface)
	}
	for n, ifname := range ifaces {
		if len(ifaces) > 1 && n > 0 {
			fmt.Println()
		}
		if len(ifaces) > 1 {
			fmt.Printf("── %s ──\n", ifname)
		}
		out, err := sh("wg", "show", ifname)
		if err != nil {
			fmt.Println("interface down:", err)
			continue
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
		if age := handshakeAge(ifname); age >= 0 {
			fmt.Printf("  last handshake: %ds ago\n", age)
		} else {
			fmt.Println("  last handshake: never")
		}
	}
}
