package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

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
				ensureRoute6(ip + "/128")
				continue
			}
			ensureRoute(ip+"/32", dev)
		}
		return
	}
	sh("ip", "route", "replace", dst, "dev", dev)
	sh("ip", "rule", "add", "to", dst, "lookup", "main", "pref", "100")
}

// ensureRoute6 fail-closes IPv6 for a routed destination: the tunnel carries
// no v6 address, so v6 to routed hosts must error, never leak direct.
func ensureRoute6(dst string) {
	sh("ip", "-6", "route", "replace", "prohibit", dst)
	sh("ip", "-6", "rule", "add", "to", dst, "lookup", "main", "pref", "100")
}

// resolveRoutedIPs expands routed hostnames/CIDRs into v4 and v6 address lists.
func resolveRoutedIPs(routed []string) (v4, v6 []string) {
	for _, d := range routed {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.Contains(d, "/") {
			if strings.Contains(d, ":") {
				v6 = append(v6, d)
			} else {
				v4 = append(v4, d)
			}
			continue
		}
		if ips, err := net.LookupHost(d); err == nil {
			for _, ip := range ips {
				if strings.Contains(ip, ":") {
					v6 = append(v6, ip+"/128")
				} else {
					v4 = append(v4, ip+"/32")
				}
			}
		}
	}
	return v4, v6
}

// delRouteBestEffort removes a destination route in dev or prohibit form, v4/v6.
func delRouteBestEffort(dst string) {
	v6 := strings.Contains(dst, ":")
	ip := func(args ...string) {
		if v6 {
			args = append([]string{"-6"}, args...)
		}
		sh("ip", args...)
	}
	ip("route", "del", dst)
	ip("route", "del", "prohibit", dst)
}

// cleanupRoutes removes everything ensureRoute/flipRoutes/probes added for
// the given routed list, plus wgtunnel-owned policy-rule leftovers.
func cleanupRoutes(routed []string) {
	if len(routed) == 0 {
		return
	}
	fmt.Printf("🧹 cleaning routes/rules for %s ...\n", strings.Join(routed, ","))
	v4, v6 := resolveRoutedIPs(routed)
	for _, dst := range v4 {
		delRouteBestEffort(dst)
		sh("ip", "rule", "del", "to", dst, "lookup", "main", "pref", "100")
		sh("ip", "rule", "del", "to", dst, "lookup", "main", "pref", "99")
	}
	for _, dst := range v6 {
		delRouteBestEffort(dst)
		sh("ip", "-6", "rule", "del", "to", dst, "lookup", "main", "pref", "100")
	}
	sweepProbeRules()
}

// sweepProbeRules deletes leftover wgtunnel policy rules (prefs 99/100,
// lookup main). Those pref numbers are wgtunnel-owned; Android system rules
// live at pref 10000+.
func sweepProbeRules() {
	out, err := sh("ip", "rule", "show")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "lookup main") {
			continue
		}
		if !strings.Contains(line, "pref 99") && !strings.Contains(line, "pref 100") {
			continue
		}
		f := strings.Fields(line)
		for i, w := range f {
			if w == "to" && i+1 < len(f) {
				dst := f[i+1]
				pref := "100"
				if strings.Contains(line, "pref 99") {
					pref = "99"
				}
				sh("ip", "rule", "del", "to", dst, "lookup", "main", "pref", pref)
			}
		}
	}
}

// pathOK reports whether kernel would send ip via dev.
func pathOK(ip, dev string) bool {
	out, err := sh("ip", "route", "get", ip)
	return err == nil && strings.Contains(out, "dev "+dev)
}

// ---- Killswitch (fail-closed): routed destinations must never leak direct.
// When VPN is unhealthy we point them at a prohibit route instead of
// removing routes (absence would fall through to the direct tables).

func setKillswitch(dsts []string, on bool, egress string) {
	for _, d := range dsts {
		d = strings.TrimSpace(d)
		if strings.Contains(d, "/") {
			if on {
				if out, err := sh("ip", "route", "replace", "prohibit", d); err != nil {
					fmt.Printf("   ⚠️  killswitch route %s: %v %s\n", d, err, strings.TrimSpace(out))
				}
			} else {
				sh("ip", "route", "replace", d, "dev", egress)
			}
			continue
		}
		// Hostname: expand each resolved IP (v4 via egress, v6 fail-closed).
		if ips, err := net.LookupHost(d); err == nil {
			for _, ip := range ips {
				if strings.Contains(ip, ":") {
					if on {
						sh("ip", "-6", "route", "replace", "prohibit", ip+"/128")
					} else {
						ensureRoute6(ip + "/128")
					}
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
