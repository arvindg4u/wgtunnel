package main

// WGTunnel - rotating WireGuard peer pool with a local HTTP proxy.
// WireGuard counterpart to FlareTunnel: instead of Cloudflare Workers,
// egress rotates across N WireGuard peers (one active at a time).
//
// Usage:
//   ./wgtunnel proxy --peers peers.json --listen 127.0.0.1:8080 --interval 300 --verbose
//   ./wgtunnel rotate --peers peers.json --iface flare --once
//   ./wgtunnel status --iface flare

import (
	"fmt"
	"os"
)

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
