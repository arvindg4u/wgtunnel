package main

import "testing"

func TestSavedProxyRoutes(t *testing.T) {
	saved := []string{"proxy", "--iface", "flare", "--listen", "127.0.0.1:8080",
		"--interval", "1800", "--route", "opencode.ai, example.com", "--verbose"}
	routes := savedProxyRoutes(saved)
	if len(routes) != 2 || routes[0] != "opencode.ai" || routes[1] != "example.com" {
		t.Errorf("unexpected routes: %q", routes)
	}
	if routes := savedProxyRoutes([]string{"proxy"}); len(routes) != 0 {
		t.Errorf("no --route flag must yield no routes: %q", routes)
	}
	if routes := savedProxyRoutes(nil); len(routes) != 0 {
		t.Errorf("nil args must yield no routes: %q", routes)
	}
}
