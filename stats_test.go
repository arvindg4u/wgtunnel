package main

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestPeerCooldown(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)

	if skip, _ := peerCooldown(map[string]*PeerStats{}, "ghost"); skip {
		t.Error("unknown peer should not be in cooldown")
	}
	m := map[string]*PeerStats{
		"fresh-fail": {DialFails: 1, LastFail: now + " dial timeout"},
		"old-fail":   {DialFails: 1, LastFail: time.Now().UTC().Add(-2*time.Hour).Format(time.RFC3339) + " dial timeout"},
		"capped":     {DialFails: 100, LastFail: time.Now().UTC().Add(-30*time.Minute).Format(time.RFC3339) + " dial timeout"},
		"bad-ts":     {DialFails: 3, LastFail: "not-a-time"},
	}
	if skip, left := peerCooldown(m, "fresh-fail"); !skip || left == "" {
		t.Error("recent fail should be in cooldown with remaining time")
	}
	if skip, _ := peerCooldown(m, "old-fail"); skip {
		t.Error("2h-old single fail (5min cooldown) should have expired")
	}
	if skip, _ := peerCooldown(m, "capped"); !skip {
		t.Error("100 fails within capped 1h cooldown should still skip")
	}
	if skip, _ := peerCooldown(m, "bad-ts"); skip {
		t.Error("unparseable timestamp should not trigger cooldown")
	}
}

func TestRollDay(t *testing.T) {
	today := istToday()
	if today != time.Now().In(istZone).Format("2006-01-02") {
		t.Errorf("istToday=%q not IST date", today)
	}

	st := &PeerStats{Day: today, DayRequests: 7, LastDayRequests: 3}
	rollDay(st)
	if st.DayRequests != 7 || st.LastDayRequests != 3 || st.Day != today {
		t.Errorf("same-day roll must be a no-op: %+v", st)
	}

	st = &PeerStats{Day: "2000-01-01", DayRequests: 7, LastDayRequests: 3}
	rollDay(st)
	if st.DayRequests != 0 || st.LastDayRequests != 7 || st.Day != today {
		t.Errorf("day change must roll over: %+v", st)
	}

	st = &PeerStats{Requests: 42}
	rollDay(st)
	if st.Day != today || st.DayRequests != 0 {
		t.Errorf("empty day must init bucket: %+v", st)
	}
}

func TestPickProbeHosts(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"opencode.ai"}, []string{"opencode.ai"}},
		{[]string{"10.0.0.1/8", "example.com"}, []string{"example.com"}},
		{[]string{"a.example.com", "b.example.com", "a.example.com"}, []string{"a.example.com", "b.example.com"}},
		{[]string{"1.2.3.0/24"}, []string{"opencode.ai"}},
		{[]string{"", "  "}, []string{"opencode.ai"}},
		{nil, []string{"opencode.ai"}},
		{[]string{"172.65.90.22"}, []string{"opencode.ai"}},
	}
	for _, c := range cases {
		got := pickProbeHosts(c.in)
		if len(got) != len(c.want) {
			t.Errorf("pickProbeHosts(%q)=%q want %q", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("pickProbeHosts(%q)=%q want %q", c.in, got, c.want)
				break
			}
		}
	}
}

func TestFillDashLiveCountdown(t *testing.T) {
	start := time.Now().Add(-100 * time.Second)
	atomic.StoreInt64(&lastRotateUnix, start.Unix())
	var st dashStatus
	fillDashLive(&st, 1800, "opencode.ai", "127.0.0.1:8080", start)
	if st.UptimeS < 99 || st.UptimeS > 110 {
		t.Errorf("uptime=%d want ~100", st.UptimeS)
	}
	if st.RotateInS < 1690 || st.RotateInS > 1700 {
		t.Errorf("rotate_in=%d want ~1700 (no rotation since start)", st.RotateInS)
	}
	if st.Rotating {
		t.Error("rotating should be false with no rotation in flight")
	}
	atomic.StoreInt64(&rotating, 1)
	fillDashLive(&st, 1800, "", "", start)
	if !st.Rotating {
		t.Error("rotating flag should reflect in-flight rotation")
	}
	atomic.StoreInt64(&rotating, 0)
}

func TestRateLimitCooldown15h(t *testing.T) {
	now := time.Now().UTC()
	m := map[string]*PeerStats{
		"limited": {DialFails: 1, RateLimitedAt: now.Format(time.RFC3339),
			LastFail: now.Format(time.RFC3339) + " 429/manual SIGUSR1"},
		"expired": {DialFails: 1, RateLimitedAt: now.Add(-16 * time.Hour).Format(time.RFC3339)},
		"bad-ts":  {RateLimitedAt: "not-a-time"},
	}
	skip, left := peerCooldown(m, "limited")
	if !skip || left == "" {
		t.Errorf("429-marked peer must hold 15h window, got skip=%v left=%q", skip, left)
	}
	if skip, _ := peerCooldown(m, "expired"); skip {
		t.Error("16h-old 429 mark must have expired")
	}
	if m["expired"].RateLimitedAt != "" {
		t.Error("expired mark should be cleared")
	}
	if skip, _ := peerCooldown(m, "bad-ts"); skip {
		t.Error("unparseable mark must not trigger cooldown")
	}
}

func TestFmtLeft(t *testing.T) {
	if got := fmtLeft(45*time.Minute + 10*time.Second); got != "46m left" {
		t.Errorf("fmtLeft sub-hour = %q", got)
	}
	if got := fmtLeft(14*time.Hour + 5*time.Minute); got != "14h05m left" {
		t.Errorf("fmtLeft multi-hour = %q", got)
	}
}
