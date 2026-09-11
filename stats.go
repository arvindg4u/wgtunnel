package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ---- Peer stats (persisted) ----

type PeerStats struct {
	Requests        int64  `json:"requests"`
	LastActive      string `json:"last_active"`
	RxBytes         uint64 `json:"rx_bytes"`
	TxBytes         uint64 `json:"tx_bytes"`
	DialFails       int64  `json:"dial_fails"`
	LastFail        string `json:"last_fail,omitempty"`
	Day             string `json:"day,omitempty"` // IST date bucket YYYY-MM-DD
	DayRequests     int64  `json:"day_requests"`
	LastDayRequests int64  `json:"last_day_requests"`
}

// istZone is Asia/Kolkata without loading tzdata (fixed +05:30).
var istZone = time.FixedZone("IST", 5*3600+1800)

func istToday() string { return time.Now().In(istZone).Format("2006-01-02") }

// rollDay moves a stale day bucket into LastDayRequests. Called on every
// counted request so idle days still roll on next activity (no ticker needed).
func rollDay(st *PeerStats) {
	today := istToday()
	if st.Day == "" {
		st.Day = today
		return
	}
	if st.Day != today {
		st.LastDayRequests = st.DayRequests
		st.DayRequests = 0
		st.Day = today
	}
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

// transferTracker accumulates per-peer traffic from raw wg counters.
// wg counters are per-interface (reset when the peer changes), so we track
// the last-seen baseline and credit only the delta to the active peer.
type transferTracker struct {
	lastRx, lastTx uint64
	haveBaseline   bool
}

// credit attributes counter movement on iface to peerName since the last
// call. Call with the CURRENT active peer on every tick; call reset() when
// switching peers so the new peer's baseline starts clean.
func (t *transferTracker) credit(iface, peerName string, m map[string]*PeerStats) {
	rx, tx, err := ifaceTransfer(iface)
	if err != nil {
		return
	}
	if !t.haveBaseline {
		t.lastRx, t.lastTx = rx, tx
		t.haveBaseline = true
		return
	}
	st := m[peerName]
	if st == nil {
		st = &PeerStats{}
		m[peerName] = st
	}
	// Counters reset on peer change; a drop means a fresh baseline.
	if rx >= t.lastRx {
		st.RxBytes += rx - t.lastRx
	}
	if tx >= t.lastTx {
		st.TxBytes += tx - t.lastTx
	}
	t.lastRx, t.lastTx = rx, tx
}

// reset starts a fresh baseline (call after switching peers/interfaces).
func (t *transferTracker) reset(iface string) {
	if rx, tx, err := ifaceTransfer(iface); err == nil {
		t.lastRx, t.lastTx = rx, tx
	}
	t.haveBaseline = true
}

// snapshotTransfer credits iface movement since the tracker's baseline to
// peerName (used at rotation/failover boundaries).
func snapshotTransfer(tr *transferTracker, iface, peerName string, m map[string]*PeerStats) {
	tr.credit(iface, peerName, m)
}

// peerCooldown reports whether peerName failed recently and should be
// skipped this rotation round. Cooldown scales with failure count
// (5min × fails, capped at 1h) so flaky peers get another chance later.
func peerCooldown(m map[string]*PeerStats, peerName string) (bool, string) {
	st := m[peerName]
	if st == nil || st.LastFail == "" {
		return false, ""
	}
	// LastFail format: RFC3339 + " " + reason.
	ts, _, _ := strings.Cut(st.LastFail, " ")
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return false, ""
	}
	cool := time.Duration(st.DialFails) * 5 * time.Minute
	if cool > time.Hour {
		cool = time.Hour
	}
	if remain := time.Until(t.Add(cool)); remain > 0 {
		return true, fmt.Sprintf("%.0fm left", remain.Minutes()+1)
	}
	return false, ""
}
