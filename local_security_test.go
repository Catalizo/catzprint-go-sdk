package catzprint

// Regression tests for the security review (FINDINGS.md H4, M6, M7, M8) and
// SPEC addendum 1 (A10, A11, A12, A15).

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// H4 (reviewer's TestRevMDNSHostnameImpostor): an mDNS impostor copying a
// real station's ID and announcing its own public-cert hostname must not
// produce a hostname target, nor its own fingerprint; with no cloud list an
// announcement alone produces nothing.
func TestRevMDNSHostnameImpostor(t *testing.T) {
	realFP, evilFP := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	l := &localState{c: &Client{}, cfg: LocalConfig{Discover: true}}
	st := &StoredToken{StationsUpdatedAt: time.Now(), Stations: []LocalEndpoint{{
		StationID: "real-station", LocalEnabled: true, TLSMode: "public", Port: 7443,
		CertFingerprintSHA256: realFP, Addresses: []string{"192.168.1.20"}}}}
	evil := mdnsStation{StationID: "real-station", Port: 7443, TLSMode: "public", Fingerprint: evilFP,
		Hostname: "192-168-1-66.attackerlbl.local.catzprint.com", Addresses: []string{"192.168.1.66"}}
	var targets []stationTarget
	for _, d := range l.acceptedMDNS([]mdnsStation{evil}, st) {
		targets = append(targets, mdnsTargets(d)...)
	}
	if len(targets) != 1 {
		t.Fatalf("targets %+v", targets)
	}
	tg := targets[0]
	if tg.URL != "https://192.168.1.66:7443" || !tg.needsPin() || tg.Fingerprint != realFP || strings.Contains(tg.URL, "attackerlbl") {
		t.Fatalf("impostor target not pinned to the cloud's fingerprint: %+v", tg)
	}
	// No endpoint list (paired device): the announced fingerprint is not trusted.
	if got := l.acceptedMDNS([]mdnsStation{{StationID: "x", Port: 7443, TLSMode: "self_signed", Fingerprint: evilFP, Addresses: []string{"192.168.1.66"}}}, nil); len(got) != 0 {
		t.Fatalf("mDNS-only station trusted: %+v", got)
	}
	// Public addresses announced over mDNS are dropped (M6).
	pub := evil
	pub.Addresses = []string{"203.0.113.9"}
	if got := l.acceptedMDNS([]mdnsStation{pub}, st); len(got) != 0 {
		t.Fatalf("public mDNS address used: %+v", got)
	}
}

// M6/A10: IP URLs from the endpoint list must be private; hostnames are only
// dialled directly under their own label.
func TestEndpointTargetsFilter(t *testing.T) {
	fp := strings.Repeat("cd", 32)
	ts := endpointTargets(LocalEndpoint{StationID: "s", TLSMode: "public", LocalLabel: "abcdefghij", CertFingerprintSHA256: fp,
		PublicSPKISHA256: strings.Repeat("ef", 32), URLs: []string{
			"https://192-168-1-20.abcdefghij.local.catzprint.com:7443", "https://192.168.1.20:7443", "https://203.0.113.9:7443", "https://[fd00::1]:7443"}}, "cloud")
	if len(ts) != 3 {
		t.Fatalf("targets %+v", ts)
	}
	if ts[0].Label != "abcdefghij" || ts[0].SPKI != strings.Repeat("ef", 32) || ts[0].needsPin() {
		t.Fatalf("hostname target %+v", ts[0])
	}
	if ts[1].Fingerprint != fp || ts[2].URL != "https://[fd00::1]:7443" {
		t.Fatalf("ip targets %+v", ts[1:])
	}
}

// M7/A11: re-mint only on token_expired, never on device_revoked or
// unauthenticated, and at most once per 10 minutes per store key.
func TestRemintRules(t *testing.T) {
	for _, code := range []string{"device_revoked", "unauthenticated"} {
		t.Run(code, func(t *testing.T) {
			fc := newFakeCloud(t)
			st := newFakeStation(t, nil)
			st.accept = func(string) bool { return false }
			st.rejectCode = code
			c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
			_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
			if ErrorCode(err) != code {
				t.Fatalf("got %v", err)
			}
			if m, _ := fc.counts(); m != 1 || len(st.jobRequests()) != 1 {
				t.Fatalf("re-minted on %s: mints=%d attempts=%d", code, m, len(st.jobRequests()))
			}
		})
	}
	t.Run("rate limit is persisted per store key", func(t *testing.T) {
		fc := newFakeCloud(t)
		st := newFakeStation(t, nil)
		st.accept = func(string) bool { return false }
		store := NewFileTokenStore(filepath.Join(t.TempDir(), "t.json"))
		cfg := LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, TokenStore: store}
		for i := 0; i < 3; i++ { // three clients (restarts) within 10 minutes
			c := newLocalClient(t, fc, cfg)
			if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); ErrorCode(err) != "token_expired" {
				t.Fatalf("got %v", err)
			}
		}
		if m, _ := fc.counts(); m != 2 { // the first mint + one re-mint
			t.Fatalf("mints %d", m)
		}
		// After 10 minutes one more re-mint is allowed.
		c := newLocalClient(t, fc, cfg)
		c.local.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
		_, _ = c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		if m, _ := fc.counts(); m != 3 {
			t.Fatalf("mints after interval %d", m)
		}
	})
}

// A11: minted tokens are bound to LocationID by default.
func TestMintBoundToLocation(t *testing.T) {
	if _, err := NewClient(WithAPIKey(fakeKey), WithLocal(LocalConfig{Mode: ModeLocal, Discover: true})); err == nil {
		t.Fatal("org-wide minting without AllLocations accepted")
	}
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, LocationID: "loc9", StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); err != nil {
		t.Fatal(err)
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if got := fc.mints[0]["location_ids"]; len(got.([]any)) != 1 || got.([]any)[0] != "loc9" {
		t.Fatalf("mint not location-bound: %v", fc.mints[0])
	}
}

// M8/A12: Pair needs the fingerprint from the station app or the cloud list.
func TestPairRequiresTrust(t *testing.T) {
	st := newFakeStation(t, nil)
	offline := &fakeCloud{srv: &httptest.Server{}}
	c := newLocalClient(t, offline, LocalConfig{Mode: ModeCloud})
	ctx := context.Background()

	if _, err := c.Local.Pair(ctx, st.url, "12345678", "Till"); ErrorCode(err) != "invalid" || len(st.requests()) != 0 {
		t.Fatalf("pairing without a fingerprint: %v (requests %d)", err, len(st.requests()))
	}
	_, err := c.Local.Pair(ctx, st.url, "12345678", "Till", PairFingerprint(strings.Repeat("ab", 32)))
	var pm *PinMismatchError
	var sue *StationUnreachableError
	if !errors.As(err, &sue) || !errors.As(sue.Attempts[0].Err, &pm) || len(st.requests()) != 0 {
		t.Fatalf("relay not detected: %v", err)
	}
	host := "https://127-0-0-1.abcdefghij.local.catzprint.com:" + st.url[strings.LastIndex(st.url, ":")+1:]
	if _, err := c.Local.Pair(ctx, host, "12345678", "Till"); ErrorCode(err) != "invalid" {
		t.Fatalf("unknown hostname accepted: %v", err)
	}
	p, err := c.Local.Pair(ctx, st.url, "12345678", "Till", PairFingerprint(strings.ToUpper(st.fp)))
	if err != nil || p.Token != "czd_paired" {
		t.Fatalf("pair %v %v", p, err)
	}
}

// A15: LocalJob.live maps to Job.Live; paired devices are live.
func TestLocalJobLive(t *testing.T) {
	st := newFakeStation(t, nil)
	offline := &fakeCloud{srv: &httptest.Server{}}
	c := newLocalClient(t, offline, LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, Token: "czd_paired"})
	j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	if err != nil || !j.Live {
		t.Fatalf("paired device job not live: %v %v", j, err)
	}
	f := false
	st.live = &f
	j, err = c.Jobs.Create(context.Background(), JobParams{Text: "y"})
	if err != nil || j.Live || j.Local.Live == nil || *j.Local.Live {
		t.Fatalf("station live=false ignored: %+v %v", j, err)
	}
}

// E2E: a paired device needs no API key in local mode.
func TestPairedDeviceWithoutAPIKey(t *testing.T) {
	t.Setenv("CATZPRINT_API_KEY", "")
	st := newFakeStation(t, nil)
	if _, err := NewClient(WithLocal(LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, Token: "czd_paired"})); err == nil {
		t.Fatal("local_first without an API key accepted")
	}
	if _, err := NewClient(WithLocal(LocalConfig{Mode: ModeLocal, LocationID: "l", StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})); err == nil {
		t.Fatal("local mode without a key or token accepted")
	}
	c, err := NewClient(WithLocal(LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, Token: "czd_paired", Discover: true, DiscoverTimeout: 50 * time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	j, err := c.Jobs.Create(context.Background(), JobParams{Role: "kitchen", Text: "x"})
	if err != nil || j.Via != ViaLocal {
		t.Fatalf("got %v %v", j, err)
	}
	if _, err := c.Local.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Printers.List(context.Background()); ErrorCode(err) != "missing_api_key" {
		t.Fatalf("cloud call: %v", err)
	}
}
