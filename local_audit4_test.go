package catzprint

// Regression tests for SDK addendum 2 (audit round 4): the auditor's proofs
// (scratchpad/audit4/sdk/go/zz_audit4_test.go) as assertions, plus one test
// per SDK-1 branch.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func twoStations(t *testing.T, mode LocalMode) (*fakeCloud, *fakeStation, *fakeStation, *Client) {
	fc := newFakeCloud(t)
	a, b := newFakeStation(t, nil), newFakeStation(t, nil)
	c := newLocalClient(t, fc, LocalConfig{Mode: mode, StationURLs: []string{a.url, b.url},
		Fingerprints: map[string]string{a.url: a.fp, b.url: b.fp}, RequestTimeout: 300 * time.Millisecond})
	return fc, a, b, c
}

// Auditor's proof: a station that got the job but answered late made the SDK
// post it to the next station (printed twice). Now: OutcomeUnknown, B untouched.
func TestAudit4AmbiguousTimeoutSecondStation(t *testing.T) {
	_, a, b, c := twoStations(t, ModeLocal)
	a.delay = 2 * time.Second // got the job, answers late; the probe is slow too
	_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "order-7"})
	var ou *OutcomeUnknownError
	if !errors.As(err, &ou) || !IsOutcomeUnknown(err) || ErrorCode(err) != "outcome_unknown" {
		t.Fatalf("want OutcomeUnknown, got %T %v", err, err)
	}
	if ou.URL != a.url || ou.IdempotencyKey != "order-7" || !strings.Contains(err.Error(), "Retry later with the same idempotency key") {
		t.Fatalf("details %+v", ou)
	}
	if len(b.jobRequests()) != 0 {
		t.Fatal("job sent to a second station after an ambiguous outcome")
	}
}

// SDK-1 branch: not delivered (refused with 502) → next station.
func TestSDK1NotDeliveredNextStation(t *testing.T) {
	_, a, b, c := twoStations(t, ModeLocal)
	a.fail = func(r *http.Request) (int, string) { return 502, "bad_gateway" }
	j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	if err != nil || j.Local.StationURL != b.url {
		t.Fatalf("got %v %v", j, err)
	}
}

// SDK-1 branch: delivered, answer lost, the station has it by key → that job.
func TestSDK1DeliveredProbeFindsJob(t *testing.T) {
	fc, a, b, c := twoStations(t, ModeLocalFirst)
	a.answerDelay = 2 * time.Second
	j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "order-8"})
	if err != nil || j.Local.StationURL != a.url || j.IdempotencyKey != "order-8" || j.Via != ViaLocal {
		t.Fatalf("got %+v %v", j, err)
	}
	if len(a.jobRequests()) != 1 || len(b.jobRequests()) != 0 {
		t.Fatalf("posts: a=%d b=%d", len(a.jobRequests()), len(b.jobRequests()))
	}
	if _, n := fc.counts(); n != 0 {
		t.Fatal("cloud used")
	}
	var probe bool
	for _, r := range a.requests() {
		probe = probe || (r.Method == http.MethodGet && r.Query == "idempotency_key=order-8")
	}
	if !probe {
		t.Fatal("no probe by key")
	}
}

// SDK-1 branch: delivered, the station never recorded it (404) → next.
func TestSDK1DeliveredProbe404Next(t *testing.T) {
	_, a, b, c := twoStations(t, ModeLocal)
	a.jobDelay = 2 * time.Second
	j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	if err != nil || j.Local.StationURL != b.url {
		t.Fatalf("got %v %v", j, err)
	}
}

// SDK-1 branch: delivered, no answer at all → OutcomeUnknown, no cloud fallback.
func TestSDK1DeliveredNoAnswerNoFallback(t *testing.T) {
	fc, a, b, c := twoStations(t, ModeLocalFirst)
	a.delay = 2 * time.Second
	_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	if !IsOutcomeUnknown(err) {
		t.Fatalf("got %v", err)
	}
	if _, n := fc.counts(); n != 0 || len(b.jobRequests()) != 0 {
		t.Fatal("fell back after an ambiguous outcome")
	}
}

// SDK-1 cloud branches.
func TestSDK1Cloud(t *testing.T) {
	t.Run("500 once: one retry with the same key", func(t *testing.T) {
		fc := newFakeCloud(t)
		fc.jobStatus, fc.jobCode, fc.jobFailures = 500, "internal", 1
		st := newFakeStation(t, nil)
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
		j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "k1"})
		if err != nil || j.Via != ViaCloud || len(st.requests()) != 0 {
			t.Fatalf("got %v %v", j, err)
		}
		fc.mu.Lock()
		defer fc.mu.Unlock()
		if len(fc.jobs) != 2 || fc.jobs[0]["idempotency_key"] != "k1" || fc.jobs[1]["idempotency_key"] != "k1" {
			t.Fatalf("cloud posts %v", fc.jobs)
		}
	})
	for _, mode := range []LocalMode{ModeCloudFirst, ModeLocalFirst} {
		t.Run(string(mode)+": 500 twice → OutcomeUnknown, never local", func(t *testing.T) {
			fc := newFakeCloud(t)
			fc.jobStatus, fc.jobCode = 500, "internal"
			st := newFakeStation(t, nil)
			urls := []string{st.url}
			if mode == ModeLocalFirst {
				urls = []string{deadURL(t)} // the station leg fails first
			}
			c := newLocalClient(t, fc, LocalConfig{Mode: mode, StationURLs: urls, Fingerprints: map[string]string{urls[0]: st.fp}})
			_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
			var se *ServerError
			if !IsOutcomeUnknown(err) || !errors.As(err, &se) || IsStationUnreachable(err) {
				t.Fatalf("got %T %v", err, err)
			}
			if _, n := fc.counts(); n != 2 || len(st.requests()) != 0 {
				t.Fatalf("cloud posts %d, station requests %d", n, len(st.requests()))
			}
		})
	}
	t.Run("connection dropped after the request: retry once, then OutcomeUnknown", func(t *testing.T) {
		fc := newFakeCloud(t)
		fc.hangup = true
		st := newFakeStation(t, nil)
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
		_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		var ce *ConnectionError
		if !IsOutcomeUnknown(err) || !errors.As(err, &ce) || !ce.delivered {
			t.Fatalf("got %T %v", err, err)
		}
		if _, n := fc.counts(); n != 2 || len(st.requests()) != 0 {
			t.Fatalf("cloud posts %d, station requests %d", n, len(st.requests()))
		}
	})
	t.Run("not delivered → local", func(t *testing.T) {
		st := newFakeStation(t, nil)
		c := newLocalClient(t, &fakeCloud{srv: &httptest.Server{}}, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, Token: "czd_x"})
		if j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); err != nil || j.Via != ViaLocal {
			t.Fatalf("got %v %v", j, err)
		}
	})
}

// SDK-3 (auditor's proof): sealing to a small-order key must fail.
func TestAudit4LowOrderServerKey(t *testing.T) {
	var pub [32]byte
	pub[0] = 1
	if _, err := Seal(&pub, []byte("card 4111-1111")); err == nil {
		t.Fatal("sealed to a small-order key")
	}
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"public_key":%q,"algorithm":"x25519"}`, base64.StdEncoding.EncodeToString(pub[:]))
	})
	if _, err := c.ServerKey(context.Background()); ErrorCode(err) != "invalid_response" {
		t.Fatalf("small-order server key accepted: %v", err)
	}
	var good [32]byte
	good[0] = 9 // the base point
	if _, err := Seal(&good, []byte("x")); err != nil {
		t.Fatal(err)
	}
}

// SDK-4 (auditor's proof): tokens never appear in formatted output.
func TestAudit4TokensInFormatting(t *testing.T) {
	cfg := LocalConfig{Mode: ModeLocal, Token: "czd_SECRETDEVICETOKEN"}
	st := StoredToken{Token: "czl1.SECRET.SIG"}
	lt := LocalToken{Token: "czl1.SECRET2.SIG"}
	lp := LocalPairing{Token: "czd_SECRET3"}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{cfg, &cfg, st, &st, lt, &lt, lp, &lp} {
			if out := fmt.Sprintf(f, v); strings.Contains(out, "SECRET") {
				t.Fatalf("%s leaks: %s", f, out)
			}
		}
	}
	if !strings.Contains(fmt.Sprint(lt), "czl1.…") {
		t.Fatal("token type not shown")
	}
}

// SDK-6 (auditor's proof): a short TTL must not mint on every job.
func TestAudit4ShortTTLMintsOnEveryJob(t *testing.T) {
	fc := newFakeCloud(t)
	fc.expiresIn = 3 * 24 * time.Hour
	st := newFakeStation(t, nil)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, TokenTTLDays: 3, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	for i := 0; i < 10; i++ {
		if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); err != nil {
			t.Fatal(err)
		}
		c.local.wg.Wait()
	}
	if m, _ := fc.counts(); m != 1 {
		t.Fatalf("10 jobs with TokenTTLDays=3 -> %d mints", m)
	}
	// Below TTL/2 (1.5 days) it is renewed.
	key := c.local.storeKey
	sto, _ := c.local.cfg.TokenStore.Load(context.Background(), key)
	if got := c.local.refreshBefore(sto); got < 35*time.Hour || got > 36*time.Hour {
		t.Fatalf("refresh threshold %v", got)
	}
}

// SDK-2 (auditor's proof): blank keys are "no key"; padded keys are refused.
func TestAudit4WhitespaceKey(t *testing.T) {
	fc := newFakeCloud(t)
	fc.jobStatus, fc.jobCode = 503, "unavailable"
	c := newLocalClient(t, fc, LocalConfig{})
	_, _ = c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "  "})
	fc.mu.Lock()
	keys := map[any]bool{}
	for _, j := range fc.jobs {
		keys[j["idempotency_key"]] = true
	}
	n := len(fc.jobs)
	k, _ := fc.jobs[0]["idempotency_key"].(string)
	fc.mu.Unlock()
	if n < 2 || len(keys) != 1 || len(k) != 36 {
		t.Fatalf("retries without one real key: %d posts, keys %v", n, keys)
	}

	st := newFakeStation(t, nil)
	lc := newLocalClient(t, newFakeCloud(t), LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	if _, err := lc.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "\t"}); err != nil {
		t.Fatal(err)
	}
	if got := st.jobRequests()[0].Body["idempotency_key"].(string); !strings.HasPrefix(got, "sdk-") {
		t.Fatalf("blank key not replaced: %q", got)
	}
	for _, bad := range []string{" order-1", "order-1 ", "order\n1", "a\x00b"} {
		if _, err := lc.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: bad}); ErrorCode(err) != "invalid" {
			t.Fatalf("%q accepted: %v", bad, err)
		}
	}
	if len(st.jobRequests()) != 1 {
		t.Fatal("invalid keys were sent")
	}
}

// SDK-8: an insecure token store is refused, never silently used.
func TestInsecureTokenStore(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX only")
	}
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tokens.json")
	s := NewFileTokenStore(path)
	if err := s.Save(context.Background(), "k", &StoredToken{Token: "czl1.a"}); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0o666)
	if _, err := s.Load(context.Background(), "k"); !errors.Is(err, ErrInsecureTokenStore) {
		t.Fatalf("world-writable file used: %v", err)
	}
	_ = os.Chmod(path, 0o600)
	_ = os.Chmod(dir, 0o777)
	if _, err := s.Load(context.Background(), "k"); !errors.Is(err, ErrInsecureTokenStore) {
		t.Fatalf("world-writable dir used: %v", err)
	}
	if err := s.Save(context.Background(), "k", &StoredToken{Token: "czl1.b"}); !errors.Is(err, ErrInsecureTokenStore) {
		t.Fatalf("saved into a world-writable dir: %v", err)
	}
	// The client refuses to print rather than use it.
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, TokenStore: s})
	if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); !errors.Is(err, ErrInsecureTokenStore) || len(st.requests()) != 0 {
		t.Fatalf("got %v", err)
	}
	_ = os.Chmod(dir, 0o700)
	if os.Getuid() == 0 {
		_ = os.Chown(path, 1017, 1017)
		if _, err := s.Load(context.Background(), "k"); !errors.Is(err, ErrInsecureTokenStore) {
			t.Fatalf("file owned by another user used: %v", err)
		}
	}
}

// SDK-9: the mDNS collector is bounded.
func TestMDNSCollectorBounded(t *testing.T) {
	col := newMDNSCollector()
	fp := strings.Repeat("ab", 32)
	for i := 0; i < 300; i++ {
		col.add(mdnsAnswer(t, fmt.Sprintf("S%d", i), fmt.Sprintf("st%d", i), "o", "l", 7443, fp, "192.168.1.2"), net.ParseIP("192.168.1.2"))
	}
	if n := len(col.stations()); n != mdnsMaxInstances {
		t.Fatalf("stations %d", n)
	}
	if n := len(col.addr); n != mdnsMaxHosts {
		t.Fatalf("hosts %d", n)
	}
	col = newMDNSCollector()
	var addrs []mdnsRR
	for i := 0; i < 40; i++ {
		addrs = append(addrs, mdnsRR{"catzprint-flood.local.", a4(fmt.Sprintf("10.0.0.%d", i+1))})
	}
	col.add(buildResponse(t, addrs, nil), nil)
	if n := len(col.addr["catzprint-flood.local."]); n != mdnsMaxAddrs {
		t.Fatalf("addresses %d", n)
	}
}

// SDK-5: an oversized answer is never a reason to try elsewhere.
func TestOversizedStationAnswer(t *testing.T) {
	fc, a, b, c := twoStations(t, ModeLocalFirst)
	a.huge = true
	_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	var ou *OutcomeUnknownError
	if !errors.As(err, &ou) || ErrorCode(ou.Cause) != "response_too_large" {
		t.Fatalf("got %v", err)
	}
	if _, n := fc.counts(); n != 0 || len(b.requests()) != 0 {
		t.Fatal("tried elsewhere after an oversized answer")
	}
	if _, err := c.Local.Status(context.Background()); ErrorCode(err) != "response_too_large" || len(b.requests()) != 0 {
		t.Fatalf("status: %v", err)
	}
}
