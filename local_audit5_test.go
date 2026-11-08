package catzprint

// Regression tests for SDK addendum 3 (audit round 5): the auditor's proofs
// (scratchpad/audit5/sdk/go) as assertions, plus R3, R4 and C1–C6.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// cloudJobAnswers makes the fake cloud answer POST /jobs with the given
// statuses in turn (0 = the normal 201), counting posts.
func cloudJobAnswers(fc *fakeCloud, code string, statuses ...int) *atomic.Int32 {
	var posts atomic.Int32
	inner := fc.srv.Config.Handler
	fc.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs") {
			n := int(posts.Add(1))
			if n <= len(statuses) && statuses[n-1] != 0 {
				writeErr(w, statuses[n-1], fmt.Sprintf(`{"error":{"code":%q,"message":"x"}}`, code))
				return
			}
			if n <= len(statuses) && statuses[n-1] == 0 {
				w.WriteHeader(201)
				_, _ = fmt.Fprintf(w, `{"job":{"id":"cloud-%d","status":"queued"}}`, n)
				return
			}
			writeErr(w, statuses[len(statuses)-1], fmt.Sprintf(`{"error":{"code":%q,"message":"x"}}`, code))
			return
		}
		inner.ServeHTTP(w, r)
	})
	return &posts
}

// R1 (auditor's proof): 500 then 503/502 → OutcomeUnknown, never the station.
func TestAudit5Cloud500Then503GoesLocal(t *testing.T) {
	for _, second := range []int{503, 502} {
		fc := newFakeCloud(t)
		posts := cloudJobAnswers(fc, "internal", 500, second)
		st := newFakeStation(t, nil)
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
		_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "order-1-kitchen-r1"})
		if !IsOutcomeUnknown(err) || len(st.jobRequests()) != 0 || posts.Load() != 2 {
			t.Fatalf("second=%d: err=%v station posts=%d cloud posts=%d", second, err, len(st.jobRequests()), posts.Load())
		}
	}
}

// R1 (auditor's proof): local_first returns the OutcomeUnknown itself.
func TestAudit5LocalFirst500Then503(t *testing.T) {
	fc := newFakeCloud(t)
	cloudJobAnswers(fc, "x", 500, 503)
	st := newFakeStation(t, nil)
	dead := deadURL(t)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{dead}, Fingerprints: map[string]string{dead: st.fp}})
	_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "order-2"})
	var ou *OutcomeUnknownError
	if !errors.As(err, &ou) || IsStationUnreachable(err) {
		t.Fatalf("got %T %v", err, err)
	}
}

// R7 (auditor's proof): every verb, JSON and slog are redacted.
func TestAudit5FormatVerbs(t *testing.T) {
	cfg := LocalConfig{Mode: ModeLocal, Token: "czd_SECRETDEVICETOKEN"}
	st := StoredToken{Token: "czl1.SECRET.sig"}
	p := LocalPairing{Token: "czd_SECRETPAIR"}
	lt := LocalToken{Token: "czl1.SECRETLT.sig"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%t", "%q", "%10.3v"} {
		for _, v := range []any{cfg, &cfg, st, &st, p, &p, lt, &lt} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, "SECRET") {
				t.Fatalf("leak %s %T: %s", verb, v, out)
			}
		}
	}
	// Config JSON is redacted; tokens returned to the caller or persisted
	// keep the token in JSON (addendum 4, Q2).
	if b, err := json.Marshal(cfg); err != nil || strings.Contains(string(b), "SECRET") {
		t.Fatalf("json leak LocalConfig: %s %v", b, err)
	}
	for _, v := range []any{st, p, lt} {
		if b, err := json.Marshal(v); err != nil || !strings.Contains(string(b), "SECRET") {
			t.Fatalf("token missing from JSON of %T: %s %v", v, b, err)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "local", cfg, "st", st, "p", p, "lt", lt)
	if strings.Contains(buf.String(), "SECRET") {
		t.Fatalf("slog leak: %s", buf.String())
	}
	// The explicit fields still work, and the store keeps the token.
	if p.Token != "czd_SECRETPAIR" {
		t.Fatal("field changed")
	}
	enc, _ := EncodeStoredToken(&st)
	dec, err := DecodeStoredToken(enc)
	if err != nil || dec.Token != st.Token {
		t.Fatalf("store round trip: %v %v", dec, err)
	}
	fs := NewFileTokenStore(filepath.Join(t.TempDir(), "t.json"))
	_ = fs.Save(context.Background(), "k", &st)
	if got, _ := fs.Load(context.Background(), "k"); got == nil || got.Token != st.Token {
		t.Fatalf("file store lost the token: %v", got)
	}
}

// R3: the probe's 409 duplicate is an answer: returned, no next station, no fallback.
func TestProbeConflictIsAnAnswer(t *testing.T) {
	fc, a, b, c := twoStations(t, ModeLocalFirst)
	a.answerDelay = 2 * time.Second
	a.probeStatus, a.probeCode = 409, "duplicate"
	_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.Code != "duplicate" || IsOutcomeUnknown(err) {
		t.Fatalf("got %T %v", err, err)
	}
	if _, n := fc.counts(); n != 0 || len(b.jobRequests()) != 0 {
		t.Fatal("tried elsewhere after a 409 duplicate")
	}
}

// R3: only 404 not_found means "never recorded"; another 404 keeps probing.
func TestProbe404OtherCode(t *testing.T) {
	_, a, b, c := twoStations(t, ModeLocal)
	a.answerDelay = 2 * time.Second
	a.probeStatus, a.probeCode = 404, "no_such_route"
	if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); !IsOutcomeUnknown(err) || len(b.jobRequests()) != 0 {
		t.Fatalf("got %v", err)
	}
}

// R4: cloud 409 duplicate/"being created": re-send up to 3 times, 1 s apart.
func TestCloudConflictResend(t *testing.T) {
	t.Run("then created", func(t *testing.T) {
		fc := newFakeCloud(t)
		posts := cloudJobAnswers(fc, "duplicate", 409, 409, 0)
		st := newFakeStation(t, nil)
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
		j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		if err != nil || j.ID != "cloud-3" || posts.Load() != 3 || len(st.requests()) != 0 {
			t.Fatalf("got %v %v posts=%d", j, err, posts.Load())
		}
	})
	t.Run("after an ambiguous 500, still 409 after 3 re-sends → that 409, never local", func(t *testing.T) {
		fc := newFakeCloud(t)
		posts := cloudJobAnswers(fc, "duplicate", 500, 409)
		st := newFakeStation(t, nil)
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
		_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		var ce *ConflictError
		if !errors.As(err, &ce) || IsOutcomeUnknown(err) || posts.Load() != 5 || len(st.requests()) != 0 {
			t.Fatalf("got %T %v posts=%d", err, err, posts.Load())
		}
	})
	t.Run("a re-send that isn't answered → OutcomeUnknown", func(t *testing.T) {
		fc := newFakeCloud(t)
		posts := cloudJobAnswers(fc, "duplicate", 409, 500, 500)
		st := newFakeStation(t, nil)
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
		_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		if !IsOutcomeUnknown(err) || posts.Load() != 2 || len(st.requests()) != 0 {
			t.Fatalf("got %v posts=%d", err, posts.Load())
		}
	})
	t.Run("cloud mode: re-sends carry the same generated key", func(t *testing.T) {
		fc := newFakeCloud(t)
		cloudJobAnswers(fc, "duplicate", 409, 0)
		var keys []string
		inner := fc.srv.Config.Handler
		fc.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			if k, ok := m["idempotency_key"].(string); ok {
				keys = append(keys, k)
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
			inner.ServeHTTP(w, r)
		})
		c := newLocalClient(t, fc, LocalConfig{})
		if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); err != nil {
			t.Fatal(err)
		}
		if len(keys) != 2 || keys[0] != keys[1] || keys[0] == "" {
			t.Fatalf("keys %v", keys)
		}
	})
	t.Run("cloud mode too", func(t *testing.T) {
		fc := newFakeCloud(t)
		posts := cloudJobAnswers(fc, "duplicate", 409, 0)
		c := newLocalClient(t, fc, LocalConfig{})
		j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		if err != nil || j.ID != "cloud-2" || posts.Load() != 2 {
			t.Fatalf("got %v %v", j, err)
		}
	})
}

// C1: local_first returns a cloud 4xx itself.
func TestLocalFirstCloud4xxUnwrapped(t *testing.T) {
	fc := newFakeCloud(t)
	fc.jobStatus, fc.jobCode = 422, "no_printer"
	dead := deadURL(t)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{dead}, Fingerprints: map[string]string{dead: strings.Repeat("ab", 32)}})
	_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	var ve *ValidationError
	if !errors.As(err, &ve) || IsStationUnreachable(err) || ve.Code != "no_printer" {
		t.Fatalf("got %T %v", err, err)
	}
}

// C2: any 5xx but 502/503/504 is ambiguous (one retry).
func TestCloud501Ambiguous(t *testing.T) {
	fc := newFakeCloud(t)
	posts := cloudJobAnswers(fc, "x", 501, 0)
	st := newFakeStation(t, nil)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	if j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); err != nil || j.Via != ViaCloud || posts.Load() != 2 {
		t.Fatalf("got %v %v", j, err)
	}
}

// C3: the org lookup failing before the job POST → not delivered → local.
func TestOrgLookupFailureIsNotDelivered(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, 500, `{"error":{"code":"internal","message":"x"}}`)
	}))
	t.Cleanup(cloud.Close)
	st := newFakeStation(t, nil)
	c, err := NewClient(WithAPIKey(fakeKey), WithBaseURL(cloud.URL), WithMaxRetries(0),
		WithLocal(LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, Token: "czd_x"}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); err != nil || j.Via != ViaLocal {
		t.Fatalf("got %v %v", j, err)
	}
}

// C5: a 2xx without a usable job is probed by key.
func TestEmptyStationAnswerIsProbed(t *testing.T) {
	_, a, b, c := twoStations(t, ModeLocal)
	a.emptyAnswer = true
	j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "k5"})
	if err != nil || j.Local.StationURL != a.url || !strings.HasPrefix(j.ID, "lj_") || len(b.jobRequests()) != 0 {
		t.Fatalf("got %+v %v", j, err)
	}
}

// C6: cancellation after the write → OutcomeUnknown; before → the cancellation.
func TestCancellationAfterWrite(t *testing.T) {
	fc, a, b, c := twoStations(t, ModeLocalFirst)
	a.answerDelay = 3 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	_, err := c.Jobs.Create(ctx, JobParams{Text: "x", IdempotencyKey: "k6"})
	var ou *OutcomeUnknownError
	if !errors.As(err, &ou) || !errors.Is(err, context.Canceled) || ou.URL != a.url {
		t.Fatalf("got %T %v", err, err)
	}
	if _, n := fc.counts(); n != 0 || len(b.jobRequests()) != 0 {
		t.Fatal("fell back after a cancellation")
	}
	pre, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := c.Jobs.Create(pre, JobParams{Text: "x"}); IsOutcomeUnknown(err) || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled: %v", err)
	}
	// Cloud leg: cancelled while the cloud holds the answer.
	slow := newFakeCloud(t)
	inner := slow.srv.Config.Handler
	slow.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = io.ReadAll(r.Body)
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
			}
			return
		}
		inner.ServeHTTP(w, r)
	})
	st := newFakeStation(t, nil)
	cf := newLocalClient(t, slow, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	ctx3, cancel3 := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel3)
	if _, err := cf.Jobs.Create(ctx3, JobParams{Text: "x"}); !IsOutcomeUnknown(err) || !errors.Is(err, context.Canceled) || len(st.requests()) != 0 {
		t.Fatalf("cloud leg: %v", err)
	}
}
