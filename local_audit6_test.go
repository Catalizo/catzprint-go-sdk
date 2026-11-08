package catzprint

// Regression tests for SDK addendum 4 (audit round 6): the auditor's proof
// (scratchpad/audit6/sdk/go/zz_audit6_test.go) as an assertion, plus Q1–Q4, Q6.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// jsonStore is a custom TokenStore that persists with json.Marshal, the way
// a Redis/DB store would be written.
type jsonStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *jsonStore) Load(_ context.Context, k string) (*StoredToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[k]
	if !ok {
		return nil, nil
	}
	var t StoredToken
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *jsonStore) Save(_ context.Context, k string, t *StoredToken) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = b
	return nil
}

// Q2 (auditor's proof): a json.Marshal-based store keeps the real token
// across a restart while the cloud is down.
func TestA6CustomJSONStoreKeepsToken(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	store := &jsonStore{m: map[string][]byte{}}
	cfg := LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, TokenStore: store}
	c1 := newLocalClient(t, fc, cfg)
	if _, err := c1.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "a6-1"}); err != nil {
		t.Fatal(err)
	}
	first := st.jobRequests()[0].Auth
	fc.mu.Lock()
	fc.down = true
	fc.mu.Unlock()
	c2 := newLocalClient(t, fc, cfg)
	if _, err := c2.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "a6-2"}); err != nil {
		t.Fatal(err)
	}
	reqs := st.jobRequests()
	if last := reqs[len(reqs)-1].Auth; last != first || strings.Contains(last, "…") {
		t.Fatalf("restarted client sent %q, want %q", last, first)
	}
}

// Q2: a stored redaction placeholder counts as "no token" (store error).
func TestA6StoredPlaceholderIsNoToken(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	store := NewMemoryTokenStore()
	cfg := LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, TokenStore: store}
	c := newLocalClient(t, fc, cfg)
	_ = store.Save(context.Background(), c.local.storeKey, &StoredToken{Token: "czl1.…", ExpiresAt: c.local.now().Add(240 * 3600 * 1e9)})
	if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); err != nil {
		t.Fatal(err)
	}
	// (S6, addendum 5: the store error is cleared once the re-minted token
	// was stored.)
	if a := st.jobRequests()[0].Auth; strings.Contains(a, "…") || c.Local.StoreError() != nil {
		t.Fatalf("placeholder used: %q (store error %v)", a, c.Local.StoreError())
	}
	if m, _ := fc.counts(); m != 1 {
		t.Fatalf("mints %d", m)
	}
}

// Q2: LocalToken/LocalPairing JSON keeps the token (handed to browser tills),
// while fmt/slog stay redacted.
func TestA6ResultJSONHasToken(t *testing.T) {
	lt := LocalToken{Token: "czl1.abc.sig", TokenID: "j1"}
	b, _ := json.Marshal(lt)
	var back LocalToken
	_ = json.Unmarshal(b, &back)
	if back.Token != lt.Token || strings.Contains(fmt.Sprint(lt), "abc") {
		t.Fatalf("json %s / fmt %v", b, lt)
	}
	pb, _ := json.Marshal(LocalPairing{Token: "czd_abc"})
	if !strings.Contains(string(pb), "czd_abc") {
		t.Fatalf("pairing json %s", pb)
	}
}

// Q1: a station POST answered 409 in_progress is waited for by probing.
func TestA6PostInProgress(t *testing.T) {
	fc, a, b, c := twoStations(t, ModeLocalFirst)
	a.postInProgress = true
	j, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "q1"})
	if err != nil || j.Local.StationURL != a.url || j.IdempotencyKey != "q1" {
		t.Fatalf("got %+v %v", j, err)
	}
	if _, n := fc.counts(); n != 0 || len(b.jobRequests()) != 0 {
		t.Fatal("fell back while the station was still processing")
	}
	// A probe that keeps answering in_progress ends in OutcomeUnknown.
	fc2, a2, b2, c2 := twoStations(t, ModeLocalFirst)
	a2.postInProgress = true
	a2.probeStatus, a2.probeCode = 409, "in_progress"
	if _, err := c2.Jobs.Create(context.Background(), JobParams{Text: "x"}); !IsOutcomeUnknown(err) {
		t.Fatalf("got %v", err)
	}
	if _, n := fc2.counts(); n != 0 || len(b2.jobRequests()) != 0 {
		t.Fatal("fell back")
	}
}

// sealingCloud serves a real X25519 server key and records raw job bodies;
// POST /jobs answers the statuses in turn (0 = created).
func sealingCloud(t *testing.T, statuses ...int) (*fakeCloud, *[][]byte) {
	fc := newFakeCloud(t)
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var bodies [][]byte
	var mu sync.Mutex
	inner := fc.srv.Config.Handler
	fc.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/public/server-key":
			_, _ = fmt.Fprintf(w, `{"public_key":%q,"algorithm":"x25519"}`, base64.StdEncoding.EncodeToString(pub[:]))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs"):
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, b)
			n := len(bodies)
			mu.Unlock()
			st := statuses[min(n, len(statuses))-1]
			if st != 0 {
				writeErr(w, st, `{"error":{"code":"duplicate","message":"A job with this key is being created."}}`)
				return
			}
			w.WriteHeader(201)
			_, _ = fmt.Fprintf(w, `{"job":{"id":"cloud-%d","status":"queued"}}`, n)
		default:
			inner.ServeHTTP(w, r)
		}
	})
	return fc, &bodies
}

// Q3 + Q4: a sealed job in a fallback mode goes through the cloud-mode
// create (409 loop) and every re-send carries the exact same bytes.
func TestA6SealedResendIdenticalBytes(t *testing.T) {
	for _, mode := range []LocalMode{ModeCloud, ModeLocalFirst, ModeCloudFirst} {
		t.Run(string(mode), func(t *testing.T) {
			fc, bodies := sealingCloud(t, 409, 409, 0)
			st := newFakeStation(t, nil)
			cfg := LocalConfig{Mode: mode, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}}
			if mode == ModeCloud {
				cfg = LocalConfig{}
			}
			c := newLocalClient(t, fc, cfg)
			j, err := c.Jobs.Create(context.Background(), JobParams{Text: "card 4111", Sealed: true})
			if err != nil || j.ID != "cloud-3" || len(st.requests()) != 0 {
				t.Fatalf("got %v %v", j, err)
			}
			if len(*bodies) != 3 || !bytes.Equal((*bodies)[0], (*bodies)[1]) || !bytes.Equal((*bodies)[1], (*bodies)[2]) {
				t.Fatalf("re-sends differ:\n%s\n%s", (*bodies)[0], (*bodies)[1])
			}
			if !bytes.Contains((*bodies)[0], []byte("sealed_content")) {
				t.Fatal("not sealed")
			}
		})
	}
	// Q3: the ambiguous retry of the careful path reuses the bytes too.
	fc, bodies := sealingCloud(t, 500, 0)
	st := newFakeStation(t, nil)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	if _, err := c.Jobs.createCloudCareful(context.Background(), JobParams{Text: "x", Sealed: true, IdempotencyKey: "q3"}, c.local.cloudOpts()); err != nil {
		t.Fatal(err)
	}
	if len(*bodies) != 2 || !bytes.Equal((*bodies)[0], (*bodies)[1]) {
		t.Fatal("ambiguous retry re-sealed the content")
	}
}

// Q4: a PDF in local_first gets the cloud-mode 409 loop.
func TestA6UnsupportedLocallyUsesCloudMode(t *testing.T) {
	fc, bodies := sealingCloud(t, 409, 0)
	st := newFakeStation(t, nil)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	j, err := c.PrintPDF(context.Background(), []byte("%PDF-1.4 x"), JobParams{})
	if err != nil || j.ID != "cloud-2" || len(*bodies) != 2 || len(st.requests()) != 0 {
		t.Fatalf("got %v %v (%d posts)", j, err, len(*bodies))
	}
}

// Q6: a failed server-key fetch (before the job POST) is not delivered.
func TestA6ServerKeyFailureNotDelivered(t *testing.T) {
	fc := newFakeCloud(t) // no server-key endpoint: 404
	st := newFakeStation(t, nil)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	_, err := c.Jobs.createCloudCareful(context.Background(), JobParams{Text: "x", Sealed: true, IdempotencyKey: "q6"}, c.local.cloudOpts())
	var nf *NotFoundError
	if !cloudNotDelivered(err) || cloudAmbiguous(err) || IsOutcomeUnknown(err) || !errors.As(err, &nf) {
		t.Fatalf("got %T %v", err, err)
	}
	if _, n := fc.counts(); n != 0 {
		t.Fatal("job POST sent")
	}
}
