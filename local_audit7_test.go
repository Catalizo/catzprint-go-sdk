package catzprint

// Regression tests for SDK addendum 5 (audit round 7): S1 (re-seal after a
// sealed_content 400, also after an ambiguous attempt: the amb400/seal400
// matrix scenarios), S2 (server-key cache TTL), S4 (POST 409 in_progress
// then probe 404: the ip404 scenario) and S6.

import (
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
	"time"

	"golang.org/x/crypto/nacl/box"
)

const a7Sealed400 = `{"error":{"code":"invalid","message":"Couldn't decrypt.","fields":{"sealed_content":"Couldn't decrypt."}}}`

// a7Cloud serves a server key (counting fetches) and answers POST /jobs with
// the actions in turn: "hangup" (read the request, drop the connection),
// "seal400", "409", "500", or "" (201 with a job); a last action "x*" repeats.
type a7Cloud struct {
	fc      *fakeCloud
	mu      sync.Mutex
	keys    int
	bodies  []map[string]any
	actions []string
}

func newA7Cloud(t *testing.T, actions ...string) *a7Cloud {
	fc := newFakeCloud(t)
	a := &a7Cloud{fc: fc, actions: actions}
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inner := fc.srv.Config.Handler
	fc.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/public/server-key":
			a.mu.Lock()
			a.keys++
			a.mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"public_key":%q,"algorithm":"x25519"}`, base64.StdEncoding.EncodeToString(pub[:]))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs"):
			raw, _ := io.ReadAll(r.Body)
			var b map[string]any
			_ = json.Unmarshal(raw, &b)
			a.mu.Lock()
			a.bodies = append(a.bodies, b)
			n := len(a.bodies)
			act := ""
			if n <= len(a.actions) {
				act = a.actions[n-1]
			} else if len(a.actions) > 0 && strings.HasSuffix(a.actions[len(a.actions)-1], "*") {
				act = a.actions[len(a.actions)-1] // "x*": repeat
			}
			a.mu.Unlock()
			switch strings.TrimSuffix(act, "*") {
			case "hangup":
				if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
					_ = conn.Close()
				}
			case "seal400":
				writeErr(w, 400, a7Sealed400)
			case "409":
				writeErr(w, 409, `{"error":{"code":"duplicate","message":"A job with this key is being created."}}`)
			case "500":
				writeErr(w, 500, `{"error":{"code":"server_error","message":"boom"}}`)
			default:
				w.WriteHeader(201)
				_, _ = fmt.Fprintf(w, `{"job":{"id":"cloud-%d","status":"queued","idempotency_key":%q}}`, n, b["idempotency_key"])
			}
		default:
			inner.ServeHTTP(w, r)
		}
	})
	return a
}

func (a *a7Cloud) posts() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]any(nil), a.bodies...)
}

func (a *a7Cloud) keyFetches() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.keys
}

func a7Client(t *testing.T, a *a7Cloud, mode LocalMode, st *fakeStation) *Client {
	cfg := LocalConfig{Mode: mode, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}}
	if mode == ModeCloud {
		cfg = LocalConfig{}
	}
	return newLocalClient(t, a.fc, cfg, WithMaxRetries(2))
}

// S1 (amb400): the job was created but the answer was lost, then the key was
// rotated, so the retry got a sealed_content 400. That 400 is not the
// outcome: the SDK re-seals with a fresh key and re-sends with the same key.
// Before: ValidationError (the caller would print again with a new key).
func TestA7Amb400ResealsAndResends(t *testing.T) {
	for _, mode := range []LocalMode{ModeCloud, ModeLocalFirst, ModeCloudFirst} {
		t.Run(string(mode), func(t *testing.T) {
			a := newA7Cloud(t, "hangup", "seal400", "")
			st := newFakeStation(t, nil)
			c := a7Client(t, a, mode, st)
			j, err := c.Jobs.Create(context.Background(), JobParams{Text: "card", Sealed: true, IdempotencyKey: "amb-1"})
			if err != nil || j.ID != "cloud-3" {
				t.Fatalf("got %v %v", j, err)
			}
			p := a.posts()
			if len(p) != 3 || a.keyFetches() != 2 || len(st.requests()) != 0 {
				t.Fatalf("posts %d, key fetches %d, station %d", len(p), a.keyFetches(), len(st.requests()))
			}
			if p[2]["idempotency_key"] != "amb-1" || p[2]["sealed_content"] == p[1]["sealed_content"] || p[0]["sealed_content"] != p[1]["sealed_content"] {
				t.Fatal("re-send not re-sealed with the same key")
			}
		})
	}
	// The careful path (no client retries): the ambiguous retry gets the 400.
	a := newA7Cloud(t, "hangup", "seal400", "")
	st := newFakeStation(t, nil)
	c := a7Client(t, a, ModeCloudFirst, st)
	j, err := c.Jobs.createCloudCareful(context.Background(), JobParams{Text: "x", Sealed: true, IdempotencyKey: "amb-2"}, c.local.cloudOpts())
	if err != nil || j.ID != "cloud-3" {
		t.Fatalf("careful: %v %v", j, err)
	}
}

// S1: after an ambiguous attempt, a re-sealed re-send that is rejected again
// (or not delivered) is OutcomeUnknown, never a ValidationError, never local.
func TestA7Amb400RepeatIsOutcomeUnknown(t *testing.T) {
	for _, mode := range []LocalMode{ModeCloud, ModeLocalFirst, ModeCloudFirst} {
		for _, last := range []string{"seal400*", "hangup*"} {
			t.Run(string(mode)+"/"+last, func(t *testing.T) {
				a := newA7Cloud(t, "hangup", "seal400", last)
				st := newFakeStation(t, nil)
				c := a7Client(t, a, mode, st)
				_, err := c.Jobs.Create(context.Background(), JobParams{Text: "card", Sealed: true, IdempotencyKey: "amb-3"})
				if !IsOutcomeUnknown(err) {
					t.Fatalf("got %T %v", err, err)
				}
				if len(st.requests()) != 0 {
					t.Fatal("went local")
				}
				if n := len(a.posts()); n > 3+2 { // cloud mode retries the re-send per its policy
					t.Fatalf("%d posts", n)
				}
			})
		}
	}
}

// S1 (seal400): without an earlier ambiguous attempt the key is re-fetched
// and the job re-sealed once; a repeated 400 is returned as is.
func TestA7Seal400ResealsOnce(t *testing.T) {
	for _, mode := range []LocalMode{ModeCloud, ModeLocalFirst, ModeCloudFirst} {
		t.Run(string(mode), func(t *testing.T) {
			a := newA7Cloud(t, "seal400", "")
			st := newFakeStation(t, nil)
			c := a7Client(t, a, mode, st)
			j, err := c.Jobs.Create(context.Background(), JobParams{Text: "card", Sealed: true})
			if err != nil || j.ID != "cloud-2" || a.keyFetches() != 2 {
				t.Fatalf("got %v %v (keys %d)", j, err, a.keyFetches())
			}
			a2 := newA7Cloud(t, "seal400*")
			c2 := a7Client(t, a2, mode, st)
			_, err = c2.Jobs.Create(context.Background(), JobParams{Text: "card", Sealed: true})
			var ve *ValidationError
			if !errors.As(err, &ve) || len(a2.posts()) != 2 || len(st.requests()) != 0 {
				t.Fatalf("got %T %v (%d posts)", err, err, len(a2.posts()))
			}
		})
	}
	// An unsealed job's 400 is never re-sent.
	a := newA7Cloud(t, "seal400*")
	c := newLocalClient(t, a.fc, LocalConfig{})
	if _, err := c.PrintPDF(context.Background(), []byte("%PDF-1.4 x"), JobParams{}); len(a.posts()) != 1 || err == nil {
		t.Fatalf("unsealed re-sent: %v", err)
	}
}

// S1: a sealed_content 400 to a re-send after a 409 "being created" is
// OutcomeUnknown (a job with the key exists).
func TestA7SealedAfter409IsUnknown(t *testing.T) {
	a := newA7Cloud(t, "409", "seal400*")
	c := newLocalClient(t, a.fc, LocalConfig{})
	if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", Sealed: true}); !IsOutcomeUnknown(err) {
		t.Fatalf("got %T %v", err, err)
	}
}

// S2: the server key is cached for an hour, then fetched again.
func TestA7ServerKeyTTL(t *testing.T) {
	a := newA7Cloud(t)
	c := newLocalClient(t, a.fc, LocalConfig{})
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := c.ServerKey(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if a.keyFetches() != 1 {
		t.Fatalf("fetched %d times", a.keyFetches())
	}
	c.mu.Lock()
	c.serverKeyAt = time.Now().Add(-61 * time.Minute)
	c.mu.Unlock()
	if _, err := c.ServerKey(ctx); err != nil || a.keyFetches() != 2 {
		t.Fatalf("stale key not refreshed (%d fetches, %v)", a.keyFetches(), err)
	}
}

// S4 (ip404): a station answered the POST 409 in_progress, then the probe by
// key says 404 not_found. That is not "never recorded": OutcomeUnknown, no
// next station, no cloud. Before: Go fell back (local_first printed in the
// cloud too).
func TestA7InProgressThen404IsUnknown(t *testing.T) {
	for _, mode := range []LocalMode{ModeLocal, ModeLocalFirst, ModeCloudFirst} {
		t.Run(string(mode), func(t *testing.T) {
			fc, a, b, c := twoStations(t, mode)
			if mode == ModeCloudFirst {
				fc.mu.Lock()
				fc.jobStatus, fc.jobCode = 503, "unavailable"
				fc.mu.Unlock()
			}
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodPost && r.URL.Path == "/local/v1/jobs" {
					return 409, "in_progress" // not recorded: the probe answers 404
				}
				return 0, ""
			}
			_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "ip404"})
			if !IsOutcomeUnknown(err) {
				t.Fatalf("got %T %v", err, err)
			}
			if len(b.requests()) != 0 {
				t.Fatal("sent to the next station")
			}
			fc.mu.Lock()
			cloudJobs := len(fc.jobs)
			fc.mu.Unlock()
			if mode == ModeLocalFirst && cloudJobs != 0 {
				t.Fatal("fell back to the cloud")
			}
		})
	}
}

// S6: every placeholder in the shared set counts as "no token"; the store
// error is cleared once a fresh token was minted and stored.
func TestA7PlaceholdersAndStoreErrCleared(t *testing.T) {
	for _, p := range []string{"…", "***", "*****", "[redacted]", "REDACTED", "hidden", "czl1.…", "czl1.***", "czd_[redacted]", "czd_hidden"} {
		if !isRedactedToken(p) {
			t.Errorf("%q not recognised", p)
		}
	}
	for _, p := range []string{"czl1.abc.def", "czd_abc", "**", "czl1.**", "redacted-token"} {
		if isRedactedToken(p) {
			t.Errorf("%q taken for a placeholder", p)
		}
	}
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	store := NewMemoryTokenStore()
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, TokenStore: store})
	_ = store.Save(context.Background(), c.local.storeKey, &StoredToken{Token: "czl1.[redacted]", ExpiresAt: time.Now().Add(240 * time.Hour)})
	if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); err != nil {
		t.Fatal(err)
	}
	if a := st.jobRequests()[0].Auth; strings.Contains(a, "redacted") {
		t.Fatalf("placeholder sent: %q", a)
	}
	if err := c.Local.StoreError(); err != nil {
		t.Fatalf("store error kept after a successful re-mint: %v", err)
	}
}

// S6: a cloud 3xx has the code unexpected_redirect.
func TestA7RedirectCode(t *testing.T) {
	fc := newFakeCloud(t)
	inner := fc.srv.Config.Handler
	fc.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs") {
			w.Header().Set("Location", "http://127.0.0.1:1/")
			w.WriteHeader(302)
			return
		}
		inner.ServeHTTP(w, r)
	})
	c := newLocalClient(t, fc, LocalConfig{})
	if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); ErrorCode(err) != "unexpected_redirect" {
		t.Fatalf("got %v (%s)", err, ErrorCode(err))
	}
}
