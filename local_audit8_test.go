package catzprint

// Regression tests for SDK addendum 6 (audit round 8): T2 (once any answer
// for the key said in_progress, a later probe 404 is OutcomeUnknown: the
// dip404 matrix scenario) and T3 (an older in-flight server-key fetch must
// not re-install a dropped key).

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// dip404: the POST reaches the station but isn't recorded and gets no
// answer; the first probe says in_progress, the next one 404. Before: the
// 404 counted as "never recorded" and the job went to the next station or
// the cloud.
func TestA8ProbeInProgressThen404IsUnknown(t *testing.T) {
	for _, mode := range []LocalMode{ModeLocal, ModeLocalFirst} {
		t.Run(string(mode), func(t *testing.T) {
			fc, a, b, c := twoStations(t, mode)
			a.jobDelay = 2 * time.Second // the client gives up first; the job is never recorded
			var probes atomic.Int32
			a.fail = func(r *http.Request) (int, string) {
				if r.Method == http.MethodGet && r.URL.Path == "/local/v1/jobs" && probes.Add(1) == 1 {
					return 409, "in_progress"
				}
				return 0, ""
			}
			_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "dip404"})
			if !IsOutcomeUnknown(err) {
				t.Fatalf("got %T %v", err, err)
			}
			if probes.Load() < 2 {
				t.Fatalf("probes %d", probes.Load())
			}
			if len(b.requests()) != 0 {
				t.Fatal("sent to the next station")
			}
			if _, n := fc.counts(); n != 0 {
				t.Fatal("fell back to the cloud")
			}
		})
	}
}

// T3: a fetch that started before dropServerKey keeps its key for its own
// caller but doesn't put it back in the cache.
func TestA8StaleKeyFetchNotReinstalled(t *testing.T) {
	a := newA7Cloud(t)
	c := newLocalClient(t, a.fc, LocalConfig{})
	inner := a.fc.srv.Config.Handler
	a.fc.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/public/server-key" {
			c.dropServerKey() // a sealed_content rejection lands while this fetch is in flight
		}
		inner.ServeHTTP(w, r)
	})
	if k, err := c.ServerKey(context.Background()); err != nil || k == nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	cached := c.serverKey
	c.mu.Unlock()
	if cached != nil {
		t.Fatal("the stale fetch re-installed the dropped key")
	}
	a.fc.srv.Config.Handler = inner
	if _, err := c.ServerKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	cached = c.serverKey
	c.mu.Unlock()
	if cached == nil {
		t.Fatal("a fresh fetch should cache its key")
	}
}
