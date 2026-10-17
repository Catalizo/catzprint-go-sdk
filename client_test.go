package catzprint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fakeKey = "cz_test_supersecretvalue1234567890"

func newFake(t *testing.T, h http.HandlerFunc, opts ...Option) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	base := []Option{WithAPIKey(fakeKey), WithBaseURL(srv.URL), WithOrgID("org1"), WithBackoff(time.Millisecond, 5*time.Millisecond)}
	c, err := NewClient(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeErr(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func TestNewClientNeedsKey(t *testing.T) {
	t.Setenv("CATZPRINT_API_KEY", "")
	if _, err := NewClient(); err == nil {
		t.Fatal("expected an error without a key")
	}
	if _, err := NewClient(WithAPIKey("sk_nope")); err == nil {
		t.Fatal("expected an error for a malformed key")
	}
	t.Setenv("CATZPRINT_API_KEY", fakeKey)
	t.Setenv("CATZPRINT_BASE_URL", "https://example.test/")
	c, err := NewClient()
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "https://example.test" || !c.IsTestMode() {
		t.Fatalf("env not applied: %s", c.baseURL)
	}
}

func TestKeyIsRedacted(t *testing.T) {
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {})
	for _, s := range []string{c.String(), fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(s, "supersecret") {
			t.Fatalf("key leaked: %s", s)
		}
	}
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		body   string
		check  func(error) bool
		code   string
	}{
		{401, `{"error":{"code":"invalid_api_key","message":"Bad key."}}`, func(e error) bool { var x *AuthenticationError; return errors.As(e, &x) }, "invalid_api_key"},
		{403, `{"error":{"code":"forbidden","message":"No."}}`, func(e error) bool { var x *PermissionError; return errors.As(e, &x) }, "forbidden"},
		{404, `{"error":{"code":"not_found","message":"Job not found."}}`, func(e error) bool { var x *NotFoundError; return errors.As(e, &x) }, "not_found"},
		{400, `{"error":{"code":"invalid","message":"Must be between 1 and 50.","fields":{"copies":"Must be between 1 and 50."}}}`, func(e error) bool {
			var x *ValidationError
			return errors.As(e, &x) && x.Fields["copies"] != ""
		}, "invalid"},
		{422, `{"error":{"code":"no_printer","message":"No printer."}}`, func(e error) bool { var x *ValidationError; return errors.As(e, &x) }, "no_printer"},
		{402, `{"error":{"code":"out_of_prints","message":"Out."}}`, func(e error) bool { var x *OutOfPrintsError; return errors.As(e, &x) }, "out_of_prints"},
		{409, `{"error":{"code":"invalid_state","message":"A printed job can't be changed this way."}}`, func(e error) bool { var x *ConflictError; return errors.As(e, &x) }, "invalid_state"},
		{429, `{"error":{"code":"rate_limited","message":"Slow down.","retry_after_seconds":7}}`, func(e error) bool {
			var x *RateLimitError
			return errors.As(e, &x) && x.RetryAfter == 7*time.Second
		}, "rate_limited"},
		{500, `{"error":{"code":"internal","message":"Something went wrong."}}`, func(e error) bool { var x *ServerError; return errors.As(e, &x) }, "internal"},
		{502, `<html>bad gateway</html>`, func(e error) bool { var x *ServerError; return errors.As(e, &x) }, "http_502"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			c := newFake(t, func(w http.ResponseWriter, r *http.Request) { writeErr(w, tc.status, tc.body) }, WithMaxRetries(0))
			_, err := c.Jobs.Get(context.Background(), "j1")
			if err == nil || !tc.check(err) {
				t.Fatalf("wrong error type: %T %v", err, err)
			}
			var api *APIError
			if !errors.As(err, &api) || api.Status != tc.status || api.Code != tc.code {
				t.Fatalf("base error not reachable: %#v", api)
			}
			if strings.Contains(err.Error(), "supersecret") {
				t.Fatal("key in error message")
			}
		})
	}
}

func TestRetriesGetOn503ThenSucceeds(t *testing.T) {
	var n atomic.Int32
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			writeErr(w, 503, `{"error":{"code":"unavailable","message":"Try again."}}`)
			return
		}
		_, _ = io.WriteString(w, `{"job":{"id":"j1","status":"queued"},"events":[]}`)
	})
	j, err := c.Jobs.Get(context.Background(), "j1")
	if err != nil || j.ID != "j1" {
		t.Fatalf("got %v %v", j, err)
	}
	if n.Load() != 3 {
		t.Fatalf("attempts = %d, want 3", n.Load())
	}
}

func TestRetriesGiveUpAfterMax(t *testing.T) {
	var n atomic.Int32
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		writeErr(w, 504, `{}`)
	})
	_, err := c.Locations.List(context.Background())
	var se *ServerError
	if !errors.As(err, &se) || n.Load() != 3 {
		t.Fatalf("err=%v attempts=%d", err, n.Load())
	}
}

func TestNoRetryOn500Or400(t *testing.T) {
	for _, st := range []int{500, 400} {
		var n atomic.Int32
		c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
			n.Add(1)
			writeErr(w, st, `{}`)
		})
		_, _ = c.Printers.List(context.Background())
		if n.Load() != 1 {
			t.Fatalf("status %d retried %d times", st, n.Load())
		}
	}
}

func TestRetryAfterIsRespected(t *testing.T) {
	var mu sync.Mutex
	var times []time.Time
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		times = append(times, time.Now())
		first := len(times) == 1
		mu.Unlock()
		if first {
			w.Header().Set("Retry-After", "1")
			writeErr(w, 429, `{"error":{"code":"rate_limited","message":"Slow down."}}`)
			return
		}
		_, _ = io.WriteString(w, `{"templates":[]}`)
	})
	if _, err := c.Templates.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(times) != 2 || times[1].Sub(times[0]) < 900*time.Millisecond {
		t.Fatalf("Retry-After not respected: %v", times)
	}
}

func TestNetworkErrorIsConnectionErrorAndRetried(t *testing.T) {
	var n atomic.Int32
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			conn.Close() // drop the connection without answering
			return
		}
		_, _ = io.WriteString(w, `{"printers":[{"id":"p1","name":"Front"}]}`)
	})
	ps, err := c.Printers.List(context.Background())
	if err != nil || len(ps) != 1 || n.Load() != 2 {
		t.Fatalf("ps=%v err=%v attempts=%d", ps, err, n.Load())
	}

	dead, _ := NewClient(WithAPIKey(fakeKey), WithBaseURL("http://127.0.0.1:1"), WithOrgID("o"), WithMaxRetries(0))
	_, err = dead.Printers.List(context.Background())
	var ce *ConnectionError
	if !errors.As(err, &ce) {
		t.Fatalf("want ConnectionError, got %T %v", err, err)
	}
}

func TestCreateReusesIdempotencyKeyAcrossRetries(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/orgs/org1/jobs" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+fakeKey || !strings.HasPrefix(r.Header.Get("User-Agent"), "catzprint-go/2.1.3") {
			t.Errorf("bad headers %v", r.Header)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		keys = append(keys, body["idempotency_key"].(string))
		n := len(keys)
		mu.Unlock()
		if body["kind"] != "text" || body["content"] != "hi" || body["role"] != "receipt" {
			t.Errorf("bad body %v", body)
		}
		if n < 3 {
			writeErr(w, 502, `{}`)
			return
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"job":{"id":"j9","status":"queued","live":false,"billed_as":"test"}}`)
	})
	j, err := c.PrintText(context.Background(), "hi", JobParams{Role: "receipt"})
	if err != nil || j.ID != "j9" {
		t.Fatalf("j=%v err=%v", j, err)
	}
	if len(keys) != 3 || keys[0] == "" || keys[0] != keys[1] || keys[1] != keys[2] {
		t.Fatalf("idempotency keys not reused: %v", keys)
	}
	if len(keys[0]) != 36 || keys[0][14] != '4' {
		t.Fatalf("not a UUIDv4: %s", keys[0])
	}
}

func TestCreateKeepsCallerIdempotencyKey(t *testing.T) {
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["idempotency_key"] != "order-42" {
			t.Errorf("key = %v", body["idempotency_key"])
		}
		_, _ = io.WriteString(w, `{"job":{"id":"j1"}}`)
	})
	if _, err := c.PrintText(context.Background(), "x", JobParams{IdempotencyKey: "order-42"}); err != nil {
		t.Fatal(err)
	}
}

func TestPOSTWithoutIdempotencyIsNotRetried(t *testing.T) {
	var n atomic.Int32
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		writeErr(w, 503, `{}`)
	})
	_, err := c.Jobs.Cancel(context.Background(), "j1")
	var se *ServerError
	if !errors.As(err, &se) || n.Load() != 1 {
		t.Fatalf("err=%v attempts=%d", err, n.Load())
	}
}

func TestCreateBodies(t *testing.T) {
	var last map[string]any
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		last = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&last)
		_, _ = io.WriteString(w, `{"job":{"id":"j"}}`)
	})
	ctx := context.Background()
	when := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if _, err := c.PrintPDF(ctx, []byte("%PDF-1.4 x"), JobParams{PrinterID: "p1", Copies: 2, ScheduledFor: &when}); err != nil {
		t.Fatal(err)
	}
	if last["kind"] != "pdf" || last["content"] != "JVBERi0xLjQgeA==" || last["printer_id"] != "p1" || last["copies"] != float64(2) || last["scheduled_for"] != "2030-01-02T03:04:05Z" {
		t.Fatalf("pdf body %v", last)
	}
	if _, err := c.PrintReceipt(ctx, []Command{Text("Hi"), Cut()}, JobParams{}); err != nil {
		t.Fatal(err)
	}
	cmds, _ := last["commands"].([]any)
	if last["kind"] != "commands" || len(cmds) != 2 || cmds[0].(map[string]any)["text"] != "Hi" {
		t.Fatalf("commands body %v", last)
	}
	if _, err := c.PrintTemplate(ctx, "t1", map[string]any{"total": "9.99"}, JobParams{}); err != nil {
		t.Fatal(err)
	}
	if last["kind"] != "template" || last["template_id"] != "t1" || last["data"].(map[string]any)["total"] != "9.99" {
		t.Fatalf("template body %v", last)
	}
	if _, err := c.PrintImage(ctx, []byte{0x89, 'P', 'N', 'G', 1}, JobParams{}); err != nil {
		t.Fatal(err)
	}
	if last["kind"] != "image" {
		t.Fatalf("image body %v", last)
	}
	_, err := c.Jobs.Create(ctx, JobParams{Text: "a", Commands: []Command{Cut()}})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("two sources should fail: %v", err)
	}
	if _, err := c.Jobs.Create(ctx, JobParams{}); !errors.As(err, &ve) {
		t.Fatalf("no source should fail: %v", err)
	}
	if _, err := c.Jobs.Create(ctx, JobParams{Commands: []Command{Cut()}, Sealed: true}); !errors.As(err, &ve) {
		t.Fatalf("sealed commands should fail: %v", err)
	}
}

func TestOrgIDLookedUpOnceAndCached(t *testing.T) {
	var keyCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/key":
			keyCalls.Add(1)
			_, _ = io.WriteString(w, `{"id":"k1","org_id":"orgX","org_name":"Shop","live":false,"scopes":["jobs:read"]}`)
		case "/v1/orgs/orgX/locations/l%201", "/v1/orgs/orgX/locations/l 1":
			_, _ = io.WriteString(w, `{"location":{"id":"l 1","name":"Front"}}`)
		default:
			_, _ = io.WriteString(w, `{"locations":[]}`)
		}
	}))
	defer srv.Close()
	c, _ := NewClient(WithAPIKey(fakeKey), WithBaseURL(srv.URL))
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Locations.List(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	l, err := c.Locations.Get(context.Background(), "l 1")
	if err != nil || l.Name != "Front" {
		t.Fatalf("%v %v", l, err)
	}
	if keyCalls.Load() < 1 || keyCalls.Load() > 5 {
		t.Fatalf("key calls %d", keyCalls.Load())
	}
	before := keyCalls.Load()
	_, _ = c.Locations.List(context.Background())
	if keyCalls.Load() != before {
		t.Fatal("org ID not cached")
	}
}

func TestIteratorPages(t *testing.T) {
	var calls atomic.Int32
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		q := r.URL.Query()
		if q.Get("status") != "printed,failed" || q.Get("limit") != "2" {
			t.Errorf("bad query %s", r.URL.RawQuery)
		}
		switch q.Get("cursor") {
		case "":
			_, _ = io.WriteString(w, `{"items":[{"id":"a"},{"id":"b"}],"next_cursor":"c1","counts":{}}`)
		case "c1":
			_, _ = io.WriteString(w, `{"items":[{"id":"c"},{"id":"d"}],"next_cursor":"c2","counts":{}}`)
		case "c2":
			_, _ = io.WriteString(w, `{"items":[{"id":"e"}],"next_cursor":"","counts":{}}`)
		}
	})
	params := ListJobsParams{Status: []string{"printed", "failed"}, Limit: 2}
	it := c.Jobs.Iter(context.Background(), params)
	var ids []string
	for it.Next() {
		ids = append(ids, it.Job().ID)
	}
	if it.Err() != nil || strings.Join(ids, "") != "abcde" || calls.Load() != 3 {
		t.Fatalf("ids=%v err=%v calls=%d", ids, it.Err(), calls.Load())
	}
	// The func-style sequence stops early when the consumer does.
	ids = nil
	c.Jobs.All(context.Background(), params)(func(j *Job, err error) bool {
		ids = append(ids, j.ID)
		return len(ids) < 3
	})
	if strings.Join(ids, "") != "abc" {
		t.Fatalf("All: %v", ids)
	}
}

func TestIteratorStopsOnError(t *testing.T) {
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cursor") == "" {
			_, _ = io.WriteString(w, `{"items":[{"id":"a"}],"next_cursor":"bad"}`)
			return
		}
		writeErr(w, 400, `{"error":{"code":"invalid","message":"Invalid cursor.","fields":{"cursor":"Invalid cursor."}}}`)
	})
	var got []string
	var lastErr error
	c.Jobs.All(context.Background(), ListJobsParams{})(func(j *Job, err error) bool {
		if err != nil {
			lastErr = err
			return false
		}
		got = append(got, j.ID)
		return true
	})
	var ve *ValidationError
	if len(got) != 1 || !errors.As(lastErr, &ve) {
		t.Fatalf("got=%v err=%v", got, lastErr)
	}
}

func TestWaitFor(t *testing.T) {
	var n atomic.Int32
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		st := "sent"
		switch k := n.Add(1); {
		case k == 2:
			writeErr(w, 503, `{}`) // transient errors keep polling
			return
		case k >= 4:
			st = "printed"
		}
		fmt.Fprintf(w, `{"job":{"id":"j1","status":%q},"events":[{"status":%q}]}`, st, st)
	}, WithMaxRetries(0))
	j, err := c.Jobs.WaitFor(context.Background(), "j1", WithPollInterval(5*time.Millisecond), WithWaitTimeout(5*time.Second))
	if err != nil || j.Status != StatusPrinted || len(j.Events) != 1 {
		t.Fatalf("j=%+v err=%v", j, err)
	}

	slow := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"job":{"id":"j2","status":"queued"},"events":[]}`)
	})
	j, err = slow.Jobs.WaitFor(context.Background(), "j2", WithPollInterval(10*time.Millisecond), WithWaitTimeout(50*time.Millisecond))
	var te *TimeoutError
	if !errors.As(err, &te) || te.Job == nil || te.Job.Status != "queued" || j == nil {
		t.Fatalf("want TimeoutError, got %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := slow.Jobs.WaitFor(ctx, "j2"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestContextCancelStopsRetries(t *testing.T) {
	var n atomic.Int32
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		writeErr(w, 503, `{}`)
	}, WithBackoff(time.Second, time.Second), WithMaxRetries(5))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Printers.List(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 900*time.Millisecond || n.Load() != 1 {
		t.Fatalf("err=%v attempts=%d took=%s", err, n.Load(), time.Since(start))
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	c := &Client{backoff: 100 * time.Millisecond, maxBackoff: 400 * time.Millisecond}
	err := &ServerError{&APIError{Status: 503}}
	for attempt, max := range []time.Duration{100, 200, 400, 400, 400} {
		max *= time.Millisecond
		for i := 0; i < 50; i++ {
			d := c.retryDelay(attempt, err)
			if d < max/2 || d > max {
				t.Fatalf("attempt %d: delay %s outside [%s,%s]", attempt, d, max/2, max)
			}
		}
	}
	rl := &RateLimitError{&APIError{Status: 429, RetryAfter: 3 * time.Second}}
	if d := c.retryDelay(0, rl); d != 3*time.Second {
		t.Fatalf("retry-after delay %s", d)
	}
}

func TestBaseURLMustBeHTTPS(t *testing.T) {
	for _, bad := range []string{"http://api-v1.catzprint.com", "http://10.0.0.5:8080", "ftp://x.test", "not a url", "https://u:p@x.test", "https://x.test/?a=1"} {
		if _, err := NewClient(WithAPIKey(fakeKey), WithBaseURL(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, ok := range []string{"https://api.example.test", "http://localhost:8080", "http://127.0.0.1:1", "http://[::1]:3000"} {
		if _, err := NewClient(WithAPIKey(fakeKey), WithBaseURL(ok)); err != nil {
			t.Errorf("rejected %q: %v", ok, err)
		}
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Add(1)
		w.Write([]byte(`{"printers":[]}`))
	}))
	defer other.Close()
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	})
	if _, err := c.Printers.List(context.Background()); err == nil {
		t.Fatal("expected an error for a redirect")
	}
	if leaked.Load() != 0 {
		t.Fatal("the redirect was followed")
	}
}

func TestOversizedResponseIsRefused(t *testing.T) {
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		chunk := bytes.Repeat([]byte(" "), 1<<20)
		for i := 0; i <= maxResponseBytes>>20; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	_, err := c.Printers.List(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "response_too_large" {
		t.Fatalf("got %v", err)
	}
}
