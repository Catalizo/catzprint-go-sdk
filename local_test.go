package catzprint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- fake station (spec §4.2) ----

type stationReq struct {
	Method, Path, Query, Auth string
	Body                      map[string]any
}

type fakeStation struct {
	t   *testing.T
	srv *httptest.Server
	url string // https://127.0.0.1:port
	fp  string

	mu       sync.Mutex
	reqs     []stationReq
	accept   func(token string) bool             // nil: any czl1./czd_ token
	fail     func(r *http.Request) (int, string) // status, code; 0 = no failure
	delay    time.Duration
	jobs     map[string]map[string]any // by id
	byKey    map[string]string         // idempotency key -> id
	nextID   int
	pairCode string
	// rejectCode is the 401 code for refused tokens (default token_expired).
	rejectCode string
	// live, when set, is reported as LocalJob.live.
	live *bool
	// jobDelay delays POST /local/v1/jobs before it is recorded (a slow or
	// lost request); answerDelay delays the answer after the job was
	// recorded (a lost answer). Other requests aren't delayed.
	jobDelay, answerDelay time.Duration
	// huge: every answer is a 5 MiB body (over the 4 MiB cap).
	huge bool
	// probeStatus/probeCode override the answer to GET /local/v1/jobs?idempotency_key=
	// (e.g. 409 duplicate: the key belongs to another device's job).
	probeStatus int
	probeCode   string
	// emptyAnswer: POST /local/v1/jobs records the job, then answers 201 "{}".
	emptyAnswer bool
	// postInProgress: POST /local/v1/jobs records the job, then answers 409 in_progress.
	postInProgress bool
}

func newFakeStation(t *testing.T, cert *tls.Certificate) *fakeStation {
	t.Helper()
	fs := &fakeStation{t: t, jobs: map[string]map[string]any{}, byKey: map[string]string{}, pairCode: "12345678"}
	fs.srv = httptest.NewUnstartedServer(http.HandlerFunc(fs.serve))
	fs.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // pin rejections are expected
	if cert != nil {
		fs.srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	}
	fs.srv.StartTLS()
	t.Cleanup(fs.srv.Close)
	fs.url = fs.srv.URL
	fs.fp = certFingerprint(fs.srv.Certificate())
	return fs
}

func (fs *fakeStation) requests() []stationReq {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]stationReq(nil), fs.reqs...)
}

func (fs *fakeStation) jobRequests() []stationReq {
	var out []stationReq
	for _, r := range fs.requests() {
		if r.Method == http.MethodPost && r.Path == "/local/v1/jobs" {
			out = append(out, r)
		}
	}
	return out
}

func stationErr(w http.ResponseWriter, status int, code string) {
	writeErr(w, status, fmt.Sprintf(`{"error":{"code":%q,"message":"Station says %s."}}`, code, code))
}

func (fs *fakeStation) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	fs.mu.Lock()
	fs.reqs = append(fs.reqs, stationReq{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), body})
	delay, fail, accept := fs.delay, fs.fail, fs.accept
	if r.Method == http.MethodPost && r.URL.Path == "/local/v1/jobs" && fs.jobDelay > 0 {
		delay = fs.jobDelay
	}
	answerDelay, huge := fs.answerDelay, fs.huge
	fs.mu.Unlock()
	if huge {
		_, _ = io.WriteString(w, `"`+strings.Repeat("a", 5<<20)+`"`)
		return
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if fail != nil {
		if st, code := fail(r); st != 0 {
			stationErr(w, st, code)
			return
		}
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/local/v1/info":
		_ = json.NewEncoder(w).Encode(map[string]any{"station_id": "st1", "name": "Kitchen PC", "org_id": "org1", "location_id": "loc1",
			"version": "3.0.0", "port": 7443, "tls_mode": "self_signed", "cert_fingerprint_sha256": fs.fp, "hostnames": []string{},
			"addresses": []string{"127.0.0.1"}, "pairing_open": true, "time": time.Now().UTC().Format(time.RFC3339)})
		return
	case r.Method == http.MethodPost && r.URL.Path == "/local/v1/pair":
		if body["code"] != fs.pairCode {
			stationErr(w, 403, "invalid_code")
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"device_id": "d_0123456789abcdef", "token": "czd_paired", "station_id": "st1", "org_id": "org1", "location_id": "loc1"})
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	ok := strings.HasPrefix(tok, "czl1.") || strings.HasPrefix(tok, "czd_")
	if accept != nil {
		ok = accept(tok)
	}
	if !ok {
		code := fs.rejectCode
		if code == "" {
			code = "token_expired"
		}
		stationErr(w, 401, code)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/local/v1/jobs":
		key, _ := body["idempotency_key"].(string)
		fs.mu.Lock()
		if id, seen := fs.byKey[key]; seen && key != "" {
			j := fs.jobs[id]
			fs.mu.Unlock()
			_ = json.NewEncoder(w).Encode(j)
			return
		}
		fs.nextID++
		id := fmt.Sprintf("lj_%016x", fs.nextID)
		status := "queued"
		var finished any
		if r.URL.Query().Get("wait") != "" {
			status, finished = "printed", time.Now().UTC().Format(time.RFC3339Nano)
		}
		copies := 1
		if c, ok := body["copies"].(float64); ok {
			copies = int(c)
		}
		j := map[string]any{"id": id, "idempotency_key": key, "status": status, "detail": "", "printer_id": "p-kitchen",
			"printer_name": "Kitchen", "role": body["role"], "location_id": "loc1", "copies": copies, "title": body["title"],
			"reference": body["reference"], "created_at": time.Now().UTC().Format(time.RFC3339Nano), "finished_at": finished,
			"printed_locally": true, "via": "local", "cloud_job_id": nil}
		if fs.live != nil {
			j["live"] = *fs.live
		}
		fs.jobs[id] = j
		fs.byKey[key] = id
		fs.mu.Unlock()
		if answerDelay > 0 {
			select {
			case <-time.After(answerDelay):
			case <-r.Context().Done():
				return
			}
		}
		fs.mu.Lock()
		empty, inProgress := fs.emptyAnswer, fs.postInProgress
		fs.mu.Unlock()
		if inProgress {
			stationErr(w, 409, "in_progress")
			return
		}
		w.WriteHeader(201)
		if empty {
			_, _ = io.WriteString(w, "{}")
			return
		}
		_ = json.NewEncoder(w).Encode(j)
	case r.Method == http.MethodGet && r.URL.Path == "/local/v1/jobs":
		fs.mu.Lock()
		ps, pc := fs.probeStatus, fs.probeCode
		fs.mu.Unlock()
		if ps != 0 {
			stationErr(w, ps, pc)
			return
		}
		fs.mu.Lock()
		id, ok := fs.byKey[r.URL.Query().Get("idempotency_key")]
		j := fs.jobs[id]
		fs.mu.Unlock()
		if !ok {
			stationErr(w, 404, "not_found")
			return
		}
		_ = json.NewEncoder(w).Encode(j)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/local/v1/jobs/"):
		fs.mu.Lock()
		j, ok := fs.jobs[strings.TrimPrefix(r.URL.Path, "/local/v1/jobs/")]
		if ok {
			j["status"], j["finished_at"] = "printed", time.Now().UTC().Format(time.RFC3339Nano)
		}
		fs.mu.Unlock()
		if !ok {
			stationErr(w, 404, "not_found")
			return
		}
		_ = json.NewEncoder(w).Encode(j)
	case r.Method == http.MethodGet && r.URL.Path == "/local/v1/status":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"station":      map[string]any{"id": "st1", "name": "Kitchen PC", "cloud_connected": false, "last_cloud_contact": "", "version": "3.0.0", "local_enabled": true},
			"printers":     []any{map[string]any{"id": "p-kitchen", "name": "Kitchen", "role": "kitchen", "status": "ready", "paper": "ok", "jobs_waiting": 0}},
			"jobs_waiting": 0, "unsynced": 3, "allowance": map[string]any{"expires_at": "2026-11-14T00:00:00Z", "prints_left": 1997},
		})
	default:
		stationErr(w, 404, "not_found")
	}
}

// ---- fake cloud ----

type fakeCloud struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	mints     []map[string]any
	jobs      []map[string]any
	endpoints int
	revoked   []string
	jobStatus int    // when set, POST /jobs answers this status
	jobCode   string // with this code
	stations  []LocalEndpoint
	expiresIn time.Duration
	down      bool // every request: 503 (use closeConn for network errors)
	// jobFailures: the first N POST /jobs answer jobStatus, then succeed.
	jobFailures int
	// hangup: POST /jobs reads the request and drops the connection.
	hangup bool
}

func newFakeCloud(t *testing.T) *fakeCloud {
	fc := &fakeCloud{t: t, expiresIn: 30 * 24 * time.Hour}
	fc.srv = httptest.NewServer(http.HandlerFunc(fc.serve))
	t.Cleanup(fc.srv.Close)
	return fc
}

func makeLocalToken(jti string, live bool) string {
	p, _ := json.Marshal(map[string]any{"v": 1, "kid": "k1", "jti": jti, "org": "org1", "key": "key1", "loc": nil, "dev": "hub", "live": live, "iat": 1, "exp": 2})
	return "czl1." + base64.RawURLEncoding.EncodeToString(p) + ".c2ln"
}

func (fc *fakeCloud) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.down {
		writeErr(w, 503, `{"error":{"code":"unavailable","message":"Down."}}`)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/orgs/org1/local-tokens":
		fc.mints = append(fc.mints, body)
		jti := fmt.Sprintf("jti-%d", len(fc.mints))
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": makeLocalToken(jti, true), "token_id": jti,
			"expires_at": time.Now().Add(fc.expiresIn).UTC().Format(time.RFC3339), "stations": fc.stations})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/orgs/org1/local-tokens/"):
		fc.revoked = append(fc.revoked, strings.TrimPrefix(r.URL.Path, "/v1/orgs/org1/local-tokens/"))
		w.WriteHeader(204)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/orgs/org1/local-endpoints":
		fc.endpoints++
		_ = json.NewEncoder(w).Encode(map[string]any{"stations": fc.stations})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/orgs/org1/jobs":
		fc.jobs = append(fc.jobs, body)
		if fc.hangup {
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		if fc.jobStatus != 0 && (fc.jobFailures == 0 || len(fc.jobs) <= fc.jobFailures) {
			writeErr(w, fc.jobStatus, fmt.Sprintf(`{"error":{"code":%q,"message":"Cloud says no."}}`, fc.jobCode))
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"job": map[string]any{"id": "cloud-1", "status": "queued", "idempotency_key": body["idempotency_key"]}})
	default:
		writeErr(w, 404, `{"error":{"code":"not_found","message":"Nope."}}`)
	}
}

func (fc *fakeCloud) counts() (mints, jobs int) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return len(fc.mints), len(fc.jobs)
}

func (fc *fakeCloud) lastJob() map[string]any {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if len(fc.jobs) == 0 {
		return nil
	}
	return fc.jobs[len(fc.jobs)-1]
}

// newLocalClient builds a client against the fake cloud with a fast local
// config. Close is registered as cleanup.
func newLocalClient(t *testing.T, fc *fakeCloud, cfg LocalConfig, opts ...Option) *Client {
	t.Helper()
	base := fc.srv.URL
	if base == "" {
		base = "http://127.0.0.1:1"
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = time.Second
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 2 * time.Second
	}
	if cfg.CloudTimeout == 0 {
		cfg.CloudTimeout = 2 * time.Second
	}
	if cfg.DeviceName == "" {
		cfg.DeviceName = "Hub"
	}
	if cfg.LocationID == "" {
		cfg.AllLocations = true
	}
	all := append([]Option{WithAPIKey(fakeKey), WithBaseURL(base), WithOrgID("org1"), WithBackoff(time.Millisecond, 2*time.Millisecond), WithLocal(cfg)}, opts...)
	c, err := NewClient(all...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// deadURL returns an https URL on a closed local port.
func deadURL(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "https://" + addr
}

func kitchenParams(key string) JobParams {
	return JobParams{
		Role:           "kitchen",
		TemplateID:     "tpl-kitchen",
		Data:           map[string]any{"table": "12"},
		Reference:      "order-1042",
		IdempotencyKey: key,
	}
}

// ---- tests ----

func TestLocalModePrintsOnStation(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, LocationID: "loc1", StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	job, err := c.Jobs.Create(context.Background(), JobParams{Role: "kitchen", Commands: []Command{Text("ALLERGY"), Cut()}, Copies: 2})
	if err != nil {
		t.Fatal(err)
	}
	if job.Via != ViaLocal || !job.PrintedLocally || !strings.HasPrefix(job.ID, "lj_") || job.Status != StatusQueued || job.Copies != 2 || !job.Live {
		t.Fatalf("bad job %+v", job)
	}
	if job.Local == nil || job.Local.StationURL != st.url || job.PrinterName == nil || *job.PrinterName != "Kitchen" {
		t.Fatalf("local details missing: %+v", job.Local)
	}
	reqs := st.jobRequests()
	if len(reqs) != 1 {
		t.Fatalf("want 1 station job request, got %d", len(reqs))
	}
	r := reqs[0]
	key, _ := r.Body["idempotency_key"].(string)
	if !strings.HasPrefix(key, "sdk-") || len(key) != 40 {
		t.Fatalf("auto idempotency key %q", key)
	}
	if !strings.HasPrefix(r.Auth, "Bearer czl1.") || r.Body["kind"] != "commands" || r.Body["role"] != "kitchen" || r.Body["location_id"] != "loc1" {
		t.Fatalf("bad request %+v", r)
	}
	mints, jobs := fc.counts()
	if mints != 1 || jobs != 0 {
		t.Fatalf("mints=%d cloud jobs=%d", mints, jobs)
	}
	fc.mu.Lock()
	m := fc.mints[0]
	fc.mu.Unlock()
	if m["device_name"] != "Hub" || fmt.Sprint(m["location_ids"]) != "[loc1]" {
		t.Fatalf("mint body %v", m)
	}
	// The second job reuses the cached token.
	if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "hi"}); err != nil {
		t.Fatal(err)
	}
	if mints, _ := fc.counts(); mints != 1 {
		t.Fatalf("token not cached: %d mints", mints)
	}
}

func TestLocalJobBodyMatchesSpec(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, Wait: 5 * time.Second})
	job, err := c.Jobs.Create(context.Background(), JobParams{Content: []byte{0x1b, 0x40, 'h', 'i'}, Title: "Raw", Options: map[string]any{"cut": true}})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != StatusPrinted || job.PrintedAt == nil {
		t.Fatalf("wait not honoured: %+v", job)
	}
	r := st.jobRequests()[0]
	if r.Query != "wait=5" || r.Body["kind"] != "escpos" || r.Body["content"] != base64.StdEncoding.EncodeToString([]byte{0x1b, 0x40, 'h', 'i'}) || r.Body["title"] != "Raw" {
		t.Fatalf("bad request %+v", r)
	}
	for _, k := range []string{"file_name", "scheduled_for", "sealed_content"} {
		if _, ok := r.Body[k]; ok {
			t.Fatalf("%s must not be sent to a station", k)
		}
	}
}

func TestLocalFirstFallsBackWhenStationUnreachable(t *testing.T) {
	fc := newFakeCloud(t)
	dead := deadURL(t)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{dead}, Fingerprints: map[string]string{dead: strings.Repeat("ab", 32)}})
	job, err := c.Jobs.Create(context.Background(), kitchenParams("order-1042-kitchen-r1"))
	if err != nil {
		t.Fatal(err)
	}
	if job.Via != ViaCloud || job.ID != "cloud-1" || job.PrintedLocally {
		t.Fatalf("bad job %+v", job)
	}
	if fc.lastJob()["idempotency_key"] != "order-1042-kitchen-r1" {
		t.Fatalf("key not reused: %v", fc.lastJob())
	}
}

func TestLocalFirstFallbackRules(t *testing.T) {
	cases := []struct {
		status   int
		code     string
		fallback bool
		check    func(error) bool
	}{
		{502, "bad_gateway", true, nil},
		{504, "gateway_timeout", true, nil},
		{503, "local_disabled", true, nil},
		{503, "printer_offline", false, IsPrinterOffline},
		{503, "out_of_paper", false, IsOutOfPaper},
		{503, "cover_open", false, IsCoverOpen},
		{503, "printer_error", false, func(e error) bool { var pe *PrinterError; return errors.As(e, &pe) }},
		{422, "no_printer", false, func(e error) bool { var ve *ValidationError; return errors.As(e, &ve) }},
		{400, "invalid", false, func(e error) bool { var ve *ValidationError; return errors.As(e, &ve) }},
		{402, "offline_allowance_exhausted", false, IsOfflineAllowanceExhausted},
		{403, "device_not_approved", false, func(e error) bool { var pe *PermissionError; return errors.As(e, &pe) }},
		{429, "rate_limited", false, func(e error) bool { var rl *RateLimitError; return errors.As(e, &rl) }},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprint(tc.status, tc.code), func(t *testing.T) {
			fc := newFakeCloud(t)
			st := newFakeStation(t, nil)
			st.fail = func(r *http.Request) (int, string) {
				if r.URL.Path == "/local/v1/jobs" {
					return tc.status, tc.code
				}
				return 0, ""
			}
			c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
			job, err := c.Jobs.Create(context.Background(), kitchenParams("k-"+tc.code))
			_, cloudJobs := fc.counts()
			if tc.fallback {
				if err != nil || job.Via != ViaCloud || cloudJobs != 1 || fc.lastJob()["idempotency_key"] != "k-"+tc.code {
					t.Fatalf("want cloud fallback, got %v %v (cloud jobs %d)", job, err, cloudJobs)
				}
				return
			}
			if err == nil || cloudJobs != 0 {
				t.Fatalf("must not fall back: err=%v cloud jobs=%d", err, cloudJobs)
			}
			if IsStationUnreachable(err) || ErrorCode(err) != tc.code || !tc.check(err) {
				t.Fatalf("wrong error %T %v", err, err)
			}
		})
	}
}

func TestLocal401RemintsOnceThenSucceeds(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	// The station only accepts the second minted token.
	st.accept = func(tok string) bool { return tokenClaimsJTI(tok) == "jti-2" }
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	job, err := c.Jobs.Create(context.Background(), kitchenParams("k1"))
	if err != nil || job.Via != ViaLocal {
		t.Fatalf("got %v %v", job, err)
	}
	if mints, _ := fc.counts(); mints != 2 {
		t.Fatalf("want 2 mints, got %d", mints)
	}
	if n := len(st.jobRequests()); n != 2 {
		t.Fatalf("want 2 station attempts, got %d", n)
	}
}

func tokenClaimsJTI(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		JTI string `json:"jti"`
	}
	_ = json.Unmarshal(b, &c)
	return c.JTI
}

func TestLocal401TwiceFallsBackOrFails(t *testing.T) {
	for _, mode := range []LocalMode{ModeLocalFirst, ModeLocal} {
		t.Run(string(mode), func(t *testing.T) {
			fc := newFakeCloud(t)
			st := newFakeStation(t, nil)
			st.accept = func(string) bool { return false }
			c := newLocalClient(t, fc, LocalConfig{Mode: mode, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
			job, err := c.Jobs.Create(context.Background(), kitchenParams("k401"))
			mints, cloudJobs := fc.counts()
			if mints != 2 || len(st.jobRequests()) != 2 {
				t.Fatalf("re-mint must happen exactly once: mints=%d attempts=%d", mints, len(st.jobRequests()))
			}
			if mode == ModeLocalFirst {
				if err != nil || job.Via != ViaCloud || cloudJobs != 1 || fc.lastJob()["idempotency_key"] != "k401" {
					t.Fatalf("want cloud fallback, got %v %v", job, err)
				}
				return
			}
			var ae *AuthenticationError
			if !errors.As(err, &ae) || ae.Code != "token_expired" || cloudJobs != 0 {
				t.Fatalf("want 401 in local mode, got %T %v", err, err)
			}
		})
	}
}

func TestLocal401WithCloudDownFallsBackToCloudError(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	st.accept = func(string) bool { return false }
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	if _, err := c.Local.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	fc.mu.Lock()
	fc.down = true
	fc.mu.Unlock()
	_, err := c.Jobs.Create(context.Background(), kitchenParams("k"))
	var sue *StationUnreachableError
	var se *ServerError
	if !errors.As(err, &sue) || !errors.As(err, &se) || len(st.jobRequests()) != 1 {
		t.Fatalf("got %T %v (attempts %d)", err, err, len(st.jobRequests()))
	}
}

func TestCloudFirst(t *testing.T) {
	t.Run("503 goes local with the same key", func(t *testing.T) {
		fc := newFakeCloud(t)
		fc.jobStatus, fc.jobCode = 503, "unavailable"
		st := newFakeStation(t, nil)
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
		job, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		if err != nil || job.Via != ViaLocal {
			t.Fatalf("got %v %v", job, err)
		}
		cloudKey := fc.lastJob()["idempotency_key"].(string)
		if !strings.HasPrefix(cloudKey, "sdk-") || st.jobRequests()[0].Body["idempotency_key"] != cloudKey {
			t.Fatalf("key differs: cloud %q station %v", cloudKey, st.jobRequests()[0].Body["idempotency_key"])
		}
		if _, n := fc.counts(); n != 1 {
			t.Fatalf("cloud_first must not retry the cloud before falling back: %d", n)
		}
	})
	t.Run("network error goes local", func(t *testing.T) {
		st := newFakeStation(t, nil)
		c := newLocalClient(t, &fakeCloud{srv: &httptest.Server{}}, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, Token: "czd_paired"})
		job, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "order-7"})
		if err != nil || job.Via != ViaLocal || st.jobRequests()[0].Body["idempotency_key"] != "order-7" || st.jobRequests()[0].Auth != "Bearer czd_paired" {
			t.Fatalf("got %v %v", job, err)
		}
	})
	for _, tc := range []struct {
		status int
		code   string
	}{{422, "no_printer"}, {402, "out_of_prints"}, {429, "rate_limited"}, {401, "invalid_api_key"}} {
		t.Run(fmt.Sprint("4xx stays ", tc.status), func(t *testing.T) {
			fc := newFakeCloud(t)
			fc.jobStatus, fc.jobCode = tc.status, tc.code
			st := newFakeStation(t, nil)
			c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
			_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
			if ErrorCode(err) != tc.code || len(st.requests()) != 0 {
				t.Fatalf("got %v, station requests %d", err, len(st.requests()))
			}
		})
	}
	t.Run("both down", func(t *testing.T) {
		fc := newFakeCloud(t)
		fc.jobStatus, fc.jobCode = 503, "unavailable"
		dead := deadURL(t)
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeCloudFirst, StationURLs: []string{dead}, Fingerprints: map[string]string{dead: strings.Repeat("0", 64)}})
		_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		var sue *StationUnreachableError
		var se *ServerError
		if !errors.Is(err, ErrStationUnreachable) || !errors.As(err, &sue) || !errors.As(err, &se) || len(sue.URLs()) != 1 || sue.URLs()[0] != dead {
			t.Fatalf("got %T %v", err, err)
		}
	})
}

func TestUnsupportedLocally(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	pdf := []byte("%PDF-1.4 fake")
	local := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	_, err := local.PrintPDF(context.Background(), pdf, JobParams{})
	if ErrorCode(err) != "unsupported_locally" {
		t.Fatalf("got %v", err)
	}
	lf := newLocalClient(t, fc, LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}})
	job, err := lf.PrintPDF(context.Background(), pdf, JobParams{})
	if err != nil || job.Via != ViaCloud || len(st.requests()) != 0 {
		t.Fatalf("PDF must go straight to the cloud: %v %v", job, err)
	}
}

func TestStationOrderTriesNextOnUnreachable(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	dead := deadURL(t)
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, StationURLs: []string{dead, st.url},
		Fingerprints: map[string]string{dead: st.fp, st.url: st.fp}})
	job, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	if err != nil || job.Local.StationURL != st.url {
		t.Fatalf("got %v %v", job, err)
	}
}

// ---- TLS pinning ----

func TestPinning(t *testing.T) {
	fc := newFakeCloud(t)
	t.Run("no fingerprint: never contacted", func(t *testing.T) {
		st := newFakeStation(t, nil)
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}})
		_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		var sue *StationUnreachableError
		if !errors.As(err, &sue) || !errors.Is(sue.Attempts[0].Err, errNoPin) || len(st.requests()) != 0 {
			t.Fatalf("got %v, requests %d", err, len(st.requests()))
		}
	})
	t.Run("wrong fingerprint: rejected before any request", func(t *testing.T) {
		st := newFakeStation(t, nil)
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: strings.Repeat("ab", 32)}})
		_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		var pm *PinMismatchError
		var sue *StationUnreachableError
		if !errors.As(err, &sue) || !errors.As(sue.Attempts[0].Err, &pm) || pm.Got != st.fp || len(st.requests()) != 0 {
			t.Fatalf("got %v, requests %d", err, len(st.requests()))
		}
	})
	t.Run("fingerprint with colons, upper case", func(t *testing.T) {
		st := newFakeStation(t, nil)
		var parts []string
		for i := 0; i < len(st.fp); i += 2 {
			parts = append(parts, strings.ToUpper(st.fp[i:i+2]))
		}
		host := strings.TrimPrefix(st.url, "https://")
		c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}, Fingerprints: map[string]string{host: strings.Join(parts, ":")}})
		if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("fingerprint from the cloud endpoint list", func(t *testing.T) {
		st := newFakeStation(t, nil)
		fc2 := newFakeCloud(t)
		fc2.stations = []LocalEndpoint{{StationID: "st1", LocalEnabled: true, URLs: []string{st.url}, TLSMode: "self_signed", CertFingerprintSHA256: st.fp}}
		c := newLocalClient(t, fc2, LocalConfig{Mode: ModeLocal, StationURLs: []string{st.url}})
		job, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		if err != nil || job.StationID == nil || *job.StationID != "st1" {
			t.Fatalf("got %v %v", job, err)
		}
	})
	t.Run("public hostname from the cloud list: verified, SPKI-pinned, dialled under its label", func(t *testing.T) {
		ca, caKey := newTestCA(t)
		host := "127-0-0-1.abcdefghij.local.catzprint.com"
		cert := newLeaf(t, ca, caKey, host)
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		st := newFakeStation(t, &cert)
		port := st.url[strings.LastIndex(st.url, ":")+1:]
		hostURL := "https://" + host + ":" + port
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		ep := LocalEndpoint{StationID: "st1", LocalEnabled: true, TLSMode: "public", LocalLabel: "abcdefghij",
			URLs: []string{hostURL}, PublicSPKISHA256: hex.EncodeToString(spki[:])}
		fc2 := newFakeCloud(t)
		fc2.stations = []LocalEndpoint{ep}
		c := newLocalClient(t, fc2, LocalConfig{Mode: ModeLocal, Discover: true, RootCAs: pool})
		job, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
		if err != nil || job.Local.StationURL != hostURL {
			t.Fatalf("got %v %v", job, err)
		}
		// Same certificate chain, but the cloud reports another public key:
		// refused even though the WebPKI check passes.
		fc3 := newFakeCloud(t)
		ep.PublicSPKISHA256 = strings.Repeat("ab", 32)
		fc3.stations = []LocalEndpoint{ep}
		c3 := newLocalClient(t, fc3, LocalConfig{Mode: ModeLocal, Discover: true, RootCAs: pool})
		_, err = c3.Jobs.Create(context.Background(), JobParams{Text: "x"})
		var pm *PinMismatchError
		if !IsStationUnreachable(err) || !errors.As(err.(*StationUnreachableError).Attempts[0].Err, &pm) || !pm.SPKI {
			t.Fatalf("want SPKI pin mismatch, got %v", err)
		}
		// Without the CA (system roots only) the same certificate is refused.
		c2 := newLocalClient(t, fc2, LocalConfig{Mode: ModeLocal, Discover: true})
		_, err = c2.Jobs.Create(context.Background(), JobParams{Text: "x"})
		var ue x509.UnknownAuthorityError
		if !IsStationUnreachable(err) || !errors.As(err.(*StationUnreachableError).Attempts[0].Err, &ue) {
			t.Fatalf("want unknown authority, got %v", err)
		}
		// A configured hostname the cloud doesn't know is not dialled at the
		// IP in its name (DNS only; here it doesn't resolve).
		c4 := newLocalClient(t, &fakeCloud{srv: &httptest.Server{}}, LocalConfig{Mode: ModeLocal, StationURLs: []string{hostURL}, RootCAs: pool, Token: "czd_x"})
		_, err = c4.Jobs.Create(context.Background(), JobParams{Text: "x"})
		if !IsStationUnreachable(err) || len(st.jobRequests()) != 1 {
			t.Fatalf("unknown hostname dialled directly: %v (requests %d)", err, len(st.jobRequests()))
		}
	})
}

func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return ca, key
}

func newLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, host string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func TestDashedIP(t *testing.T) {
	for _, tc := range []struct{ host, label, want string }{
		{"192-168-1-20.ab3k9x2mqp.local.catzprint.com", "ab3k9x2mqp", "192.168.1.20"},
		{"192-168-1-20.ab3k9x2mqp.local.catzprint.com", "otherlabel", ""},
		{"192-168-1-20.ab3k9x2mqp.local.catzprint.com", "", ""},
		{"10-0-0-5.x.y", "x", "10.0.0.5"},
		{"8-8-8-8.x.local.catzprint.com", "x", ""},
		{"192-168-1.x.y", "x", ""},
		{"192-168-1-20.com", "com", ""},
		{"printer.example.com", "example", ""},
	} {
		got := ""
		if ip := dashedIP(tc.host, tc.label); ip != nil {
			got = ip.String()
		}
		if got != tc.want {
			t.Errorf("%s/%s: got %q want %q", tc.host, tc.label, got, tc.want)
		}
	}
}

// ---- token store ----

func TestFileTokenStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "tokens.json")
	s := NewFileTokenStore(path)
	ctx := context.Background()
	if tok, err := s.Load(ctx, "a"); err != nil || tok != nil {
		t.Fatalf("empty store: %v %v", tok, err)
	}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := s.Save(ctx, "a", &StoredToken{Token: "czl1.a", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "b", &StoredToken{Token: "czl1.b"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	got, err := NewFileTokenStore(path).Load(ctx, "a")
	if err != nil || got.Token != "czl1.a" || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("got %+v %v", got, err)
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), fakeKey) {
		t.Fatal("API key in the store")
	}
	// A corrupt file is reported on load and replaced on save.
	_ = os.WriteFile(path, []byte("{nope"), 0o600)
	if _, err := s.Load(ctx, "a"); err == nil {
		t.Fatal("want corrupt error")
	}
	if err := s.Save(ctx, "a", &StoredToken{Token: "czl1.c"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Load(ctx, "a"); got.Token != "czl1.c" {
		t.Fatal("not replaced")
	}
}

func TestTokenStoreSurvivesRestartAndRefreshes(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	path := filepath.Join(t.TempDir(), "tokens.json")
	cfg := LocalConfig{Mode: ModeLocal, LocationID: "loc1", StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, TokenStore: NewFileTokenStore(path)}
	fc.stations = []LocalEndpoint{{StationID: "st1", LocalEnabled: true}}

	c1 := newLocalClient(t, fc, cfg)
	if _, err := c1.Jobs.Create(context.Background(), JobParams{Text: "1"}); err != nil {
		t.Fatal(err)
	}
	_ = c1.Close()
	if m, _ := fc.counts(); m != 1 {
		t.Fatalf("mints %d", m)
	}

	// Restart: the stored token is used, nothing is minted.
	c2 := newLocalClient(t, fc, cfg)
	if _, err := c2.Jobs.Create(context.Background(), JobParams{Text: "2"}); err != nil {
		t.Fatal(err)
	}
	_ = c2.Close()
	if m, _ := fc.counts(); m != 1 {
		t.Fatalf("stored token not reused: %d mints", m)
	}

	// Less than 7 days left: the old token is used now and a new one is
	// minted in the background.
	ctx := context.Background()
	store := cfg.TokenStore
	key := c2.local.storeKey
	old, _ := store.Load(ctx, key)
	old.ExpiresAt = time.Now().Add(3 * 24 * time.Hour)
	old.IssuedAt = time.Now().Add(-27 * 24 * time.Hour) // a 30-day token with 3 days left
	_ = store.Save(ctx, key, old)
	c3 := newLocalClient(t, fc, cfg)
	if _, err := c3.Jobs.Create(ctx, JobParams{Text: "3"}); err != nil {
		t.Fatal(err)
	}
	reqs := st.jobRequests()
	if reqs[len(reqs)-1].Auth != "Bearer "+old.Token {
		t.Fatal("the still-valid token must be used for this job")
	}
	c3.local.wg.Wait() // let the background refresh finish (Close would cancel it)
	if m, _ := fc.counts(); m != 2 {
		t.Fatalf("want a background re-mint, mints=%d", m)
	}
	renewed, _ := store.Load(ctx, key)
	if renewed.Token == old.Token || renewed.ExpiresAt.Sub(time.Now()) < 20*24*time.Hour {
		t.Fatalf("store not updated: %+v", renewed)
	}

	// Expired: minted synchronously before the job.
	renewed.ExpiresAt = time.Now().Add(-time.Minute)
	_ = store.Save(ctx, key, renewed)
	c4 := newLocalClient(t, fc, cfg)
	if _, err := c4.Jobs.Create(ctx, JobParams{Text: "4"}); err != nil {
		t.Fatal(err)
	}
	reqs = st.jobRequests()
	if reqs[len(reqs)-1].Auth == "Bearer "+renewed.Token {
		t.Fatal("expired token used")
	}
}

func TestEndpointListRefreshedWhenStale(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	fc.stations = []LocalEndpoint{{StationID: "st1", LocalEnabled: true, URLs: []string{st.url}, CertFingerprintSHA256: st.fp, TLSMode: "self_signed"}}
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, Discover: true})
	now := time.Now()
	c.local.now = func() time.Time { return now }
	// First job: the mint brings the endpoint list, which is used right away.
	job, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	if err != nil || job.Local.StationURL != st.url {
		t.Fatalf("got %v %v", job, err)
	}
	fc.mu.Lock()
	eps := fc.endpoints
	fc.mu.Unlock()
	if eps != 0 {
		t.Fatalf("fresh list refreshed: %d", eps)
	}
	now = now.Add(2 * time.Hour)
	if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "y"}); err != nil {
		t.Fatal(err)
	}
	c.local.wg.Wait() // let the background refresh finish
	fc.mu.Lock()
	eps = fc.endpoints
	fc.mu.Unlock()
	if eps != 1 {
		t.Fatalf("want one endpoint refresh, got %d", eps)
	}
}

// ---- timeouts, cancellation, goroutines ----

func TestStationTimeoutFallsBack(t *testing.T) {
	// The job never reached the station's records (the probe by key gets
	// 404), so falling back is safe.
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	st.jobDelay = 2 * time.Second
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, RequestTimeout: 200 * time.Millisecond})
	start := time.Now()
	job, err := c.Jobs.Create(context.Background(), JobParams{Text: "x", IdempotencyKey: "slow-1"})
	if err != nil || job.Via != ViaCloud || fc.lastJob()["idempotency_key"] != "slow-1" {
		t.Fatalf("got %v %v", job, err)
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("timeout not applied: %v", time.Since(start))
	}
}

func TestContextCancellationStopsWithoutFallback(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	st.delay = 5 * time.Second
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocalFirst, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, RequestTimeout: 10 * time.Second})
	if _, err := c.Local.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(150*time.Millisecond, cancel)
	start := time.Now()
	_, err := c.Jobs.Create(ctx, JobParams{Text: "x"})
	if !errors.Is(err, context.Canceled) || IsStationUnreachable(err) {
		t.Fatalf("got %T %v", err, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation not honoured")
	}
	if _, jobs := fc.counts(); jobs != 0 {
		t.Fatal("a cancelled create must not fall back")
	}
}

func TestNoGoroutineLeaks(t *testing.T) {
	// Let goroutines of earlier tests (closing servers, connections) finish.
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n == before {
			break
		}
		before = n
	}
	func() {
		fc := newFakeCloud(t)
		st := newFakeStation(t, nil)
		resp := startFakeResponder(t, mdnsAnswer(t, "Bar PC", "st9", "org1", "loc1", 7443, st.fp, "127.0.0.1"))
		c, err := NewClient(WithAPIKey(fakeKey), WithBaseURL(fc.srv.URL), WithOrgID("org1"),
			WithLocal(LocalConfig{Mode: ModeLocalFirst, AllLocations: true, StationURLs: []string{st.url}, Fingerprints: map[string]string{st.url: st.fp}, Discover: true, DiscoverTimeout: 200 * time.Millisecond}))
		if err != nil {
			t.Fatal(err)
		}
		c.local.mdnsAddr = resp
		for i := 0; i < 3; i++ {
			if _, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.Local.Discover(context.Background()); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		st.srv.Close()
		fc.srv.Close()
	}()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+1 {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines: before %d after %d\n%s", before, n, buf[:runtime.Stack(buf, true)])
	}
}

// ---- local helpers ----

func TestLocalHelpers(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	fc.stations = []LocalEndpoint{{StationID: "st1", Name: "Kitchen PC", LocationID: "loc1", LocalEnabled: true, Port: 7443,
		Addresses: []string{"127.0.0.1"}, URLs: []string{st.url}, TLSMode: "self_signed", CertFingerprintSHA256: st.fp}}
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, LocationID: "loc1", Discover: true})
	ctx := context.Background()

	status, err := c.Local.Status(ctx)
	if err != nil || status.Unsynced != 3 || status.Allowance.PrintsLeft != 1997 || status.Station.LastCloudContact != nil || status.Printers[0].Role != "kitchen" || status.StationURL != st.url {
		t.Fatalf("status %+v %v", status, err)
	}
	info, err := c.Local.Info(ctx, st.url)
	if err != nil || info.StationID != "st1" || !info.PairingOpen {
		t.Fatalf("info %+v %v", info, err)
	}
	if _, err := c.Local.Pair(ctx, st.url, "1234", "Till"); ErrorCode(err) != "invalid" {
		t.Fatalf("bad code accepted: %v", err)
	}
	if _, err := c.Local.Pair(ctx, st.url, "00000000", "Till"); ErrorCode(err) != "invalid_code" {
		t.Fatalf("wrong code: %v", err)
	}
	p, err := c.Local.Pair(ctx, st.url, "12345678", "Till 3")
	if err != nil || p.Token != "czd_paired" || p.DeviceID != "d_0123456789abcdef" {
		t.Fatalf("pair %+v %v", p, err)
	}
	pr := st.requests()[len(st.requests())-1]
	if pr.Auth != "" || pr.Body["device_name"] != "Till 3" {
		t.Fatalf("pair request %+v", pr)
	}

	job, err := c.Jobs.Create(ctx, JobParams{Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Jobs.WaitFor(ctx, job.ID, WithPollInterval(10*time.Millisecond))
	if err != nil || got.Status != StatusPrinted || got.Via != ViaLocal || got.PrintedAt == nil {
		t.Fatalf("waitfor %+v %v", got, err)
	}
	if _, err := c.Jobs.Get(ctx, "lj_missing"); ErrorCode(err) != "not_found" {
		t.Fatalf("missing local job: %v", err)
	}

	stations, err := c.Local.Discover(ctx)
	if err != nil || len(stations) != 1 || !stations[0].FromCloud || stations[0].Fingerprint != st.fp || stations[0].URLs[0] != st.url {
		t.Fatalf("discover %+v %v", stations, err)
	}

	lt, err := c.LocalTokens.Create(ctx, LocalTokenParams{DeviceName: "Till 9", LocationIDs: []string{"loc1"}, TTLDays: 7})
	if err != nil || !strings.HasPrefix(lt.Token, "czl1.") || len(lt.Stations) != 1 {
		t.Fatalf("token %+v %v", lt, err)
	}
	fc.mu.Lock()
	m := fc.mints[len(fc.mints)-1]
	fc.mu.Unlock()
	if m["ttl_days"] != float64(7) || m["device_name"] != "Till 9" {
		t.Fatalf("mint body %v", m)
	}
	if err := c.LocalTokens.Revoke(ctx, lt.TokenID); err != nil {
		t.Fatal(err)
	}
	fc.mu.Lock()
	revoked := fc.revoked
	fc.mu.Unlock()
	if len(revoked) != 1 || revoked[0] != lt.TokenID {
		t.Fatalf("revoked %v", revoked)
	}
	eps, err := c.LocalEndpoints.List(ctx, "loc1")
	if err != nil || len(eps) != 1 || eps[0].Port != 7443 {
		t.Fatalf("endpoints %+v %v", eps, err)
	}
}

func TestLocalConfigValidation(t *testing.T) {
	bad := []LocalConfig{
		{Mode: "offline"},
		{Mode: ModeLocal},
		{Mode: ModeLocalFirst, StationURLs: []string{"http://192.168.1.20:7443"}},
		{Mode: ModeLocal, StationURLs: []string{"https://192.168.1.20:7443/x"}},
		{Mode: ModeLocal, StationURLs: []string{"https://192.168.1.20:7443"}, Fingerprints: map[string]string{"192.168.1.20": "abc"}},
		{Mode: ModeLocal, Discover: true, Token: "cz_live_x"},
		{Mode: ModeLocal, Discover: true, Wait: time.Minute},
	}
	for i, cfg := range bad {
		if _, err := NewClient(WithAPIKey(fakeKey), WithLocal(cfg)); err == nil {
			t.Errorf("%d: config accepted: %+v", i, cfg)
		}
	}
	if _, err := NewClient(WithAPIKey(fakeKey), WithLocal(LocalConfig{Mode: ModeLocalFirst, Discover: true})); err == nil {
		t.Error("minting without LocationID or AllLocations accepted")
	}
	c, err := NewClient(WithAPIKey(fakeKey), WithLocal(LocalConfig{Mode: ModeLocalFirst, Discover: true, LocationID: "loc1"}))
	if err != nil || c.Local.Mode() != ModeLocalFirst {
		t.Fatal(err)
	}
	_ = c.Close()
}

func TestCloudModeUnchanged(t *testing.T) {
	var key string
	c := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		key, _ = b["idempotency_key"].(string)
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"job":{"id":"j1","status":"queued","printed_locally":false,"local_device":null,"duplicate_of":"j0"}}`)
	})
	job, err := c.PrintText(context.Background(), "x", JobParams{})
	if err != nil || job.Via != ViaCloud || job.DuplicateOf == nil || *job.DuplicateOf != "j0" {
		t.Fatalf("got %+v %v", job, err)
	}
	if strings.HasPrefix(key, "sdk-") || len(key) != 36 {
		t.Fatalf("cloud mode key changed: %q", key)
	}
}

func TestStationUnreachableErrorMessage(t *testing.T) {
	e := &StationUnreachableError{}
	e.add("https://10.0.0.5:7443", &ConnectionError{Err: errors.New("connection refused")})
	e.CloudErr = &ServerError{&APIError{Status: 503, Code: "unavailable", Message: "Down."}}
	s := e.Error()
	if !strings.Contains(s, "10.0.0.5") || !strings.Contains(s, "connection refused") || !strings.Contains(s, "cloud fallback failed") {
		t.Fatal(s)
	}
	if !errors.Is(e, ErrStationUnreachable) || !IsStationUnreachable(fmt.Errorf("wrapped: %w", e)) {
		t.Fatal("Is")
	}
}
