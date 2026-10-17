// Package catzprint is the official Go client for the CatzPrint API.
//
// Create a client with an API key (or set CATZPRINT_API_KEY) and print:
//
//	client, err := catzprint.NewClient(catzprint.WithAPIKey("cz_test_..."))
//	if err != nil { ... }
//	job, err := client.PrintText(ctx, "Hello from Go", catzprint.JobParams{Role: "receipt"})
//
// Every call takes a context.Context. Errors returned by the API are typed
// (see APIError and the kind-specific error types) and work with errors.As.
package catzprint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version is the SDK version.
const Version = "2.1.3"

// DefaultBaseURL is the production API.
const DefaultBaseURL = "https://api-v1.catzprint.com"

const (
	defaultTimeout    = 30 * time.Second
	defaultMaxRetries = 2
	defaultBackoff    = 500 * time.Millisecond
	defaultMaxBackoff = 8 * time.Second
	maxRetryAfter     = 60 * time.Second
	userAgent         = "catzprint-go/" + Version
)

// Client talks to the CatzPrint API. It is safe for concurrent use.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
	maxRetries int
	backoff    time.Duration
	maxBackoff time.Duration
	userAgent  string

	mu        sync.Mutex
	orgID     string
	serverKey *[32]byte

	// Jobs creates, lists and manages print jobs.
	Jobs *JobsService
	// Printers lists the organization's printers.
	Printers *PrintersService
	// Locations lists and reads locations.
	Locations *LocationsService
	// Templates lists saved receipt templates.
	Templates *TemplatesService
	// Webhooks verifies webhook signatures.
	Webhooks *WebhooksService
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey sets the API key (cz_live_… or cz_test_…). Without it the
// client reads CATZPRINT_API_KEY.
func WithAPIKey(key string) Option { return func(c *Client) { c.apiKey = key } }

// WithBaseURL overrides the API base URL (default https://api-v1.catzprint.com,
// or CATZPRINT_BASE_URL when set).
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = strings.TrimRight(u, "/") } }

// WithOrgID sets the organization explicitly, skipping the GET /v1/key lookup.
func WithOrgID(id string) Option { return func(c *Client) { c.orgID = id } }

// WithHTTPClient uses a custom *http.Client (for proxies, transports, tests).
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.httpClient = hc } }

// WithTimeout sets the per-attempt request timeout (default 30s). Zero or
// negative disables it; the context still applies.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// WithMaxRetries sets how many times a failed request is retried (default 2).
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n < 0 {
			n = 0
		}
		c.maxRetries = n
	}
}

// WithBackoff sets the initial and maximum wait between retries
// (default 500ms doubling up to 8s, with jitter).
func WithBackoff(initial, max time.Duration) Option {
	return func(c *Client) { c.backoff, c.maxBackoff = initial, max }
}

// WithUserAgentSuffix appends text (such as your app name) to the User-Agent.
func WithUserAgentSuffix(s string) Option {
	return func(c *Client) {
		if s != "" {
			c.userAgent = userAgent + " " + s
		}
	}
}

// NewClient builds a client. It fails when no API key is given or found in
// the environment.
func NewClient(opts ...Option) (*Client, error) {
	c := &Client{
		apiKey:     os.Getenv("CATZPRINT_API_KEY"),
		baseURL:    DefaultBaseURL,
		httpClient: &http.Client{},
		timeout:    defaultTimeout,
		maxRetries: defaultMaxRetries,
		backoff:    defaultBackoff,
		maxBackoff: defaultMaxBackoff,
		userAgent:  userAgent,
	}
	if env := os.Getenv("CATZPRINT_BASE_URL"); env != "" {
		c.baseURL = strings.TrimRight(env, "/")
	}
	for _, o := range opts {
		o(c)
	}
	if c.apiKey == "" {
		return nil, errors.New("catzprint: no API key; pass WithAPIKey or set CATZPRINT_API_KEY")
	}
	if !strings.HasPrefix(c.apiKey, "cz_live_") && !strings.HasPrefix(c.apiKey, "cz_test_") {
		return nil, errors.New("catzprint: API keys start with cz_live_ or cz_test_")
	}
	if err := checkBaseURL(c.baseURL); err != nil {
		return nil, err
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{}
	}
	if c.httpClient.CheckRedirect == nil {
		// Never follow redirects: the Authorization header must only reach
		// the configured API host. Work on a copy so the caller's client is
		// left untouched.
		hc := *c.httpClient
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		c.httpClient = &hc
	}
	if c.backoff <= 0 {
		c.backoff = defaultBackoff
	}
	if c.maxBackoff < c.backoff {
		c.maxBackoff = c.backoff
	}
	c.Jobs = &JobsService{c: c}
	c.Printers = &PrintersService{c: c}
	c.Locations = &LocationsService{c: c}
	c.Templates = &TemplatesService{c: c}
	c.Webhooks = &WebhooksService{}
	return c, nil
}

// checkBaseURL requires https, allowing plain http only for a local server
// (tests, development proxies): the API key travels with every request.
func checkBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("catzprint: the base URL isn't a valid URL")
	}
	if u.User != nil {
		return errors.New("catzprint: the base URL must not contain credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("catzprint: the base URL must not contain a query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	local := host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".localhost")
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && local:
	default:
		return errors.New("catzprint: the base URL must use https:// (http:// is allowed only for localhost), so the API key isn't sent in clear text")
	}
	return nil
}

// maxResponseBytes caps how much of a response body the SDK reads.
const maxResponseBytes = 64 << 20

// IsTestMode reports whether the client uses a test key (cz_test_), whose
// jobs are never billed.
func (c *Client) IsTestMode() bool { return strings.HasPrefix(c.apiKey, "cz_test_") }

// String never reveals the API key.
func (c *Client) String() string {
	return fmt.Sprintf("catzprint.Client{baseURL: %q, apiKey: %q}", c.baseURL, redact(c.apiKey))
}

// GoString never reveals the API key (used by %#v).
func (c *Client) GoString() string { return c.String() }

func redact(key string) string {
	switch {
	case strings.HasPrefix(key, "cz_live_"):
		return "cz_live_…"
	case strings.HasPrefix(key, "cz_test_"):
		return "cz_test_…"
	case key == "":
		return ""
	}
	return "…"
}

// Key returns the API key's identity and organization (GET /v1/key) and
// caches the organization ID for later calls.
func (c *Client) Key(ctx context.Context) (*Key, error) {
	var k Key
	if err := c.do(ctx, http.MethodGet, "/v1/key", nil, nil, &k, false); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.orgID == "" {
		c.orgID = k.OrgID
	}
	c.mu.Unlock()
	return &k, nil
}

// WhoAmI is an alias for Key.
func (c *Client) WhoAmI(ctx context.Context) (*Key, error) { return c.Key(ctx) }

// OrgID returns the organization the key belongs to, looking it up once.
func (c *Client) OrgID(ctx context.Context) (string, error) {
	c.mu.Lock()
	id := c.orgID
	c.mu.Unlock()
	if id != "" {
		return id, nil
	}
	k, err := c.Key(ctx)
	if err != nil {
		return "", err
	}
	return k.OrgID, nil
}

func (c *Client) orgPath(ctx context.Context, format string, args ...any) (string, error) {
	org, err := c.OrgID(ctx)
	if err != nil {
		return "", err
	}
	esc := make([]any, len(args))
	for i, a := range args {
		esc[i] = url.PathEscape(fmt.Sprint(a))
	}
	return "/v1/orgs/" + url.PathEscape(org) + fmt.Sprintf(format, esc...), nil
}

// do sends one API call with retries. retryPOST says whether a POST is safe
// to retry (it carries an idempotency key).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any, retryPOST bool) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("catzprint: encoding request: %w", err)
		}
	}
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	retryable := method != http.MethodPost || retryPOST
	for attempt := 0; ; attempt++ {
		respBody, status, header, err := c.attempt(ctx, method, u, payload)
		if err == nil && status < 300 {
			if out == nil || len(bytes.TrimSpace(respBody)) == 0 {
				return nil
			}
			if err := json.Unmarshal(respBody, out); err != nil {
				return &APIError{Status: status, Code: "invalid_response", Message: "The API returned a response the SDK couldn't read: " + err.Error()}
			}
			return nil
		}
		if err == nil {
			err = parseError(status, header, respBody)
		}
		if ctx.Err() != nil {
			return &ConnectionError{Err: ctx.Err()}
		}
		if !retryable || attempt >= c.maxRetries || !shouldRetry(err) {
			return err
		}
		if werr := sleepCtx(ctx, c.retryDelay(attempt, err)); werr != nil {
			return &ConnectionError{Err: werr}
		}
	}
}

func (c *Client) attempt(ctx context.Context, method, u string, payload []byte) ([]byte, int, http.Header, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("catzprint: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, nil, &ConnectionError{Err: err}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, 0, nil, &ConnectionError{Err: err}
	}
	if len(b) > maxResponseBytes {
		return nil, 0, nil, &APIError{Status: resp.StatusCode, Code: "response_too_large",
			Message: fmt.Sprintf("The API response is larger than %d bytes.", maxResponseBytes)}
	}
	return b, resp.StatusCode, resp.Header, nil
}

func shouldRetry(err error) bool {
	var ce *ConnectionError
	if errors.As(err, &ce) {
		return true
	}
	var ae *APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
	}
	return false
}

func (c *Client) retryDelay(attempt int, err error) time.Duration {
	var ae *APIError
	if errors.As(err, &ae) && ae.RetryAfter > 0 {
		if ae.RetryAfter > maxRetryAfter {
			return maxRetryAfter
		}
		return ae.RetryAfter
	}
	d := c.backoff << attempt
	if d > c.maxBackoff || d <= 0 {
		d = c.maxBackoff
	}
	// Full jitter between d/2 and d.
	half := d / 2
	return half + time.Duration(rand.Int63n(int64(half)+1))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func parseError(status int, header http.Header, body []byte) error {
	var env struct {
		Error struct {
			Code              string            `json:"code"`
			Message           string            `json:"message"`
			Fields            map[string]string `json:"fields"`
			RetryAfterSeconds int               `json:"retry_after_seconds"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &env)
	e := &APIError{
		Status:  status,
		Code:    env.Error.Code,
		Message: env.Error.Message,
		Fields:  env.Error.Fields,
	}
	if e.Code == "" {
		e.Code = "http_" + strconv.Itoa(status)
	}
	if e.Message == "" {
		e.Message = http.StatusText(status)
	}
	if env.Error.RetryAfterSeconds > 0 {
		e.RetryAfter = time.Duration(env.Error.RetryAfterSeconds) * time.Second
	} else if ra := header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && secs > 0 {
			e.RetryAfter = time.Duration(secs) * time.Second
		} else if t, err := http.ParseTime(ra); err == nil {
			if d := time.Until(t); d > 0 {
				e.RetryAfter = d
			}
		}
	}
	return e.typed()
}
