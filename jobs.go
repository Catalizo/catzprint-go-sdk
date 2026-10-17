package catzprint

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// JobsService creates, lists and manages print jobs. Use it via Client.Jobs.
type JobsService struct{ c *Client }

// JobParams describes a job to print. Choose where it goes with PrinterID,
// LocationID and/or Role (or leave them empty to use your routing rules),
// and set exactly ONE content source: Text, Commands, TemplateID (+ Data) or
// Content (+ FileName).
type JobParams struct {
	// Where to print.
	PrinterID  string
	LocationID string
	Role       string // receipt, kitchen, bar, label, office, other

	// Kind is the content kind: text, commands, template, escpos, image,
	// pdf or document. The SDK fills it in when left empty.
	Kind      string
	Title     string
	Reference string
	// Copies is 1..50 (0 means 1, or the routing rule's copies).
	Copies int
	// IdempotencyKey makes retries safe: the same key always returns the
	// same job. The SDK generates one when empty.
	IdempotencyKey string
	// ScheduledFor holds the job until this time (at most 30 days ahead).
	ScheduledFor *time.Time
	Options      map[string]any

	// Content sources (set exactly one).
	Text       string
	Commands   []Command
	TemplateID string
	Data       map[string]any
	Content    []byte // PDF, PNG/JPEG, raw ESC/POS or an Office document
	FileName   string // helps detect the type of Content

	// Sealed encrypts Text or Content on this machine to the server's
	// public key (NaCl sealed box) before sending it.
	Sealed bool
}

func (p *JobParams) sources() int {
	n := 0
	if p.Text != "" {
		n++
	}
	if len(p.Commands) > 0 {
		n++
	}
	if p.TemplateID != "" {
		n++
	}
	if len(p.Content) > 0 {
		n++
	}
	return n
}

// body builds the JSON request. The idempotency key must already be set.
func (s *JobsService) body(ctx context.Context, p *JobParams) (map[string]any, error) {
	if n := p.sources(); n == 0 {
		return nil, invalidParams("content", "Set one content source: Text, Commands, TemplateID or Content.")
	} else if n > 1 {
		return nil, invalidParams("content", "Set only one content source: Text, Commands, TemplateID or Content.")
	}
	if p.Data != nil && p.TemplateID == "" {
		return nil, invalidParams("data", "Data is only used with TemplateID.")
	}
	b := map[string]any{"idempotency_key": p.IdempotencyKey}
	setStr := func(k, v string) {
		if v != "" {
			b[k] = v
		}
	}
	setStr("printer_id", p.PrinterID)
	setStr("location_id", p.LocationID)
	setStr("role", p.Role)
	setStr("title", p.Title)
	setStr("reference", p.Reference)
	setStr("file_name", p.FileName)
	if p.Copies != 0 {
		b["copies"] = p.Copies
	}
	if p.ScheduledFor != nil {
		b["scheduled_for"] = p.ScheduledFor.UTC().Format(time.RFC3339Nano)
	}
	if len(p.Options) > 0 {
		b["options"] = p.Options
	}
	kind := p.Kind
	var raw []byte
	switch {
	case p.Text != "":
		if kind == "" {
			kind = "text"
		}
		raw = []byte(p.Text)
		if !p.Sealed {
			b["content"] = p.Text // the API takes text kind as plain text
		}
	case len(p.Commands) > 0:
		if kind == "" {
			kind = "commands"
		}
		b["commands"] = p.Commands
	case p.TemplateID != "":
		if kind == "" {
			kind = "template"
		}
		b["template_id"] = p.TemplateID
		if p.Data != nil {
			b["data"] = p.Data
		}
	default:
		if kind == "" {
			kind = detectKind(p.Content, p.FileName)
		}
		raw = p.Content
		if !p.Sealed {
			if kind == "text" {
				b["content"] = string(p.Content)
			} else {
				b["content"] = base64.StdEncoding.EncodeToString(p.Content)
			}
		}
	}
	if p.Sealed {
		if raw == nil {
			return nil, invalidParams("sealed", "Sealing works with Text or Content, not Commands or templates.")
		}
		pub, err := s.c.ServerKey(ctx)
		if err != nil {
			return nil, err
		}
		sealed, err := sealTo(pub, raw)
		if err != nil {
			return nil, err
		}
		b["sealed_content"] = base64.StdEncoding.EncodeToString(sealed)
	}
	b["kind"] = kind
	return b, nil
}

// detectKind guesses the kind of raw content from its first bytes.
func detectKind(b []byte, name string) string {
	switch {
	case bytes.HasPrefix(b, []byte("%PDF-")):
		return "pdf"
	case bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G'}), bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}):
		return "image"
	case len(b) > 0 && (b[0] == 0x1b || b[0] == 0x1d) && name == "":
		return "escpos"
	}
	return "document"
}

// Create sends a job to print. It always carries an idempotency key, so
// network failures and 5xx/429 answers are retried safely.
func (s *JobsService) Create(ctx context.Context, params JobParams) (*Job, error) {
	if params.IdempotencyKey == "" {
		params.IdempotencyKey = newUUID()
	}
	body, err := s.body(ctx, &params)
	if err != nil {
		return nil, err
	}
	path, err := s.c.orgPath(ctx, "/jobs")
	if err != nil {
		return nil, err
	}
	var out struct {
		Job *Job `json:"job"`
	}
	if err := s.c.do(ctx, http.MethodPost, path, nil, body, &out, true); err != nil {
		return nil, err
	}
	return out.Job, nil
}

// Get returns a job with its status history (Job.Events).
func (s *JobsService) Get(ctx context.Context, id string) (*Job, error) {
	path, err := s.c.orgPath(ctx, "/jobs/%s", id)
	if err != nil {
		return nil, err
	}
	var out struct {
		Job    *Job       `json:"job"`
		Events []JobEvent `json:"events"`
	}
	if err := s.c.do(ctx, http.MethodGet, path, nil, nil, &out, false); err != nil {
		return nil, err
	}
	if out.Job == nil {
		return nil, &APIError{Status: http.StatusOK, Code: "invalid_response", Message: "The API answered without a job."}
	}
	out.Job.Events = out.Events
	return out.Job, nil
}

// ListJobsParams filters Jobs.List. All fields are optional.
type ListJobsParams struct {
	// Status keeps jobs with any of these statuses.
	Status     []string
	PrinterID  string
	StationID  string
	LocationID string
	// Source is api, console, app, playground, share or station.
	Source string
	// Live filters live (true) or test (false) jobs.
	Live *bool
	// Query matches reference, title or the start of the job ID.
	Query string
	// Since keeps jobs created at or after this time.
	Since *time.Time
	// Limit is the page size, 1..200 (default 50).
	Limit int
	// Cursor continues from a previous page's NextCursor.
	Cursor string
}

func (p ListJobsParams) values() url.Values {
	v := url.Values{}
	if len(p.Status) > 0 {
		v.Set("status", strings.Join(p.Status, ","))
	}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	set("printer_id", p.PrinterID)
	set("station_id", p.StationID)
	set("location_id", p.LocationID)
	set("source", p.Source)
	set("q", p.Query)
	set("cursor", p.Cursor)
	if p.Live != nil {
		v.Set("live", strconv.FormatBool(*p.Live))
	}
	if p.Since != nil {
		v.Set("since", p.Since.UTC().Format(time.RFC3339))
	}
	if p.Limit > 0 {
		v.Set("limit", strconv.Itoa(p.Limit))
	}
	return v
}

// JobList is one page of jobs, newest first.
type JobList struct {
	Items []Job `json:"items"`
	// NextCursor is empty on the last page.
	NextCursor string `json:"next_cursor"`
}

// List returns one page of jobs. Use Iter or All to walk every page.
func (s *JobsService) List(ctx context.Context, params ListJobsParams) (*JobList, error) {
	path, err := s.c.orgPath(ctx, "/jobs")
	if err != nil {
		return nil, err
	}
	var out JobList
	if err := s.c.do(ctx, http.MethodGet, path, params.values(), nil, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// JobIterator walks every job matching a filter, fetching pages as needed:
//
//	it := client.Jobs.Iter(ctx, catzprint.ListJobsParams{Status: []string{"failed"}})
//	for it.Next() {
//		job := it.Job()
//	}
//	if err := it.Err(); err != nil { ... }
type JobIterator struct {
	ctx    context.Context
	s      *JobsService
	params ListJobsParams
	page   []Job
	idx    int
	cur    *Job
	err    error
	done   bool
}

// Iter returns an iterator over all jobs matching params.
func (s *JobsService) Iter(ctx context.Context, params ListJobsParams) *JobIterator {
	return &JobIterator{ctx: ctx, s: s, params: params}
}

// Next advances to the next job. It returns false at the end or on error.
func (it *JobIterator) Next() bool {
	if it.err != nil {
		return false
	}
	for it.idx >= len(it.page) {
		if it.done {
			return false
		}
		list, err := it.s.List(it.ctx, it.params)
		if err != nil {
			it.err = err
			return false
		}
		it.page, it.idx = list.Items, 0
		it.params.Cursor = list.NextCursor
		it.done = list.NextCursor == ""
	}
	it.cur = &it.page[it.idx]
	it.idx++
	return true
}

// Job is the current job.
func (it *JobIterator) Job() *Job { return it.cur }

// Err is the error that stopped iteration, if any.
func (it *JobIterator) Err() error { return it.err }

// All returns a range-over-func sequence of every matching job, for Go
// 1.23+ callers:
//
//	for job, err := range client.Jobs.All(ctx, params) { ... }
//
// Iteration stops after the first error.
func (s *JobsService) All(ctx context.Context, params ListJobsParams) func(yield func(*Job, error) bool) {
	return func(yield func(*Job, error) bool) {
		it := s.Iter(ctx, params)
		for it.Next() {
			if !yield(it.Job(), nil) {
				return
			}
		}
		if err := it.Err(); err != nil {
			yield(nil, err)
		}
	}
}

// Cancel cancels a scheduled, held, queued or sent job.
func (s *JobsService) Cancel(ctx context.Context, id string) (*Job, error) {
	return s.action(ctx, id, "cancel", nil)
}

// Retry re-queues a failed or held job.
func (s *JobsService) Retry(ctx context.Context, id string) (*Job, error) {
	return s.action(ctx, id, "retry", nil)
}

// ReprintParams are the optional settings for Jobs.Reprint.
type ReprintParams struct {
	// PrinterID prints on another printer (default: the original one).
	PrinterID string
	// Copies is 1..50 (default: the original copies).
	Copies int
}

// Reprint creates a new job with the same content.
func (s *JobsService) Reprint(ctx context.Context, id string, params ReprintParams) (*Job, error) {
	body := map[string]any{}
	if params.PrinterID != "" {
		body["printer_id"] = params.PrinterID
	}
	if params.Copies != 0 {
		body["copies"] = params.Copies
	}
	return s.action(ctx, id, "reprint", body)
}

func (s *JobsService) action(ctx context.Context, id, verb string, body any) (*Job, error) {
	path, err := s.c.orgPath(ctx, "/jobs/%s/"+verb, id)
	if err != nil {
		return nil, err
	}
	var out struct {
		Job *Job `json:"job"`
	}
	if err := s.c.do(ctx, http.MethodPost, path, nil, body, &out, false); err != nil {
		return nil, err
	}
	return out.Job, nil
}

type waitConfig struct {
	timeout  time.Duration
	interval time.Duration
}

// WaitOption configures Jobs.WaitFor.
type WaitOption func(*waitConfig)

// WithWaitTimeout sets how long WaitFor polls (default 60s).
func WithWaitTimeout(d time.Duration) WaitOption { return func(w *waitConfig) { w.timeout = d } }

// WithPollInterval sets the time between polls (default 1s).
func WithPollInterval(d time.Duration) WaitOption { return func(w *waitConfig) { w.interval = d } }

// WaitFor polls a job until it is printed, failed or cancelled and returns
// the final job. It returns a *TimeoutError when the timeout passes first.
// A failed or cancelled job is returned without error; check Job.Status.
func (s *JobsService) WaitFor(ctx context.Context, id string, opts ...WaitOption) (*Job, error) {
	cfg := waitConfig{timeout: 60 * time.Second, interval: time.Second}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.interval <= 0 {
		cfg.interval = time.Second
	}
	deadline := time.Now().Add(cfg.timeout)
	var last *Job
	for {
		job, err := s.Get(ctx, id)
		if err != nil {
			var nf *NotFoundError
			if errors.As(err, &nf) || ctx.Err() != nil {
				return nil, err
			}
			var ce *ConnectionError
			var se *ServerError
			var rl *RateLimitError
			if !errors.As(err, &ce) && !errors.As(err, &se) && !errors.As(err, &rl) {
				return nil, err
			}
			// Transient: keep polling until the deadline.
		} else {
			last = job
			if job.Finished() {
				return job, nil
			}
		}
		wait := cfg.interval
		if remaining := time.Until(deadline); remaining <= 0 {
			return last, &TimeoutError{JobID: id, Job: last, Timeout: cfg.timeout}
		} else if remaining < wait {
			wait = remaining
		}
		if err := sleepCtx(ctx, wait); err != nil {
			return last, &ConnectionError{Err: err}
		}
	}
}

// PrintText prints plain text.
func (c *Client) PrintText(ctx context.Context, text string, params JobParams) (*Job, error) {
	params.Text = text
	return c.Jobs.Create(ctx, params)
}

// PrintPDF prints a PDF document.
func (c *Client) PrintPDF(ctx context.Context, pdf []byte, params JobParams) (*Job, error) {
	params.Content = pdf
	if params.Kind == "" {
		params.Kind = "pdf"
	}
	return c.Jobs.Create(ctx, params)
}

// PrintFile reads a file (PDF, PNG/JPEG, text or Office document) and prints
// it. The file name is sent for type detection and as the default title.
func (c *Client) PrintFile(ctx context.Context, path string, params JobParams) (*Job, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("catzprint: reading %s: %w", path, err)
	}
	params.Content = b
	if params.FileName == "" {
		params.FileName = filepath.Base(path)
	}
	if params.Title == "" {
		params.Title = filepath.Base(path)
	}
	return c.Jobs.Create(ctx, params)
}

// PrintImage prints a PNG or JPEG image.
func (c *Client) PrintImage(ctx context.Context, img []byte, params JobParams) (*Job, error) {
	params.Content = img
	if params.Kind == "" {
		params.Kind = "image"
	}
	return c.Jobs.Create(ctx, params)
}

// PrintReceipt prints a list of ESC/POS commands.
func (c *Client) PrintReceipt(ctx context.Context, commands []Command, params JobParams) (*Job, error) {
	params.Commands = commands
	return c.Jobs.Create(ctx, params)
}

// PrintTemplate prints a saved template filled with data.
func (c *Client) PrintTemplate(ctx context.Context, templateID string, data map[string]any, params JobParams) (*Job, error) {
	params.TemplateID = templateID
	params.Data = data
	return c.Jobs.Create(ctx, params)
}

// newUUID returns a random UUIDv4.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("catzprint: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
