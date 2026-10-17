package catzprint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Integration tests run against a live API when CATZPRINT_TEST_FIXTURE
// points at a fixture file (see make_fixture.py).
type fixture struct {
	BaseURL          string `json:"base_url"`
	OrgID            string `json:"org_id"`
	LocationID       string `json:"location_id"`
	ReceiptPrinterID string `json:"receipt_printer_id"`
	OfficePrinterID  string `json:"office_printer_id"`
	APIKeyLive       string `json:"api_key_live"`
	APIKeyTest       string `json:"api_key_test"`
	APIKeyReadOnly   string `json:"api_key_printers_read_only"`
	DeviceToken      string `json:"device_token"`
}

func loadFixture(t *testing.T) *fixture {
	t.Helper()
	path := os.Getenv("CATZPRINT_TEST_FIXTURE")
	if path == "" {
		t.Skip("CATZPRINT_TEST_FIXTURE not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func (f *fixture) client(t *testing.T, key string) *Client {
	t.Helper()
	c, err := NewClient(WithAPIKey(key), WithBaseURL(f.BaseURL), WithUserAgentSuffix("integration-test"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// device calls the station API with the fixture's device token.
func (f *fixture) device(t *testing.T, method, path, body string) []byte {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, f.BaseURL+path, rd)
	req.Header.Set("Authorization", "Bearer "+f.DeviceToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("device %s %s: %d %s", method, path, resp.StatusCode, b)
	}
	return b
}

// tinyPDF is a minimal valid one-page PDF.
func tinyPDF() []byte {
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		"",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	stream := "BT /F1 24 Tf 72 760 Td (CatzPrint Go SDK sealed test) Tj ET"
	objs[3] = fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream)
	var b strings.Builder
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, o := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return []byte(b.String())
}

func TestIntegration(t *testing.T) {
	f := loadFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	live := f.client(t, f.APIKeyLive)
	test := f.client(t, f.APIKeyTest)
	start := time.Now().Add(-time.Minute)

	var sealedJob *Job

	t.Run("1 key returns the org", func(t *testing.T) {
		k, err := live.Key(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if k.OrgID != f.OrgID || k.OrgName == "" || !k.Live || len(k.Scopes) == 0 {
			t.Fatalf("key = %+v", k)
		}
		tk, err := test.WhoAmI(ctx)
		if err != nil || tk.Live || tk.OrgID != f.OrgID {
			t.Fatalf("test key = %+v %v", tk, err)
		}
	})

	t.Run("read endpoints", func(t *testing.T) {
		ps, err := live.Printers.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, p := range ps {
			found[p.ID] = true
		}
		if !found[f.ReceiptPrinterID] || !found[f.OfficePrinterID] {
			t.Fatalf("printers missing: %+v", ps)
		}
		ls, err := live.Locations.List(ctx)
		if err != nil || len(ls) == 0 {
			t.Fatalf("locations %v %v", ls, err)
		}
		l, err := live.Locations.Get(ctx, f.LocationID)
		if err != nil || l.ID != f.LocationID || l.Name == "" {
			t.Fatalf("location %+v %v", l, err)
		}
		if _, err := live.Templates.List(ctx); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("2 test key prints text unbilled", func(t *testing.T) {
		j, err := test.PrintText(ctx, "Go SDK integration test\nHello!", JobParams{PrinterID: f.ReceiptPrinterID, Title: "Go SDK text", Reference: "go-sdk-it"})
		if err != nil {
			t.Fatal(err)
		}
		if j.Live || j.BilledAs != "test" || j.Kind != "escpos" || j.Source != "api" {
			t.Fatalf("job = %+v", j)
		}
	})

	t.Run("3 live key prints a sealed PDF", func(t *testing.T) {
		j, err := live.PrintPDF(ctx, tinyPDF(), JobParams{PrinterID: f.OfficePrinterID, Title: "Go SDK sealed PDF", Sealed: true})
		if err != nil {
			t.Fatal(err)
		}
		if !j.Live || j.Kind != "pdf" || j.PrinterID == nil || *j.PrinterID != f.OfficePrinterID {
			t.Fatalf("job = %+v", j)
		}
		sealedJob = j
	})

	t.Run("4 station prints it and WaitFor sees printed", func(t *testing.T) {
		if sealedJob == nil {
			t.Skip("no job from step 3")
		}
		// The station collects pending jobs (marking them sent). Other SDK
		// test runs share this station, so ours may already have been
		// collected by them; check the job's status rather than only the
		// list we got back.
		deadline := time.Now().Add(20 * time.Second)
		for {
			f.device(t, http.MethodGet, "/v1/device/jobs", "")
			j, err := live.Jobs.Get(ctx, sealedJob.ID)
			if err != nil {
				t.Fatal(err)
			}
			if j.Status == StatusSent || j.Status == StatusPrinting || j.Finished() {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("job never sent: %s", j.Status)
			}
			time.Sleep(300 * time.Millisecond)
		}
		f.device(t, http.MethodPost, "/v1/device/jobs/"+sealedJob.ID+"/status", `{"status":"printed"}`)
		j, err := live.Jobs.WaitFor(ctx, sealedJob.ID, WithWaitTimeout(30*time.Second), WithPollInterval(500*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		if j.Status != StatusPrinted || j.PrintedAt == nil || len(j.Events) == 0 {
			t.Fatalf("job = %+v", j)
		}
	})

	t.Run("5 list includes it and a scheduled job cancels", func(t *testing.T) {
		if sealedJob == nil {
			t.Skip("no job from step 3")
		}
		since := start
		it := live.Jobs.Iter(ctx, ListJobsParams{PrinterID: f.OfficePrinterID, Since: &since, Limit: 2})
		found, n := false, 0
		for it.Next() {
			n++
			if it.Job().ID == sealedJob.ID {
				found = true
				break
			}
		}
		if err := it.Err(); err != nil {
			t.Fatal(err)
		}
		if !found {
			t.Fatalf("job not listed (looked at %d)", n)
		}
		page, err := live.Jobs.List(ctx, ListJobsParams{Status: []string{StatusPrinted}, Limit: 5})
		if err != nil || len(page.Items) == 0 {
			t.Fatalf("list %v %v", page, err)
		}

		when := time.Now().Add(time.Hour)
		j, err := test.PrintText(ctx, "Scheduled from the Go SDK", JobParams{PrinterID: f.ReceiptPrinterID, ScheduledFor: &when})
		if err != nil {
			t.Fatal(err)
		}
		if j.Status != StatusScheduled {
			t.Fatalf("status = %s", j.Status)
		}
		c, err := test.Jobs.Cancel(ctx, j.ID)
		if err != nil || c.Status != StatusCancelled {
			t.Fatalf("cancel %+v %v", c, err)
		}
		// Cancelling again is a conflict.
		_, err = test.Jobs.Cancel(ctx, j.ID)
		var ce *ConflictError
		if !errors.As(err, &ce) {
			t.Fatalf("want ConflictError, got %v", err)
		}
	})

	t.Run("6 errors", func(t *testing.T) {
		ro := f.client(t, f.APIKeyReadOnly)
		_, err := ro.PrintText(ctx, "nope", JobParams{PrinterID: f.ReceiptPrinterID})
		var pe *PermissionError
		if !errors.As(err, &pe) {
			t.Fatalf("read-only key: want PermissionError, got %T %v", err, err)
		}

		bad, _ := NewClient(WithAPIKey("cz_live_thisKeyDoesNotExist000000000000000000000"), WithBaseURL(f.BaseURL))
		_, err = bad.Key(ctx)
		var ae *AuthenticationError
		if !errors.As(err, &ae) {
			t.Fatalf("bad key: want AuthenticationError, got %T %v", err, err)
		}
		if strings.Contains(err.Error(), "thisKeyDoesNotExist") {
			t.Fatal("key leaked into error")
		}

		_, err = test.PrintText(ctx, "x", JobParams{PrinterID: "00000000-0000-4000-8000-000000000000"})
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Fields["printer_id"] == "" {
			t.Fatalf("unknown printer: want ValidationError on printer_id, got %T %v", err, err)
		}

		_, err = test.Jobs.Get(ctx, "00000000-0000-4000-8000-000000000000")
		var nf *NotFoundError
		if !errors.As(err, &nf) {
			t.Fatalf("unknown job: want NotFoundError, got %T %v", err, err)
		}
	})

	t.Run("7 idempotency returns the same job", func(t *testing.T) {
		key := "go-sdk-it-" + newUUID()
		a, err := test.PrintText(ctx, "Idempotent", JobParams{PrinterID: f.ReceiptPrinterID, IdempotencyKey: key})
		if err != nil {
			t.Fatal(err)
		}
		b, err := test.PrintText(ctx, "Idempotent", JobParams{PrinterID: f.ReceiptPrinterID, IdempotencyKey: key})
		if err != nil {
			t.Fatal(err)
		}
		if a.ID != b.ID {
			t.Fatalf("different jobs: %s vs %s", a.ID, b.ID)
		}
	})
}
