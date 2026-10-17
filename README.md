# CatzPrint Go SDK

The official Go client for the [CatzPrint](https://catzprint.com) API: send
receipts, PDFs, images and templates to printers from your Go services.

- Go 1.26+, standard library only (plus `golang.org/x/crypto` for sealed printing)
- `context.Context` on every call, functional options, typed errors for `errors.As`
- Safe automatic retries with idempotency keys, auto-paging iterators, webhook verification

## Install

```sh
go get github.com/Catalizo/catzprint-go-sdk/v2
```

## Quickstart

```go
package main

import (
	"context"
	"fmt"
	"log"

	catzprint "github.com/Catalizo/catzprint-go-sdk/v2"
)

func main() {
	client, err := catzprint.NewClient(catzprint.WithAPIKey("cz_test_…"))
	if err != nil {
		log.Fatal(err)
	}
	job, err := client.PrintText(context.Background(), "Hello from Go!", catzprint.JobParams{Role: "receipt"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(job.ID, job.Status)
}
```

## The client

```go
client, err := catzprint.NewClient(
	catzprint.WithAPIKey(os.Getenv("CATZPRINT_API_KEY")), // default: $CATZPRINT_API_KEY
	catzprint.WithBaseURL("https://api-v1.catzprint.com"), // default, or $CATZPRINT_BASE_URL
	catzprint.WithOrgID("…"),                             // optional: skips the GET /v1/key lookup
	catzprint.WithTimeout(30*time.Second),                // per attempt
	catzprint.WithMaxRetries(2),
	catzprint.WithBackoff(500*time.Millisecond, 8*time.Second),
	catzprint.WithHTTPClient(&http.Client{}),
	catzprint.WithUserAgentSuffix("my-shop/2.1"),
)
```

A `*Client` is safe for concurrent use; create one and share it. Its
`String()` and `%#v` output never contain the API key.

Every key belongs to one organization. The SDK looks it up once with
`GET /v1/key` and caches it:

```go
key, err := client.Key(ctx) // or client.WhoAmI(ctx)
fmt.Println(key.OrgID, key.OrgName, key.Live, key.Scopes)
```

## Printing

Choose a destination with `PrinterID`, `LocationID` and/or `Role` (or leave
them empty to use your routing rules), and exactly one content source.

```go
// Plain text
job, err := client.PrintText(ctx, "Table 4\n2 x Soup", catzprint.JobParams{Role: "kitchen"})

// ESC/POS receipt commands
job, err := client.PrintReceipt(ctx, []catzprint.Command{
	{Type: "text", Text: "Corner Café", Align: "center", Bold: true, Size: 2},
	catzprint.Line(),
	catzprint.Columns(catzprint.Column{Text: "Flat white"}, catzprint.Column{Text: "3.50", Align: "right"}),
	catzprint.QR("https://example.com/r/1042"),
	catzprint.Cut(),
}, catzprint.JobParams{Role: "receipt", Reference: "order-1042"})

// A saved template filled with data
job, err := client.PrintTemplate(ctx, templateID, map[string]any{"total": "10.20"}, catzprint.JobParams{Role: "receipt"})

// PDF bytes, an image, or a file from disk (PDF, PNG/JPEG, text, Office)
job, err := client.PrintPDF(ctx, pdfBytes, catzprint.JobParams{PrinterID: officeID})
job, err := client.PrintImage(ctx, pngBytes, catzprint.JobParams{Role: "label"})
job, err := client.PrintFile(ctx, "invoice.pdf", catzprint.JobParams{Role: "office", Copies: 2})

// Everything at once with Jobs.Create
when := time.Now().Add(time.Hour)
job, err := client.Jobs.Create(ctx, catzprint.JobParams{
	PrinterID:      printerID,
	Text:           "Prep the oven",
	Title:          "Reminder",
	Reference:      "kitchen-7",
	Copies:         1,
	ScheduledFor:   &when,            // held as "scheduled" until then
	IdempotencyKey: "kitchen-7",      // generated for you when empty
	Options:        map[string]any{}, // passed through to the station
})
```

### Managing jobs

```go
job, err := client.Jobs.Get(ctx, id)        // job.Events holds the status history
job, err  = client.Jobs.Cancel(ctx, id)     // scheduled, held, queued or sent jobs
job, err  = client.Jobs.Retry(ctx, id)      // failed or held jobs
job, err  = client.Jobs.Reprint(ctx, id, catzprint.ReprintParams{PrinterID: otherID, Copies: 2})

// Wait until printed, failed or cancelled (default timeout 60s, poll every 1s)
job, err = client.Jobs.WaitFor(ctx, id, catzprint.WithWaitTimeout(2*time.Minute), catzprint.WithPollInterval(time.Second))
var te *catzprint.TimeoutError
if errors.As(err, &te) {
	fmt.Println("still", te.Job.Status)
}
```

Statuses: `scheduled`, `held`, `queued`, `sent`, `printing`, `printed`,
`failed`, `cancelled` (constants `catzprint.StatusPrinted` etc.).

### Listing jobs

`Jobs.List` returns one page (newest first) with `NextCursor`. `Jobs.Iter`
walks every page for you:

```go
it := client.Jobs.Iter(ctx, catzprint.ListJobsParams{Status: []string{"failed"}, Limit: 100})
for it.Next() {
	fmt.Println(it.Job().ID, it.Job().StatusDetail)
}
if err := it.Err(); err != nil {
	log.Fatal(err)
}

// Go 1.23+: range over a function
for job, err := range client.Jobs.All(ctx, catzprint.ListJobsParams{PrinterID: id}) {
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(job.ID)
}

// One page at a time
page, err := client.Jobs.List(ctx, catzprint.ListJobsParams{Limit: 50, Cursor: ""})
```

Filters: `Status`, `PrinterID`, `StationID`, `LocationID`, `Source`, `Live`,
`Query` (reference, title or ID prefix), `Since`, `Limit` (1–200), `Cursor`.

### Printers, locations, templates

```go
printers, err := client.Printers.List(ctx)
locations, err := client.Locations.List(ctx)
location, err := client.Locations.Get(ctx, id)
templates, err := client.Templates.List(ctx)
```

## Sealed printing

Set `Sealed: true` to encrypt `Text` or `Content` on your machine to the
server's public key (NaCl sealed box, X25519 + XSalsa20-Poly1305) before it
leaves. The server key is fetched once from `GET /v1/public/server-key` and
cached. Commands and templates can't be sealed.

```go
job, err := client.PrintPDF(ctx, pdf, catzprint.JobParams{Role: "office", Sealed: true})
```

`catzprint.Seal(publicKey, msg)` is exported if you need to seal by hand.

## Errors

Every API error is an `*catzprint.APIError` (`Status`, `Code`, `Message`,
`Fields`, `RetryAfter`) wrapped in a kind-specific type:

| Type | When |
|---|---|
| `*AuthenticationError` | 401: missing, wrong, revoked or expired key |
| `*PermissionError` | 403: the key's scopes or mode don't allow it |
| `*NotFoundError` | 404 |
| `*ValidationError` | 400 / 422; `Fields` says what to fix |
| `*OutOfPrintsError` | 402 `out_of_prints` |
| `*ConflictError` | 409, e.g. cancelling a printed job |
| `*RateLimitError` | 429; `RetryAfter` says how long to wait |
| `*ServerError` | 5xx |
| `*ConnectionError` | network failure or timeout (unwraps to the cause) |
| `*TimeoutError` | `Jobs.WaitFor` ran out of time |
| `*SignatureVerificationError` | webhook verification failed |

```go
job, err := client.PrintText(ctx, "Hi", catzprint.JobParams{PrinterID: id})
var ve *catzprint.ValidationError
var oop *catzprint.OutOfPrintsError
var api *catzprint.APIError
switch {
case errors.As(err, &ve):
	fmt.Println("fix:", ve.Fields)
case errors.As(err, &oop):
	fmt.Println("top up:", oop.Message)
case errors.As(err, &api): // any other API error
	fmt.Println(api.Status, api.Code, api.Message)
case errors.Is(err, context.DeadlineExceeded):
	fmt.Println("timed out")
}
```

## Retries and idempotency

Failed requests are retried up to 2 times (`WithMaxRetries`) with exponential
backoff and jitter on network errors, 429 (honouring `Retry-After` /
`retry_after_seconds`) and 502/503/504. A POST is only retried when it
carries an idempotency key: `Jobs.Create` (and every `Print*` helper) always
sends one, generating a UUIDv4 when you don't set `IdempotencyKey`, and
reuses it on every retry, so a job is never printed twice. Pass your own key
(an order number, say) to make your own retries safe too: the same key
always returns the same job. `Cancel`, `Retry` and `Reprint` are not retried.

## Webhooks

CatzPrint signs each delivery with `CatzPrint-Signature: t=<unix>,v1=<hex>`,
an HMAC-SHA256 of `t + "." + body` with your endpoint secret. Verify it with
the raw body (before any JSON parsing):

```go
http.HandleFunc("POST /webhooks/catzprint", func(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	event, err := catzprint.VerifyWebhook(body, r.Header.Get(catzprint.SignatureHeader), os.Getenv("CATZPRINT_WEBHOOK_SECRET"))
	if err != nil {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}
	if event.Type == "job.printed" {
		job, _ := event.Job()
		log.Printf("printed %s", job.ID)
	}
	w.WriteHeader(http.StatusNoContent)
})
```

Signatures older or newer than 5 minutes are rejected
(`catzprint.WithTolerance(d)` changes it), comparison is constant-time, and
headers with several `v1` entries (secret rotation) are accepted.
`catzprint.ConstructEvent` and `client.Webhooks.Verify` / `ConstructEvent`
are aliases. `catzprint.SignWebhook(secret, time.Now(), body)` makes test
signatures for your handler tests.

Every event carries `event.ID`, the delivery id, which stays the same across
retries. **Deduplicate on `event.ID`**: the timestamp check limits the replay
window to 5 minutes, it does not stop a captured delivery from being replayed
within that window (and retries can deliver the same event twice).

Events: `job.created`, `job.printed`, `job.failed`, `job.cancelled`,
`job.retried`, `station.online`, `station.offline`, `printer.status`, `ping`.

## Test and live keys

- `cz_test_…` keys print for real but are never billed: jobs come back with
  `Live: false` and `BilledAs: "test"`, and they can only change test jobs.
- `cz_live_…` keys print billed jobs against your organization's prints.

`client.IsTestMode()` tells you which one a client uses.

## Examples

- [`examples/print-receipt`](examples/print-receipt): an ESC/POS receipt
- [`examples/print-pdf-and-wait`](examples/print-pdf-and-wait): a sealed PDF, waiting until printed
- [`examples/verify-webhook`](examples/verify-webhook): a net/http webhook endpoint

```sh
CATZPRINT_API_KEY=cz_test_… go run ./examples/print-receipt
```

## Development

```sh
go vet ./... && gofmt -l . && go test -race ./...
# Integration tests against a running API:
CATZPRINT_TEST_FIXTURE=/path/to/fixture.json go test -race -run Integration -v ./...
```

## License

MIT, Copyright Catalizo. See [LICENSE](LICENSE).
