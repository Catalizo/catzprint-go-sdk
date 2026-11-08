# CatzPrint Go SDK

The official Go client for the [CatzPrint](https://catzprint.com) API: send
receipts, PDFs, images and templates to printers from your Go services.

- Go 1.26+, standard library only (plus `golang.org/x/crypto` for sealed printing and `golang.org/x/net` for mDNS)
- Local printing through CatzPrint stations when the internet is down
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
`String()` and `%#v` output never contain the API key. `LocalConfig`,
`StoredToken`, `LocalToken` and `LocalPairing` redact tokens in every `fmt`
verb and in `log/slog`. `json.Marshal` keeps the token for `StoredToken`,
`LocalToken` and `LocalPairing` (results you persist or hand to a browser
till); only `LocalConfig`'s JSON is redacted. A stored token that is a
redaction placeholder (`…`, a run of 3+ `*`, `[redacted]`, `redacted` or
`hidden`, optionally after `czl1.`/`czd_`) is treated as "no token"
(`Local.StoreError`, cleared once a fresh token was minted and stored).

Every key belongs to one organization. The SDK looks it up once with
`GET /v1/key` and caches it:

```go
key, err := client.Key(ctx) // or client.WhoAmI(ctx)
fmt.Println(key.OrgID, key.OrgName, key.Live, key.Scopes)
```

## Printing

Choose a destination with `PrinterID`, `LocationID` and/or `Role` (or leave
them empty to use your routing rules), and exactly one content source.

Printer names aren't unique (two stations can each have a "Kitchen"), so target printers by ID. `client.Printers.List` returns each printer's `id`, `station_id`, `station_name`, `location_id` and `role`. Optional shortcut: in the CatzPrint console, open **Locations & stations** (**My devices** in a personal account), then a station, and click the ID under a printer's name to copy it.

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

## Local printing (offline)

A restaurant must print when its internet is down. With `WithLocal`, the SDK
sends jobs straight to the CatzPrint Station (desktop or Android) on the same network
(its local API on port 7443), and the station reports everything it printed
offline to the cloud when it's back: one job per idempotency key, billed,
with webhooks (`job.PrintedLocally`, `job.Offline`, `job.DuplicateOf`).

```go
client, err := catzprint.NewClient(
	catzprint.WithAPIKey(os.Getenv("CATZPRINT_API_KEY")),
	catzprint.WithLocal(catzprint.LocalConfig{
		Mode:       catzprint.ModeLocalFirst,
		LocationID: locationID,
		Discover:   true, // the cloud's endpoint list + mDNS on the LAN
		TokenStore: catzprint.NewFileTokenStore("/var/lib/catzserve/catzprint-local.json"),
		DeviceName: "CatzServe hub",
	}),
)
if err != nil {
	log.Fatal(err)
}
defer client.Close()

// A kitchen ticket: an inverted ALLERGY banner, then the order.
job, err := client.Jobs.Create(ctx, catzprint.JobParams{
	Role:      "kitchen",
	Reference: fmt.Sprintf("order-%d", order.ID),
	// One key per ticket and attempt: the station and the cloud both
	// dedupe on it, so a fallback or a retry never prints twice.
	IdempotencyKey: fmt.Sprintf("order-%d-kitchen-r1", order.ID),
	Commands: []catzprint.Command{
		{Type: "text", Text: " ALLERGY: PEANUTS ", Align: "center", Bold: true, Invert: true, Size: 2},
		{Type: "text", Text: "Table 12", Bold: true, Size: 2},
		catzprint.Line(),
		catzprint.Columns(catzprint.Column{Text: "2 x", Width: 0.15}, catzprint.Column{Text: "Pad thai", Bold: true}),
		catzprint.Text("   no egg"),
		catzprint.Cut(),
	},
})

// Or a saved template with data (templates are synced to the station):
job, err = client.Jobs.Create(ctx, catzprint.JobParams{
	Role:           "kitchen",
	TemplateID:     kitchenTemplateID,
	Data:           map[string]any{"table": "12", "items": items},
	IdempotencyKey: fmt.Sprintf("order-%d-kitchen-r1", order.ID),
})
fmt.Println(job.ID, job.Status, job.Via, job.Live) // lj_… queued local true   (or … cloud)
```

### Modes

| Mode | Behaviour |
|---|---|
| `ModeCloud` (default) | Unchanged: every job goes to the API. |
| `ModeLocal` | Stations only. No station → `*StationUnreachableError`. |
| `ModeLocalFirst` | Stations first; the cloud **only** when no station can be reached. |
| `ModeCloudFirst` | Cloud first; stations on a network error, timeout or 5xx. A 4xx (validation, 402, 429…) is returned, not retried locally. |

In `local_first` the SDK falls back to the cloud only when the stations are
**unreachable**: connection, TLS or timeout errors, `502`/`504`, and `503
local_disabled`. A station that answers is never second-guessed: these are
returned to you, never sent to the cloud:

| Station answer | Go |
|---|---|
| `503 printer_offline` / `out_of_paper` / `cover_open` / `printer_error` (not accepted, not counted) | `*PrinterError`, `IsPrinterOffline`, `IsOutOfPaper`, `IsCoverOpen` |
| `422 no_printer` / `invalid` / `unsupported_locally`, `400` | `*ValidationError` |
| `402 offline_allowance_exhausted` (offline too long / offline prints used) | `*OutOfPrintsError`, `IsOfflineAllowanceExhausted` |
| `403 device_not_approved` / `forbidden_location` | `*PermissionError` |

A `401 token_expired` makes the SDK mint a fresh token once and retry (at most
once per 10 minutes). Any other `401` (`device_revoked`, `unauthenticated`), or a
token that can't be renewed because the cloud is down too: `local_first` uses
the cloud and `local` returns the `*AuthenticationError`.

**Never printed twice.** The SDK tells "the job never got there" from "it got
there but the answer was lost":

- *Not delivered* (DNS, connect, TLS or pin failure, or the station refused with
  502/504/503 `local_disabled`): the next station is tried, then (in
  `local_first`) the cloud.
- *Sent, no answer* (timeout or reset after the request was written, a body read
  error, an oversized or unreadable answer, a redirect): the SDK asks **that
  station** for the job by idempotency key (`GET /local/v1/jobs?idempotency_key=`,
  up to 3 times within 5 s). Found → that job is the result. 404 → it never got
  it, so the SDK moves on. Still unknown → `*OutcomeUnknownError`
  (`errors.Is(err, catzprint.ErrOutcomeUnknown)`, `IsOutcomeUnknown`, code
  `outcome_unknown`, with `URL` and `IdempotencyKey`) and **no fallback**.
- The cloud leg (`cloud_first`, and the cloud fallback of `local_first`) makes
  one attempt. Not delivered or 502/503/504 → `cloud_first` goes to the
  stations, `local_first` returns `*StationUnreachableError` with the cloud
  error. Sent with no answer or a 500 → one retry with the same key; if that is
  ambiguous or undelivered again → `*OutcomeUnknownError`, never a station (the
  cloud may already have queued the job).

- A probe answered with `409 duplicate` (the key belongs to a job this device
  can't see) is returned as that `*ConflictError`: an answer, no fallback. A
  `409 in_progress` (the station is still processing that key), on the job
  request or a probe, is waited for by probing; if it never settles →
  `*OutcomeUnknownError`. Once any answer for the key said `409 in_progress`
  (the job request itself or an earlier probe), a probe's `404` is **not**
  "never recorded" either → `*OutcomeUnknownError` (no next station, no cloud).
- The cloud request is built (and sealed) once; the ambiguous retry and the 409
  re-sends send exactly the same bytes. Jobs that can't print locally (PDF,
  images, documents, sealed, scheduled) use the cloud-mode create, 409 loop
  included, in every mode. A failure before the job request (org lookup,
  server-key fetch) counts as not delivered.
- A cloud `409 duplicate` / "being created" is re-sent (identically, same key)
  up to 3 times, 1 s apart; if it is still 409 that conflict is returned. A
  re-send that isn't delivered or is ambiguous → `*OutcomeUnknownError`.
- A cloud `400`/`422` naming `sealed_content` (the server key was rotated)
  drops the cached server key, fetches it again, re-seals and re-sends **once**
  with the same idempotency key. After an ambiguous attempt, a failed key fetch
  or a re-send that is rejected again, not delivered or ambiguous →
  `*OutcomeUnknownError` (never a `*ValidationError`, never a station); without
  one, a repeated rejection is returned as the `*ValidationError`.
- In `local_first`, a cloud 4xx after the stations were unreachable is returned
  as is; an `*OutcomeUnknownError` from the cloud leg is returned as is too
  (never wrapped in `*StationUnreachableError`).
- **Cancelling** the context after the job request was fully written returns an
  `*OutcomeUnknownError` wrapping the cancellation (the job may print; no
  fallback). Cancelling before that returns the cancellation error.

Retrying later with the same idempotency key is always safe: the station and
the cloud return the job they already have.

The fallback modes always send an idempotency key; when you don't set one (or
it is blank) the SDK uses `"sdk-<uuid v4>"` and sends the **same** key to the station and the
cloud. If a station printed a job and the cloud later gets the same key, the
cloud merges them instead of printing again. Use your own keys (like
`order-1042-kitchen-r1`) so your own retries are safe too.

Jobs that can't print locally (PDFs, images, Office documents, sealed or
scheduled jobs) go straight to the cloud in `local_first`/`cloud_first` and
return a `ValidationError` with code `unsupported_locally` in `local` mode.
When a job sets neither `PrinterID` nor `LocationID`, `LocalConfig.LocationID`
is used.

```go
var sue *catzprint.StationUnreachableError
switch {
case err == nil:
case catzprint.IsPrinterOffline(err), catzprint.IsOutOfPaper(err):
	// tell the staff; retry later with the same key
case errors.As(err, &sue):
	fmt.Println("tried", sue.URLs(), "cloud:", sue.CloudErr) // errors.Is(err, catzprint.ErrStationUnreachable)
}
```

### Finding and trusting stations

Stations are tried in this order: `StationURLs`, then (with `Discover`) the
URLs from the cloud's endpoint list (public-certificate hostnames before raw
IPs), then current addresses found over mDNS (`_catzprint._tcp`), browsed only
when the others failed.

- **Public hostnames** (`https://192-168-1-20.<label>.local.catzprint.com:7443`)
  come **only** from the cloud endpoint list. They carry a Let's Encrypt
  certificate, verified like any website, **and** the certificate's public key
  must match the `public_spki_sha256` the cloud reports. The SDK connects to the
  IP in the name directly (so they work while public DNS is down) only for names
  under that station's own label.
- **IP URLs** are trusted **only** with a pinned SHA-256 fingerprint of the
  station's self-signed certificate: from the cloud endpoint list or
  `LocalConfig.Fingerprints` (the station app shows it). Only private addresses
  (RFC 1918, IPv6 ULA, link-local) are used. Nothing is trusted on first use.
- **mDNS is never trusted on its own.** It only maps a station ID to its current
  address, for a station on the cloud endpoint list (pinned with the list's
  fingerprint) or one whose announced fingerprint is in `Fingerprints`. The
  announced hostname is ignored. So a device on the LAN can't pose as your
  station, even with its own valid CatzPrint certificate.

The local token (`czl1…`) is minted with your API key
(`POST /v1/orgs/{org}/local-tokens`, scope `jobs:write`) and **bound to
`LocationID`** (required unless you set `AllLocations: true`). It is cached in
the `TokenStore` with the endpoint list, renewed in the background when it has
less than 7 days left, and the endpoint list is refreshed hourly while online.
A station's `401 token_expired` causes one fresh mint and a retry, at most once
per 10 minutes per device (remembered in the store); `401 device_revoked` (the
device was revoked in the station app) is never answered with a new token.
`NewFileTokenStore(path)` writes the file with mode 0600 through an atomic
rename and refuses (`ErrInsecureTokenStore`) a file or directory not owned by
you or writable by group/others (POSIX); the default store is in memory. A token
is renewed once less than min(7 days, half its lifetime) is left. Call `client.Close()` to stop
background refreshes.

Timeouts: `ConnectTimeout` (3s, TLS included), `RequestTimeout` (15s),
`CloudTimeout` (10s: the cloud attempt in `cloud_first`, minting, refreshes),
`DiscoverTimeout` (1.5s). `Wait` (up to 30s) asks the station to answer once
the job printed or failed. Every call honours its `context.Context`; a
cancelled context never falls back.

### Local helpers

```go
st, err := client.Local.Status(ctx)          // printers, paper, unsynced jobs, offline allowance
stations, err := client.Local.Discover(ctx)  // endpoint list + mDNS, merged
info, err := client.Local.Info(ctx, url)     // GET /local/v1/info
job, err = client.Jobs.Get(ctx, "lj_…")       // local job IDs are read from the station (WaitFor works too)
err = client.Local.Refresh(ctx)              // renew token / endpoint list now
tok, err := client.Local.Token(ctx)          // the czl1 token, e.g. for a browser POS

// Pair a device with one station using the 8-digit code and the certificate
// fingerprint shown in the station app (or a station on the cloud endpoint
// list); the czd_ token works without any cloud account or API key.
p, err := client.Local.Pair(ctx, "https://192.168.1.20:7443", "12345678", "Till 3",
	catzprint.PairFingerprint("3f1a…"))

// A paired till needs no API key: local mode with the device token.
till, err := catzprint.NewClient(catzprint.WithLocal(catzprint.LocalConfig{
	Mode:         catzprint.ModeLocal,
	StationURLs:  []string{"https://192.168.1.20:7443"},
	Fingerprints: map[string]string{"192.168.1.20": "3f1a…"},
	Token:        p.Token,
}))
// (its cloud calls return an AuthenticationError with code missing_api_key)

lt, err := client.LocalTokens.Create(ctx, catzprint.LocalTokenParams{DeviceName: "Till 3", LocationIDs: []string{loc}, TTLDays: 30})
err = client.LocalTokens.Revoke(ctx, lt.TokenID)
eps, err := client.LocalEndpoints.List(ctx, loc)
```

See [`examples/local-hub`](examples/local-hub) for a complete hub.

## Sealed printing

Set `Sealed: true` to encrypt `Text` or `Content` on your machine to the
server's public key (NaCl sealed box, X25519 + XSalsa20-Poly1305) before it
leaves. The server key is fetched from `GET /v1/public/server-key` and cached
for an hour; if the API can't decrypt a job (the key was rotated), the SDK
fetches the key again and re-seals once. Commands and templates can't be sealed.

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
| `*PrinterError` | a station's printer is offline, out of paper, open or in error (503) |
| `*StationUnreachableError` | no station could be reached (`errors.Is(err, catzprint.ErrStationUnreachable)`) |
| `*OutcomeUnknownError` | a job was sent but the answer was lost and couldn't be confirmed (`errors.Is(err, catzprint.ErrOutcomeUnknown)`); retry later with the same key |
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
- [`examples/local-hub`](examples/local-hub): a restaurant hub that prints kitchen tickets offline (`local_first`)

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
