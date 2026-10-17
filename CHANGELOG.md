# Changelog

## 2.1.3 — 2026-10-17

The module path is now `github.com/Catalizo/catzprint-go-sdk/v2` (Go requires the `/v2` suffix for versions 2 and later): `go get github.com/Catalizo/catzprint-go-sdk/v2` and update imports.

### Security

- The base URL must use `https://`; `http://` is accepted only for `localhost`, `127.0.0.1`, `::1` and `*.localhost`, so the API key is never sent in clear text.
- Redirects are never followed (unless you pass your own `http.Client` with a `CheckRedirect`), so the `Authorization` header only reaches the configured host.
- Response bodies are capped at 64 MiB; a larger answer is an error instead of being read into memory.
- Webhook verification hardened: an empty secret is rejected and every `v1` signature is compared in constant time.
- `WebhookEvent.ID`: the delivery id the server now includes in every signed event. Deduplicate on `event.ID`; the timestamp check limits the replay window to 5 minutes, it does not stop replays within it. Docs no longer say the timestamp check prevents replays.

## 1.0.0 — 2026-10-16

First release.

- `NewClient` with functional options (`WithAPIKey`, `WithBaseURL`, `WithOrgID`, `WithHTTPClient`, `WithTimeout`, `WithMaxRetries`, `WithBackoff`, `WithUserAgentSuffix`); reads `CATZPRINT_API_KEY` and `CATZPRINT_BASE_URL`.
- `Key` / `WhoAmI`, with the organization ID cached for later calls.
- Jobs: `Create`, `Get` (with events), `List`, `Iter` and `All` (auto-paging), `Cancel`, `Retry`, `Reprint`, `WaitFor`.
- Helpers: `PrintText`, `PrintPDF`, `PrintFile`, `PrintImage`, `PrintReceipt`, `PrintTemplate`.
- Sealed printing (NaCl sealed box to the server key, cached).
- `Printers.List`, `Locations.List`, `Locations.Get`, `Templates.List`.
- Webhooks: `VerifyWebhook`, `ConstructEvent`, `SignWebhook`.
- Typed errors for `errors.As`; retries with exponential backoff and jitter on network errors, 429 and 502/503/504; POSTs only retried with an idempotency key.
