# Changelog

## 2.2.1 — 2026-11-07

Security audit round 7 (no API changes).

- A cloud `400`/`422` naming `sealed_content` (the server key was rotated) is no longer final: the SDK drops the cached server key, fetches it again, re-seals and re-sends **once** with the same idempotency key. After an ambiguous attempt (an answer lost, a retry in flight, a `409 duplicate`), a failed key fetch, or a re-send that is rejected again, not delivered or ambiguous, is `OutcomeUnknown` — never a validation error, never local. Without one, a repeated rejection is returned as the validation error.
- The server key is cached for at most an hour (and dropped at once on a `sealed_content` rejection).
- A station that answered the job request `409 in_progress` and then `404 not_found` to the probe by key is `OutcomeUnknown` (no next station, no cloud): the 404 only means "never recorded" when the request itself wasn't answered `in_progress`.
- Stored token placeholders are recognised by the same set in every SDK: `…`, a run of 3+ `*`, `[redacted]`, `redacted`, `hidden` (any case), optionally after `czl1.` or `czd_`. `LocalService.StoreError()` is cleared once a fresh token was minted and stored.
- A cloud `3xx` has the error code `unexpected_redirect` (was `http_3xx`).
- Once any answer for the key said `409 in_progress` (the job request or a probe by key), a later probe `404 not_found` is `OutcomeUnknown` (no next station, no cloud).
- A server-key fetch that was already in flight when a `sealed_content` rejection dropped the key no longer re-installs the dropped key.

## 2.2.0 — 2026-11-07

Local printing: print through the CatzPrint desktop station on the same network when the internet is down.

- `WithLocal(LocalConfig{…})` with modes `ModeCloud` (default, unchanged), `ModeLocal`, `ModeLocalFirst` and `ModeCloudFirst`. `local_first` falls back to the cloud only when no station can be reached (connect/TLS/timeout, 502/504, 503 `local_disabled`); `cloud_first` falls back to the stations on a network error, timeout or 5xx. Printer errors, `no_printer`, validation errors and `402 offline_allowance_exhausted` are always returned, never retried elsewhere.
- Fallback modes always send an idempotency key (`sdk-<uuid v4>` when you don't set one) and use the same key for the station and the cloud.
- Local tokens are minted, cached in a `TokenStore` (`NewFileTokenStore`: mode 0600, atomic writes; `NewMemoryTokenStore`), renewed when less than 7 days are left and re-minted once on a `401`. The station endpoint list is cached with the token and refreshed hourly while online.
- Discovery: configured `StationURLs`, the cloud endpoint list and mDNS (`_catzprint._tcp`, via `golang.org/x/net`).
- TLS: public-certificate hostnames are verified normally (and reached without DNS); IP and self-signed stations only with a pinned SHA-256 fingerprint from the endpoint list, mDNS or `LocalConfig.Fingerprints`. Never trust-on-first-use. mDNS announcements of stations missing from a known endpoint list are ignored.
- `Client.Local`: `Status`, `Discover`, `Info`, `Pair`, `GetJob`, `Refresh`, `Token`; `Client.LocalTokens.Create/Revoke`; `Client.LocalEndpoints.List`. `Jobs.Get`/`WaitFor` read local job IDs (`lj_…`) from the station. `Client.Close` stops background refreshes.
- `Job.Via`, `Job.PrintedLocally`, `Job.LocalDevice`, `Job.DuplicateOf`, `Job.Offline`, `Job.IdempotencyKey`, `Job.Local`.
- Errors: `ErrStationUnreachable` and `*StationUnreachableError` (tried URLs, the cloud error of a failed fallback), `*PrinterError`, `*PinMismatchError`, helpers `IsStationUnreachable`, `IsPrinterOffline`, `IsOutOfPaper`, `IsCoverOpen`, `IsOfflineAllowanceExhausted`, `ErrorCode`. API errors with a `param` fill `Fields`.
- New example: `examples/local-hub`.
- `golang.org/x/net` v0.61.0 is a new dependency.

Security hardening before release (review findings H4, M6, M7, M8; spec addendum A10–A12, A15):

- Public hostnames are built only from the cloud endpoint list, never from mDNS, and besides normal verification the certificate's public key must match the list's `public_spki_sha256`. Direct connection to the IP in a `a-b-c-d.<label>.<zone>` name only under that station's own label.
- mDNS only maps a station ID to its address for stations on the cloud list (pinned with the list's fingerprint) or with a fingerprint in `LocalConfig.Fingerprints`; an announcement alone is never trusted. Public IPs from the list or mDNS are ignored.
- Minted tokens are bound to `LocalConfig.LocationID`, now required in local modes unless `AllLocations: true` (or a static `Token`).
- Re-mint only on `401 token_expired`, at most once per 10 minutes per store key (`StoredToken.LastRemintAt`); never on `device_revoked`.
- `Local.Pair` requires the fingerprint from the station app (`PairFingerprint(fp)` option, or `Fingerprints`) or a station on the cloud endpoint list; mDNS is not enough.
- `LocalJob.Live` maps to `Job.Live`; paired-device jobs are live.
- A paired device in `ModeLocal` with a static `Token` can be built without an API key; its cloud calls return `missing_api_key`.
- `LocalEndpoint` gains `PublicSPKISHA256` and `LocalLabel`; `PinMismatchError.SPKI`; `LocalStation.Hostname` removed.

Audit round 4 (SDK addendum 2):

- SDK-1: never double-print on an ambiguous outcome. Requests are classified as not delivered (DNS/dial/TLS/pin, or 502/504/503 `local_disabled`) or sent-without-answer (written, then timeout/reset/body error/oversized/redirect; tracked with `httptrace.WroteRequest`). A lost station answer is checked on the same station with `GET /local/v1/jobs?idempotency_key=` (3 tries within 5 s, fresh connections); unresolved → `*OutcomeUnknownError` (`ErrOutcomeUnknown`, `IsOutcomeUnknown`, code `outcome_unknown`) and no fallback. The cloud leg of the fallback modes makes one attempt and retries once with the same key after an ambiguous answer or a 500; ambiguous twice → `OutcomeUnknownError`, never a station.
- SDK-2: a blank idempotency key counts as none (`sdk-<uuid>` / a UUID in cloud mode); keys with leading/trailing whitespace or control characters are refused (`ValidationError`).
- SDK-3: sealing refuses small-order X25519 keys (`curve25519.X25519`), also when fetched as the server key.
- SDK-4: `LocalConfig`, `StoredToken`, `LocalToken` and `LocalPairing` redact tokens in `%v`, `%+v`, `%s` and `%#v`.
- SDK-5: an oversized station answer is never a reason to try another station.
- SDK-6: tokens are renewed when less than min(7 days, TTL/2) is left (`StoredToken.IssuedAt`).
- SDK-8: `FileTokenStore` refuses (`ErrInsecureTokenStore`) a file or directory not owned by the current user or group/world-writable (POSIX); local printing then fails instead of using it.
- SDK-9: the mDNS collector keeps at most 256 stations/hosts and 32 addresses per host.

Audit round 5 (SDK addendum 3):

- R1: an `OutcomeUnknownError` from the cloud leg is never treated as "not delivered": `cloud_first` doesn't go to a station after it, and `local_first` returns it as is.
- R3: a probe answered `409 duplicate` returns that `*ConflictError` (no fallback); only `404 not_found` counts as "never recorded".
- R4: a cloud `409 duplicate`/"being created" (in any create, cloud mode included) is re-sent identically up to 3 times, 1 s apart; still 409 → that conflict is returned; a re-send not delivered or ambiguous → `OutcomeUnknownError`.
- R7: `LocalConfig`, `StoredToken`, `LocalToken`, `LocalPairing` implement `fmt.Formatter` (every verb) and `slog.LogValuer`, redacted; `EncodeStoredToken` / `DecodeStoredToken` helpers. (JSON redaction of tokens was reverted in round 6, Q2: only `LocalConfig` JSON is redacted.)
- C1–C6: a cloud 4xx in `local_first` is returned unwrapped; any 5xx but 502/503/504 is ambiguous; failures before the job POST (org lookup) count as not delivered; the token store owner check uses the effective uid; a 2xx without a usable job is ambiguous (probe / retry); cancellation after the request was written → `OutcomeUnknownError` wrapping it.

Audit round 6 (SDK addendum 4):

- Q1: a station `409 in_progress` (on the job request or a probe) is waited for by probing within the budget; it never causes a fallback; unresolved → `OutcomeUnknownError`.
- Q2: **JSON keeps tokens again** for `StoredToken`, `LocalToken` and `LocalPairing` (results you persist or hand to a browser till); redaction stays in `String`/`Format`/`GoString`/`LogValue`. `LocalConfig` JSON stays redacted. A stored token that is a redaction placeholder is treated as "no token" (`Local.StoreError`). `EncodeStoredToken`/`DecodeStoredToken` remain as helpers.
- Q3: the cloud request is built and sealed once per create; the ambiguous retry and the 409 re-sends send the exact same bytes.
- Q4: jobs that can't print locally (sealed, PDF/image/document, scheduled) use the cloud-mode create (409 loop included) in `local_first` and `cloud_first`.
- Q6: a failed server-key fetch for sealing (before the job request) counts as not delivered.

## 2.1.4 — 2026-10-20

- Docs only: the README explains that printer names aren't unique across stations, how to target printers by ID, and the console's copy-ID shortcut. The README now states Go 1.26+.

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
