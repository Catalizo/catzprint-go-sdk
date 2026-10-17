package catzprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader is the HTTP header that carries a webhook's signature.
const SignatureHeader = "CatzPrint-Signature"

// DeliveryHeader carries the unique ID of a webhook delivery.
const DeliveryHeader = "CatzPrint-Delivery"

// DefaultWebhookTolerance is the largest accepted clock difference between
// the signature time and now.
const DefaultWebhookTolerance = 300 * time.Second

// WebhookEvent is a verified webhook payload.
type WebhookEvent struct {
	// ID is the delivery id. It is the same for every retry of one
	// delivery, so use it to deduplicate: the timestamp check only limits
	// the replay window to the tolerance (5 minutes by default), it does not
	// stop a captured delivery from being replayed inside that window.
	// Empty when the server did not send one.
	ID string `json:"id,omitempty"`
	// Type is job.created, job.printed, job.failed, job.cancelled,
	// job.retried, station.online, station.offline, printer.status or ping.
	Type      string          `json:"type"`
	CreatedAt time.Time       `json:"created_at"`
	OrgID     string          `json:"org_id"`
	Data      json.RawMessage `json:"data"`
}

// Job decodes data.job for job.* events. It returns nil when the event
// carries no job.
func (e *WebhookEvent) Job() (*Job, error) {
	var d struct {
		Job *Job `json:"job"`
	}
	if len(e.Data) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return nil, err
	}
	return d.Job, nil
}

// DecodeData decodes the event's data object into v.
func (e *WebhookEvent) DecodeData(v any) error { return json.Unmarshal(e.Data, v) }

type webhookConfig struct {
	tolerance time.Duration
	now       func() time.Time
}

// WebhookOption configures webhook verification.
type WebhookOption func(*webhookConfig)

// WithTolerance sets the accepted clock difference (default 300s). Zero or
// negative turns the timestamp check off (not recommended).
func WithTolerance(d time.Duration) WebhookOption { return func(w *webhookConfig) { w.tolerance = d } }

// WithClock sets the time source used for the tolerance check (for tests).
func WithClock(now func() time.Time) WebhookOption { return func(w *webhookConfig) { w.now = now } }

// WebhooksService verifies webhook signatures. Use it via Client.Webhooks,
// or call VerifyWebhook directly (no client needed).
type WebhooksService struct{}

// Verify checks the signature and returns the parsed event.
func (*WebhooksService) Verify(payload []byte, signatureHeader, secret string, opts ...WebhookOption) (*WebhookEvent, error) {
	return VerifyWebhook(payload, signatureHeader, secret, opts...)
}

// ConstructEvent is an alias for Verify.
func (*WebhooksService) ConstructEvent(payload []byte, signatureHeader, secret string, opts ...WebhookOption) (*WebhookEvent, error) {
	return VerifyWebhook(payload, signatureHeader, secret, opts...)
}

// ConstructEvent is an alias for VerifyWebhook.
func ConstructEvent(payload []byte, signatureHeader, secret string, opts ...WebhookOption) (*WebhookEvent, error) {
	return VerifyWebhook(payload, signatureHeader, secret, opts...)
}

// VerifyWebhook checks a webhook's CatzPrint-Signature header
// ("t=<unix>,v1=<hex>[,v1=<hex>…]") against the raw request body and your
// endpoint secret, then parses the event. Pass the body exactly as
// received. It returns a *SignatureVerificationError on any mismatch.
func VerifyWebhook(payload []byte, signatureHeader, secret string, opts ...WebhookOption) (*WebhookEvent, error) {
	cfg := webhookConfig{tolerance: DefaultWebhookTolerance, now: time.Now}
	for _, o := range opts {
		o(&cfg)
	}
	if secret == "" {
		return nil, &SignatureVerificationError{Reason: "no webhook secret given"}
	}
	if strings.TrimSpace(signatureHeader) == "" {
		return nil, &SignatureVerificationError{Reason: "missing " + SignatureHeader + " header"}
	}
	var ts string
	var sigs [][]byte
	for _, part := range strings.Split(signatureHeader, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			if b, err := hex.DecodeString(v); err == nil {
				sigs = append(sigs, b)
			}
		}
	}
	if ts == "" {
		return nil, &SignatureVerificationError{Reason: "no timestamp in header"}
	}
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, &SignatureVerificationError{Reason: "invalid timestamp in header"}
	}
	if len(sigs) == 0 {
		return nil, &SignatureVerificationError{Reason: "no v1 signature in header"}
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "."))
	mac.Write(payload)
	want := mac.Sum(nil)
	matched := false
	for _, s := range sigs {
		if hmac.Equal(s, want) {
			matched = true
		}
	}
	if !matched {
		return nil, &SignatureVerificationError{Reason: "no signature matches the payload"}
	}
	if cfg.tolerance > 0 {
		diff := cfg.now().Sub(time.Unix(unix, 0))
		if diff < 0 {
			diff = -diff
		}
		if diff > cfg.tolerance {
			return nil, &SignatureVerificationError{Reason: "timestamp outside the tolerance"}
		}
	}
	var ev WebhookEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return nil, &SignatureVerificationError{Reason: "payload isn't valid JSON"}
	}
	return &ev, nil
}

// SignWebhook produces a CatzPrint-Signature header value for body, exactly
// as the server does. Use it to test your webhook handler.
func SignWebhook(secret string, ts time.Time, body []byte) string {
	t := strconv.FormatInt(ts.Unix(), 10)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(t + "."))
	m.Write(body)
	return "t=" + t + ",v1=" + hex.EncodeToString(m.Sum(nil))
}
