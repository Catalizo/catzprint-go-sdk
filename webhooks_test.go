package catzprint

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Vectors produced by the server's SignWebhook (core/webhooks.go), copied
// verbatim into a throwaway program and run once.
const (
	vecBody   = `{"type":"job.printed","created_at":"2026-10-16T12:00:00Z","org_id":"34c4671b-d2ab-4ddf-aaac-615786d5acac","data":{"job":{"id":"0b6f7c1e-8d1a-4c39-9a51-3f2b0f2c9e11","status":"printed","live":true}}}`
	vecSecret = "whsec_test_secret_123"
	vecHeader = "t=1760616000,v1=2cfe6182a082b4a1c36732c6669fc2f6e19ef00a3a83fa8b4d87d7901682e6fe"
	// Same body and time, signed with "whsec_other".
	vecOtherSig = "4bde8bfcb38c81b48d210705b74d58d2963b440f86488c3e56cc06737878d6a2"
)

var vecTime = time.Unix(1760616000, 0)

func clockAt(t time.Time) WebhookOption { return WithClock(func() time.Time { return t }) }

func TestWebhookValid(t *testing.T) {
	ev, err := VerifyWebhook([]byte(vecBody), vecHeader, vecSecret, clockAt(vecTime.Add(42*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != "job.printed" || ev.OrgID != "34c4671b-d2ab-4ddf-aaac-615786d5acac" || !ev.CreatedAt.Equal(time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("bad event %+v", ev)
	}
	j, err := ev.Job()
	if err != nil || j.ID != "0b6f7c1e-8d1a-4c39-9a51-3f2b0f2c9e11" || j.Status != StatusPrinted || !j.Live {
		t.Fatalf("bad job %+v %v", j, err)
	}
	// Aliases behave the same.
	if _, err := ConstructEvent([]byte(vecBody), vecHeader, vecSecret, clockAt(vecTime)); err != nil {
		t.Fatal(err)
	}
	var s WebhooksService
	if _, err := s.ConstructEvent([]byte(vecBody), vecHeader, vecSecret, clockAt(vecTime)); err != nil {
		t.Fatal(err)
	}
}

func TestSignWebhookMatchesServer(t *testing.T) {
	if got := SignWebhook(vecSecret, vecTime, []byte(vecBody)); got != vecHeader {
		t.Fatalf("SignWebhook = %s, want %s", got, vecHeader)
	}
}

func expectSigErr(t *testing.T, err error, reason string) {
	t.Helper()
	var se *SignatureVerificationError
	if !errors.As(err, &se) {
		t.Fatalf("want SignatureVerificationError, got %T %v", err, err)
	}
	if !strings.Contains(se.Reason, reason) {
		t.Fatalf("reason %q doesn't mention %q", se.Reason, reason)
	}
}

func TestWebhookTampered(t *testing.T) {
	tampered := strings.Replace(vecBody, `"live":true`, `"live":false`, 1)
	_, err := VerifyWebhook([]byte(tampered), vecHeader, vecSecret, clockAt(vecTime))
	expectSigErr(t, err, "no signature matches")
	// Tampered timestamp: the signature covers t too.
	_, err = VerifyWebhook([]byte(vecBody), strings.Replace(vecHeader, "t=1760616000", "t=1760616001", 1), vecSecret, clockAt(vecTime))
	expectSigErr(t, err, "no signature matches")
}

func TestWebhookExpired(t *testing.T) {
	_, err := VerifyWebhook([]byte(vecBody), vecHeader, vecSecret, clockAt(vecTime.Add(301*time.Second)))
	expectSigErr(t, err, "tolerance")
	_, err = VerifyWebhook([]byte(vecBody), vecHeader, vecSecret, clockAt(vecTime.Add(-301*time.Second)))
	expectSigErr(t, err, "tolerance")
	// A wider tolerance accepts it; zero disables the check.
	if _, err := VerifyWebhook([]byte(vecBody), vecHeader, vecSecret, clockAt(vecTime.Add(time.Hour)), WithTolerance(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWebhook([]byte(vecBody), vecHeader, vecSecret, clockAt(vecTime.Add(1000*time.Hour)), WithTolerance(0)); err != nil {
		t.Fatal(err)
	}
	// Real clock: this 2026 vector is long expired or not yet valid.
	_, err = VerifyWebhook([]byte(vecBody), vecHeader, vecSecret)
	if time.Since(vecTime).Abs() > DefaultWebhookTolerance {
		expectSigErr(t, err, "tolerance")
	}
}

func TestWebhookWrongSecret(t *testing.T) {
	_, err := VerifyWebhook([]byte(vecBody), vecHeader, "whsec_other", clockAt(vecTime))
	expectSigErr(t, err, "no signature matches")
	_, err = VerifyWebhook([]byte(vecBody), vecHeader, "", clockAt(vecTime))
	expectSigErr(t, err, "secret")
}

func TestWebhookMultipleSignatures(t *testing.T) {
	// During secret rotation a header may carry several v1 entries.
	h := "t=1760616000,v1=" + vecOtherSig + ",v1=" + strings.TrimPrefix(vecHeader, "t=1760616000,v1=")
	if _, err := VerifyWebhook([]byte(vecBody), h, vecSecret, clockAt(vecTime)); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWebhook([]byte(vecBody), h, "whsec_other", clockAt(vecTime)); err != nil {
		t.Fatal(err)
	}
	// Spaces and unknown schemes are tolerated.
	h2 := "t=1760616000, v0=deadbeef, v1=" + strings.TrimPrefix(vecHeader, "t=1760616000,v1=")
	if _, err := VerifyWebhook([]byte(vecBody), h2, vecSecret, clockAt(vecTime)); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookMalformedHeader(t *testing.T) {
	for h, reason := range map[string]string{
		"":                         "missing",
		"v1=abcd":                  "no timestamp",
		"t=abc,v1=abcd":            "invalid timestamp",
		"t=1760616000":             "no v1",
		"t=1760616000,v1=nothex!!": "no v1",
		"garbage":                  "no timestamp",
	} {
		_, err := VerifyWebhook([]byte(vecBody), h, vecSecret, clockAt(vecTime))
		expectSigErr(t, err, reason)
	}
}

func TestWebhookRoundTripWithFreshSignature(t *testing.T) {
	body := []byte(`{"type":"ping","created_at":"2026-10-16T12:00:00Z","org_id":"o","data":{"message":"Test event from CatzPrint"}}`)
	h := SignWebhook("s3cret", time.Now(), body)
	ev, err := VerifyWebhook(body, h, "s3cret")
	if err != nil || ev.Type != "ping" {
		t.Fatalf("%v %v", ev, err)
	}
	var d struct{ Message string }
	if err := ev.DecodeData(&d); err != nil || d.Message == "" {
		t.Fatalf("%v %v", d, err)
	}
	if j, err := ev.Job(); j != nil || err != nil {
		t.Fatalf("ping has no job: %v %v", j, err)
	}
}

func TestWebhookEventID(t *testing.T) {
	body := []byte(`{"id":"dlv_01HZX","type":"ping","created_at":"2026-10-17T00:00:00Z","org_id":"o","data":{}}`)
	ev, err := VerifyWebhook(body, SignWebhook("whsec_x", vecTime, body), "whsec_x", clockAt(vecTime))
	if err != nil || ev.ID != "dlv_01HZX" {
		t.Fatalf("id = %q, err = %v", ev.ID, err)
	}
	// Older payloads without an id still verify, with an empty ID.
	ev, err = VerifyWebhook([]byte(vecBody), vecHeader, vecSecret, clockAt(vecTime))
	if err != nil || ev.ID != "" {
		t.Fatalf("id = %q, err = %v", ev.ID, err)
	}
}
