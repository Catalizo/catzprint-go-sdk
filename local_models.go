package catzprint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// Where a job was sent (Job.Via).
const (
	ViaCloud = "cloud"
	ViaLocal = "local"
)

// LocalEndpoint is one station's local-network address as the cloud knows
// it (GET /v1/orgs/{org}/local-endpoints and the local-tokens response).
type LocalEndpoint struct {
	StationID    string `json:"station_id"`
	Name         string `json:"name"`
	LocationID   string `json:"location_id"`
	Connected    bool   `json:"connected"`
	LocalEnabled bool   `json:"local_enabled"`
	Port         int    `json:"port"`
	// Addresses are the station's private IPv4 addresses.
	Addresses []string `json:"addresses"`
	// URLs lists public-certificate hostnames first, then raw IP URLs.
	URLs []string `json:"urls"`
	// TLSMode is "public" (a publicly trusted certificate for the
	// hostnames) or "self_signed".
	TLSMode string `json:"tls_mode"`
	// CertFingerprintSHA256 is the hex SHA-256 of the station's certificate
	// (DER). The SDK pins it for IP and self-signed URLs.
	CertFingerprintSHA256 string `json:"cert_fingerprint_sha256"`
	// PublicSPKISHA256 is the hex SHA-256 of the public certificate's
	// SubjectPublicKeyInfo (when the station has one); pinned for hostnames.
	PublicSPKISHA256 string `json:"public_spki_sha256"`
	// LocalLabel is the station's label in "<a-b-c-d>.<label>.<zone>".
	LocalLabel string    `json:"local_label"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// LocalTokenParams are the settings for LocalTokens.Create.
type LocalTokenParams struct {
	// DeviceName identifies the device on the station (up to 80 characters).
	DeviceName string
	// LocationIDs narrows the token to these locations (default: every
	// location the API key may use).
	LocationIDs []string
	// TTLDays is the lifetime, 1..30 (default 30).
	TTLDays int
}

// LocalToken is a minted local token ("czl1…") that stations verify
// offline.
type LocalToken struct {
	Token     string          `json:"token"`
	TokenID   string          `json:"token_id"`
	ExpiresAt time.Time       `json:"expires_at"`
	Stations  []LocalEndpoint `json:"stations"`
}

// LocalJob is a job as a station's local API reports it.
type LocalJob struct {
	ID             string     `json:"id"`
	IdempotencyKey string     `json:"idempotency_key"`
	Status         string     `json:"status"` // queued, printing, printed, failed
	ErrorCode      string     `json:"error_code,omitempty"`
	Detail         string     `json:"detail"`
	PrinterID      string     `json:"printer_id"`
	PrinterName    string     `json:"printer_name"`
	Role           string     `json:"role"`
	LocationID     string     `json:"location_id"`
	Copies         int        `json:"copies"`
	Title          string     `json:"title"`
	Reference      string     `json:"reference"`
	CreatedAt      time.Time  `json:"created_at"`
	FinishedAt     *time.Time `json:"finished_at"`
	PrintedLocally bool       `json:"printed_locally"`
	Via            string     `json:"via"`
	CloudJobID     *string    `json:"cloud_job_id"`
	// Live is false for jobs sent with a test-mode token (nil when the
	// station didn't say).
	Live *bool `json:"live,omitempty"`

	// StationURL is the station URL that answered (set by the SDK).
	StationURL string `json:"-"`
}

// UnmarshalJSON accepts "" for the timestamps.
func (j *LocalJob) UnmarshalJSON(b []byte) error {
	type alias LocalJob
	return json.Unmarshal(nullEmpty(b, "created_at", "finished_at"), (*alias)(j))
}

// LocalStatus is a station's GET /local/v1/status answer.
type LocalStatus struct {
	Station     LocalStationState    `json:"station"`
	Printers    []LocalPrinterStatus `json:"printers"`
	JobsWaiting int                  `json:"jobs_waiting"`
	// Unsynced is how many local jobs the station still has to report to
	// the cloud.
	Unsynced  int            `json:"unsynced"`
	Allowance LocalAllowance `json:"allowance"`

	// StationURL is the station URL that answered (set by the SDK).
	StationURL string `json:"-"`
}

// LocalStationState describes the station in LocalStatus.
type LocalStationState struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	CloudConnected   bool       `json:"cloud_connected"`
	LastCloudContact *time.Time `json:"last_cloud_contact"`
	Version          string     `json:"version"`
	LocalEnabled     bool       `json:"local_enabled"`
}

// UnmarshalJSON accepts "" for the timestamp.
func (s *LocalStationState) UnmarshalJSON(b []byte) error {
	type alias LocalStationState
	return json.Unmarshal(nullEmpty(b, "last_cloud_contact"), (*alias)(s))
}

// LocalPrinterStatus is one printer in LocalStatus.
type LocalPrinterStatus struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
	// Status is ready, offline, paper_out, paper_low, cover_open, error,
	// busy or unknown.
	Status      string `json:"status"`
	Paper       string `json:"paper"` // ok, low, out, unknown
	JobsWaiting int    `json:"jobs_waiting"`
}

// LocalAllowance is what the station may still print without the cloud.
type LocalAllowance struct {
	ExpiresAt  *time.Time `json:"expires_at"`
	PrintsLeft int        `json:"prints_left"`
}

// UnmarshalJSON accepts "" for the timestamp.
func (a *LocalAllowance) UnmarshalJSON(b []byte) error {
	type alias LocalAllowance
	return json.Unmarshal(nullEmpty(b, "expires_at"), (*alias)(a))
}

// LocalInfo is a station's unauthenticated GET /local/v1/info answer.
type LocalInfo struct {
	StationID             string     `json:"station_id"`
	Name                  string     `json:"name"`
	OrgID                 string     `json:"org_id"`
	LocationID            string     `json:"location_id"`
	Version               string     `json:"version"`
	Port                  int        `json:"port"`
	TLSMode               string     `json:"tls_mode"`
	CertFingerprintSHA256 string     `json:"cert_fingerprint_sha256"`
	Hostnames             []string   `json:"hostnames"`
	Addresses             []string   `json:"addresses"`
	PairingOpen           bool       `json:"pairing_open"`
	Time                  *time.Time `json:"time"`
}

// UnmarshalJSON accepts "" for the timestamp.
func (i *LocalInfo) UnmarshalJSON(b []byte) error {
	type alias LocalInfo
	return json.Unmarshal(nullEmpty(b, "time"), (*alias)(i))
}

// LocalPairing is the result of Local.Pair: a device token ("czd_…") for
// that one station. Pass it as LocalConfig.Token.
type LocalPairing struct {
	DeviceID   string `json:"device_id"`
	Token      string `json:"token"`
	StationID  string `json:"station_id"`
	OrgID      string `json:"org_id"`
	LocationID string `json:"location_id"`
}

// LocalStation is a station found by Local.Discover.
type LocalStation struct {
	StationID  string
	Name       string
	OrgID      string
	LocationID string
	Port       int
	Addresses  []string
	// URLs are the URLs the SDK would use, in order.
	URLs        []string
	TLSMode     string
	Fingerprint string
	// FromCloud is true when the station is in the cloud's endpoint list
	// (authenticated); FromMDNS when it answered on the local network.
	FromCloud bool
	FromMDNS  bool
	// LocalEnabled and Connected come from the cloud endpoint list.
	LocalEnabled bool
	Connected    bool
}

// nullEmpty rewrites "" values of the given top-level keys to null so they
// decode into time fields. Malformed input is returned unchanged.
func nullEmpty(b []byte, keys ...string) []byte {
	if !bytes.Contains(b, []byte(`""`)) {
		return b
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return b
	}
	changed := false
	for _, k := range keys {
		if v, ok := m[k]; ok && string(bytes.TrimSpace(v)) == `""` {
			m[k] = json.RawMessage("null")
			changed = true
		}
	}
	if !changed {
		return b
	}
	out, err := json.Marshal(m)
	if err != nil {
		return b
	}
	return out
}

// isRedactedToken reports whether t is a redaction placeholder rather than
// a token: "…", a run of 3+ "*", "[redacted]", "redacted" or "hidden"
// (any case), optionally after a "czl1." or "czd_" prefix. The same set is
// recognised by every CatzPrint SDK.
func isRedactedToken(t string) bool {
	rest := strings.TrimPrefix(strings.TrimPrefix(t, "czl1."), "czd_")
	switch strings.ToLower(rest) {
	case "…", "[redacted]", "redacted", "hidden":
		return true
	}
	return len(rest) >= 3 && strings.Trim(rest, "*") == ""
}

// redactToken keeps only a token's type prefix.
func redactToken(t string) string {
	switch {
	case t == "":
		return ""
	case strings.HasPrefix(t, "czl1."):
		return "czl1.…"
	case strings.HasPrefix(t, "czd_"):
		return "czd_…"
	}
	return "…"
}

// String never reveals the token (also used by %v and %+v).
func (t LocalToken) String() string {
	return fmt.Sprintf("catzprint.LocalToken{Token: %q, TokenID: %q, ExpiresAt: %s, Stations: %d}", redactToken(t.Token), t.TokenID, t.ExpiresAt.Format(time.RFC3339), len(t.Stations))
}

// GoString never reveals the token (%#v).
func (t LocalToken) GoString() string { return t.String() }

// Format prints the redacted form for every verb.
func (t LocalToken) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, t.String()) }

// LogValue keeps the token out of log/slog output.
func (t LocalToken) LogValue() slog.Value { return slog.StringValue(t.String()) }

// String never reveals the token (also used by %v and %+v).
func (p LocalPairing) String() string {
	return fmt.Sprintf("catzprint.LocalPairing{DeviceID: %q, Token: %q, StationID: %q, OrgID: %q, LocationID: %q}", p.DeviceID, redactToken(p.Token), p.StationID, p.OrgID, p.LocationID)
}

// GoString never reveals the token (%#v).
func (p LocalPairing) GoString() string { return p.String() }

// Format prints the redacted form for every verb.
func (p LocalPairing) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }

// LogValue keeps the token out of log/slog output.
func (p LocalPairing) LogValue() slog.Value { return slog.StringValue(p.String()) }
