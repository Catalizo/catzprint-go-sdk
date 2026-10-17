package catzprint

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// APIError is the base error for every non-2xx answer from the API. The
// kind-specific types below embed it, so errors.As(err, &apiErr) with an
// *APIError target matches all of them.
type APIError struct {
	// Status is the HTTP status code (0 for errors raised by the SDK itself).
	Status int
	// Code is the stable, machine-readable error code, e.g. "invalid".
	Code string
	// Message is plain English, safe to show to people.
	Message string
	// Fields maps each invalid request field to what's wrong with it.
	Fields map[string]string
	// RetryAfter is how long to wait before retrying (rate limits).
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "catzprint: %s", e.Message)
	if e.Status != 0 {
		fmt.Fprintf(&b, " (status %d, code %s)", e.Status, e.Code)
	} else if e.Code != "" {
		fmt.Fprintf(&b, " (code %s)", e.Code)
	}
	if len(e.Fields) > 0 {
		keys := make([]string, 0, len(e.Fields))
		for k := range e.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = k + ": " + e.Fields[k]
		}
		b.WriteString(" [" + strings.Join(parts, "; ") + "]")
	}
	return b.String()
}

// AuthenticationError is a 401: the key is missing, wrong, revoked or expired.
type AuthenticationError struct{ *APIError }

// PermissionError is a 403: the key's scopes or mode don't allow this.
type PermissionError struct{ *APIError }

// NotFoundError is a 404.
type NotFoundError struct{ *APIError }

// ValidationError is a 400 or 422; Fields says what to fix.
type ValidationError struct{ *APIError }

// OutOfPrintsError is a 402 (code out_of_prints): the organization has used
// its prints.
type OutOfPrintsError struct{ *APIError }

// RateLimitError is a 429; RetryAfter says how long to wait.
type RateLimitError struct{ *APIError }

// ConflictError is a 409, e.g. cancelling a job that already printed.
type ConflictError struct{ *APIError }

// ServerError is a 5xx.
type ServerError struct{ *APIError }

func (e *AuthenticationError) Unwrap() error { return e.APIError }
func (e *PermissionError) Unwrap() error     { return e.APIError }
func (e *NotFoundError) Unwrap() error       { return e.APIError }
func (e *ValidationError) Unwrap() error     { return e.APIError }
func (e *OutOfPrintsError) Unwrap() error    { return e.APIError }
func (e *RateLimitError) Unwrap() error      { return e.APIError }
func (e *ConflictError) Unwrap() error       { return e.APIError }
func (e *ServerError) Unwrap() error         { return e.APIError }

// typed wraps the error in its kind-specific type.
func (e *APIError) typed() error {
	switch {
	case e.Status == http.StatusPaymentRequired || e.Code == "out_of_prints":
		return &OutOfPrintsError{e}
	case e.Status == http.StatusUnauthorized:
		return &AuthenticationError{e}
	case e.Status == http.StatusForbidden:
		return &PermissionError{e}
	case e.Status == http.StatusNotFound:
		return &NotFoundError{e}
	case e.Status == http.StatusBadRequest || e.Status == http.StatusUnprocessableEntity:
		return &ValidationError{e}
	case e.Status == http.StatusConflict:
		return &ConflictError{e}
	case e.Status == http.StatusTooManyRequests:
		return &RateLimitError{e}
	case e.Status >= 500:
		return &ServerError{e}
	}
	return e
}

// ConnectionError is a network failure or timeout before an API answer
// arrived. It unwraps to the cause (e.g. context.DeadlineExceeded).
type ConnectionError struct{ Err error }

func (e *ConnectionError) Error() string { return "catzprint: connection failed: " + e.Err.Error() }
func (e *ConnectionError) Unwrap() error { return e.Err }

// TimeoutError is returned by Jobs.WaitFor when the job doesn't finish in time.
type TimeoutError struct {
	JobID string
	// Job is the last state seen (may be nil if no poll succeeded).
	Job     *Job
	Timeout time.Duration
}

func (e *TimeoutError) Error() string {
	st := "unknown"
	if e.Job != nil {
		st = e.Job.Status
	}
	return fmt.Sprintf("catzprint: job %s didn't finish within %s (last status %s)", e.JobID, e.Timeout, st)
}

// SignatureVerificationError means a webhook payload failed verification.
type SignatureVerificationError struct{ Reason string }

func (e *SignatureVerificationError) Error() string {
	return "catzprint: webhook signature verification failed: " + e.Reason
}

func invalidParams(field, msg string) error {
	return &ValidationError{&APIError{Code: "invalid", Message: msg, Fields: map[string]string{field: msg}}}
}
