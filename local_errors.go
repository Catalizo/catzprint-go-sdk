package catzprint

import (
	"errors"
	"fmt"
	"strings"
)

// ErrStationUnreachable is matched (with errors.Is) by every error that
// means no CatzPrint station on the local network could take the job: none
// answered, the TLS check failed, the request timed out, a station answered
// 502/504 or 503 local_disabled, or no local token could be obtained.
//
// The concrete error is a *StationUnreachableError listing what was tried.
var ErrStationUnreachable = errors.New("catzprint: no CatzPrint station could be reached")

// StationAttempt is one station URL the SDK tried and why it failed.
type StationAttempt struct {
	URL string
	Err error
}

// StationUnreachableError is returned when no station could take a request.
// errors.Is(err, ErrStationUnreachable) is true for it.
//
// In the fallback modes (local_first, cloud_first) CloudErr holds the cloud
// error when the cloud failed too; Unwrap returns it, so errors.As with
// *ConnectionError or *ServerError also sees the cloud failure.
type StationUnreachableError struct {
	Attempts []StationAttempt
	CloudErr error
}

// URLs returns the station URLs that were tried, in order.
func (e *StationUnreachableError) URLs() []string {
	out := make([]string, 0, len(e.Attempts))
	for _, a := range e.Attempts {
		if a.URL != "" {
			out = append(out, a.URL)
		}
	}
	return out
}

func (e *StationUnreachableError) Error() string {
	var b strings.Builder
	b.WriteString("catzprint: no CatzPrint station could be reached")
	if len(e.Attempts) == 0 {
		b.WriteString(" (no station address known: set StationURLs or Discover)")
	}
	for i, a := range e.Attempts {
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString("; ")
		}
		if a.URL != "" {
			b.WriteString(a.URL + ": ")
		}
		if a.Err != nil {
			b.WriteString(strings.TrimPrefix(a.Err.Error(), "catzprint: "))
		}
	}
	if e.CloudErr != nil {
		fmt.Fprintf(&b, "; cloud fallback failed too: %s", strings.TrimPrefix(e.CloudErr.Error(), "catzprint: "))
	}
	return b.String()
}

// Is makes errors.Is(err, ErrStationUnreachable) true.
func (e *StationUnreachableError) Is(target error) bool { return target == ErrStationUnreachable }

// Unwrap returns the cloud error of a failed fallback (or nil).
func (e *StationUnreachableError) Unwrap() error { return e.CloudErr }

func (e *StationUnreachableError) add(u string, err error) {
	e.Attempts = append(e.Attempts, StationAttempt{URL: u, Err: err})
}

func isPrinterCode(code string) bool {
	switch code {
	case "printer_offline", "out_of_paper", "cover_open", "printer_error":
		return true
	}
	return false
}

// ErrorCode returns the API error code of err ("" when err is not an API
// error), e.g. "printer_offline" or "offline_allowance_exhausted".
func ErrorCode(err error) string {
	var ou *OutcomeUnknownError
	if errors.As(err, &ou) {
		return ou.Code()
	}
	var api *APIError
	if errors.As(err, &api) {
		return api.Code
	}
	return ""
}

// IsPrinterOffline reports whether a station refused a job because the
// routed printer is offline.
func IsPrinterOffline(err error) bool { return ErrorCode(err) == "printer_offline" }

// IsOutOfPaper reports whether a station refused (or failed) a job because
// the printer is out of paper.
func IsOutOfPaper(err error) bool { return ErrorCode(err) == "out_of_paper" }

// IsCoverOpen reports whether the printer's cover is open.
func IsCoverOpen(err error) bool { return ErrorCode(err) == "cover_open" }

// IsOfflineAllowanceExhausted reports whether the station has been offline
// too long or has used its offline prints (402 offline_allowance_exhausted).
func IsOfflineAllowanceExhausted(err error) bool {
	return ErrorCode(err) == "offline_allowance_exhausted"
}

// IsStationUnreachable reports whether no station could be reached; same as
// errors.Is(err, ErrStationUnreachable).
func IsStationUnreachable(err error) bool { return errors.Is(err, ErrStationUnreachable) }

// ErrOutcomeUnknown is matched (with errors.Is) when a job was sent but no
// answer came back and the SDK couldn't find out whether it was accepted.
// The SDK then stops (no fallback), because sending it elsewhere could print
// it twice. Retrying later with the same idempotency key is always safe.
var ErrOutcomeUnknown = errors.New("catzprint: the outcome of this print is unknown")

// OutcomeUnknownError is returned when a station (or the cloud) may have
// accepted a job but its answer was lost. Code is "outcome_unknown".
type OutcomeUnknownError struct {
	// URL is the station URL (or the API base URL) that may have the job.
	URL string
	// IdempotencyKey is the key to retry with.
	IdempotencyKey string
	// Cause is the last error seen.
	Cause error
}

// Code is the stable error code, "outcome_unknown".
func (e *OutcomeUnknownError) Code() string { return "outcome_unknown" }

func (e *OutcomeUnknownError) Error() string {
	msg := "catzprint: The station may have printed this job. Retry later with the same idempotency key. (" + e.URL + ", idempotency key " + e.IdempotencyKey
	if e.Cause != nil {
		msg += ": " + strings.TrimPrefix(e.Cause.Error(), "catzprint: ")
	}
	return msg + ")"
}

// Is makes errors.Is(err, ErrOutcomeUnknown) true.
func (e *OutcomeUnknownError) Is(target error) bool { return target == ErrOutcomeUnknown }

// Unwrap returns the cause.
func (e *OutcomeUnknownError) Unwrap() error { return e.Cause }

// IsOutcomeUnknown reports whether err means the job may or may not have
// been accepted; same as errors.Is(err, ErrOutcomeUnknown).
func IsOutcomeUnknown(err error) bool { return errors.Is(err, ErrOutcomeUnknown) }
