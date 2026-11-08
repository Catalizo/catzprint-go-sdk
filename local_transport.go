package catzprint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// stationTarget is one URL to try, with how to trust it.
type stationTarget struct {
	URL         string // https://host:port, no trailing slash
	Fingerprint string // lower-case hex SHA-256 of the certificate DER, or ""
	TLSMode     string // public, self_signed or "" (unknown)
	StationID   string
	Source      string // config, cloud, mdns
	// SPKI is the hex SHA-256 of the public certificate's
	// SubjectPublicKeyInfo, pinned on top of normal verification for public
	// hostnames (from the cloud endpoint list).
	SPKI string
	// Label is the station's local label: a dashed-IP hostname is dialled
	// directly only under it ("<a-b-c-d>.<label>.<zone>").
	Label string
}

// needsPin says whether the URL can only be trusted by fingerprint: raw IP
// addresses, mDNS .local names and stations known to be self-signed. Public
// hostnames are verified with the system roots like any website.
func (t stationTarget) needsPin() bool {
	u, err := url.Parse(t.URL)
	if err != nil {
		return true
	}
	h := strings.ToLower(u.Hostname())
	return net.ParseIP(h) != nil || strings.HasSuffix(h, ".local") || t.TLSMode == "self_signed"
}

// errNoPin: an IP or self-signed URL with no fingerprint from the endpoint
// list, mDNS or LocalConfig.Fingerprints. Never trusted on first use.
var errNoPin = errors.New("catzprint: no pinned certificate fingerprint for this address (IP and self-signed stations are only trusted with the fingerprint from the cloud endpoint list, mDNS or LocalConfig.Fingerprints)")

// PinMismatchError means a station presented a certificate whose SHA-256
// fingerprint isn't the pinned one.
type PinMismatchError struct {
	Want, Got string
	// SPKI is true when the public-key pin of a public hostname failed.
	SPKI bool
}

func (e *PinMismatchError) Error() string {
	what := "certificate fingerprint"
	if e.SPKI {
		what = "public key (SPKI) fingerprint"
	}
	return fmt.Sprintf("catzprint: station %s %s doesn't match the pinned %s", what, e.Got, e.Want)
}

// normalizeFingerprint accepts hex with optional colons/spaces and returns
// lower-case hex, or "" when it isn't 32 bytes of hex.
func normalizeFingerprint(fp string) string {
	fp = strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(fp)))
	if len(fp) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return ""
	}
	return fp
}

// dashedIP decodes the station hostname scheme "<a>-<b>-<c>-<d>.<label>.<zone>"
// to the private (or loopback) IPv4 it names, so the SDK can connect while
// public DNS is unreachable. Only names under the given station label are
// mapped (the label comes from the cloud endpoint list), and the
// certificate is still verified for the hostname and its public key pinned.
func dashedIP(host, label string) net.IP {
	labels := strings.Split(host, ".")
	if len(labels) < 3 || label == "" || labels[1] != label {
		return nil
	}
	parts := strings.Split(labels[0], "-")
	if len(parts) != 4 {
		return nil
	}
	ip := net.ParseIP(strings.Join(parts, ".")).To4()
	if ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
		return nil
	}
	return ip
}

// stationHTTPClient returns a cached client for the target's trust settings.
func (l *localState) stationHTTPClient(t stationTarget) (*http.Client, error) {
	pin := ""
	if t.needsPin() {
		if t.Fingerprint == "" {
			return nil, errNoPin
		}
		pin = t.Fingerprint
	}
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, err
	}
	key := strings.ToLower(u.Host) + "|" + pin + "|" + t.SPKI + "|" + t.Label
	l.mu.Lock()
	defer l.mu.Unlock()
	if hc, ok := l.clients[key]; ok {
		return hc, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: l.cfg.RootCAs}
	if pin != "" {
		want, _ := hex.DecodeString(pin)
		// The chain isn't checked against CAs; instead the leaf
		// certificate must be exactly the pinned one.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("catzprint: the station sent no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return &PinMismatchError{Want: pin, Got: hex.EncodeToString(got[:])}
			}
			return nil
		}
	}
	if pin == "" && t.SPKI != "" {
		want, _ := hex.DecodeString(t.SPKI)
		// Runs after normal verification: the public key must also be the
		// one the cloud says this station has.
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("catzprint: the station sent no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return &PinMismatchError{Want: t.SPKI, Got: hex.EncodeToString(got[:]), SPKI: true}
			}
			return nil
		}
	}
	label := t.Label
	dialer := &net.Dialer{Timeout: l.cfg.ConnectTimeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy: nil, // stations are on the LAN: never through a proxy
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err == nil && net.ParseIP(host) == nil && label != "" {
				if ip := dashedIP(strings.ToLower(host), label); ip != nil {
					addr = net.JoinHostPort(ip.String(), port)
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   l.cfg.ConnectTimeout,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       60 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	hc := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if l.clients == nil {
		l.clients = map[string]*http.Client{}
	}
	l.clients[key] = hc
	return hc, nil
}

func (l *localState) closeIdle() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, hc := range l.clients {
		hc.CloseIdleConnections()
	}
}

const maxLocalResponseBytes = 4 << 20

// outcome classifies one request (spec SDK addendum 2, SDK-1).
type outcome int

const (
	outOK           outcome = iota // 2xx, decoded
	outAnswered                    // an answer to return (or ctx ended)
	outNotDelivered                // never reached the station, or the station refused it (502/504, 503 local_disabled)
	outNoAnswer                    // fully sent, then no usable answer: the station may have it
)

// send makes one request to a station and reports unreachable for both
// "not delivered" and "no answer" (safe for reads and pairing).
func (l *localState) send(ctx context.Context, t stationTarget, method, path string, q url.Values, token string, body, out any, extra time.Duration) (unreachable bool, err error) {
	k, err := l.sendX(ctx, t, method, path, q, token, body, out, extra, false)
	if k == outNoAnswer && ErrorCode(err) == "response_too_large" {
		return false, err // an answer, just too big: don't try another station
	}
	return k == outNotDelivered || k == outNoAnswer, err
}

// sendX makes one request to a station and classifies it. When ctx itself
// ends, the error is a *ConnectionError wrapping ctx.Err() (outAnswered).
// fresh forces a new connection (used when probing after a lost answer).
func (l *localState) sendX(ctx context.Context, t stationTarget, method, path string, q url.Values, token string, body, out any, extra time.Duration, fresh bool) (outcome, error) {
	hc, err := l.stationHTTPClient(t)
	if err != nil {
		return outNotDelivered, err
	}
	var payload []byte
	if body != nil {
		if payload, err = json.Marshal(body); err != nil {
			return outAnswered, fmt.Errorf("catzprint: encoding request: %w", err)
		}
	}
	u := t.URL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	rctx, cancel := context.WithTimeout(ctx, l.cfg.RequestTimeout+extra)
	defer cancel()
	var wrote atomic.Bool
	rctx = httptrace.WithClientTrace(rctx, &httptrace.ClientTrace{
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			if i.Err == nil {
				wrote.Store(true)
			}
		},
	})
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(rctx, method, u, rd)
	if err != nil {
		return outNotDelivered, fmt.Errorf("catzprint: building request: %w", err)
	}
	if fresh {
		hc.CloseIdleConnections()
		req.Close = true
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", l.c.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	lost := func(e error) (outcome, error) {
		if ctx.Err() != nil {
			if wrote.Load() {
				return outNoAnswer, &ConnectionError{Err: ctx.Err(), delivered: true}
			}
			return outAnswered, &ConnectionError{Err: ctx.Err()}
		}
		if wrote.Load() {
			return outNoAnswer, e
		}
		return outNotDelivered, e
	}
	resp, err := hc.Do(req)
	if err != nil {
		var pm *PinMismatchError
		if errors.As(err, &pm) {
			return outNotDelivered, pm
		}
		return lost(&ConnectionError{Err: err})
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxLocalResponseBytes+1))
	if err != nil {
		wrote.Store(true) // an answer started: the station got the request
		return lost(&ConnectionError{Err: err})
	}
	if len(b) > maxLocalResponseBytes {
		return outNoAnswer, &APIError{Status: resp.StatusCode, Code: "response_too_large", Message: "The station's answer is too large."}
	}
	if resp.StatusCode >= 300 {
		e := parseError(resp.StatusCode, resp.Header, b)
		code := ErrorCode(e)
		switch {
		case resp.StatusCode == http.StatusBadGateway, resp.StatusCode == http.StatusGatewayTimeout:
			return outNotDelivered, e
		case resp.StatusCode == http.StatusServiceUnavailable && (code == "local_disabled" || code == "http_503"):
			return outNotDelivered, e
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			// Something on the network redirected us after taking the request.
			return outNoAnswer, e
		}
		return outAnswered, e
	}
	if out != nil && len(bytes.TrimSpace(b)) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return outNoAnswer, &APIError{Status: resp.StatusCode, Code: "invalid_response", Message: "The station returned a response the SDK couldn't read: " + err.Error()}
		}
	}
	return outOK, nil
}
