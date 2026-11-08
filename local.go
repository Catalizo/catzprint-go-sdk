package catzprint

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// LocalMode chooses where Jobs.Create sends jobs.
type LocalMode string

const (
	// ModeCloud sends every job to the CatzPrint API (the default; same
	// behaviour as before 2.2.0).
	ModeCloud LocalMode = "cloud"
	// ModeLocal sends jobs only to stations on the local network.
	ModeLocal LocalMode = "local"
	// ModeLocalFirst tries the stations first and falls back to the cloud
	// only when no station can be reached.
	ModeLocalFirst LocalMode = "local_first"
	// ModeCloudFirst tries the cloud first and falls back to the stations on
	// a network error, timeout or 5xx.
	ModeCloudFirst LocalMode = "cloud_first"
)

const (
	defaultLocalConnectTimeout = 3 * time.Second
	defaultLocalRequestTimeout = 15 * time.Second
	defaultLocalCloudTimeout   = 10 * time.Second
	defaultDiscoverTimeout     = 1500 * time.Millisecond
	tokenRefreshBefore         = 7 * 24 * time.Hour
	endpointsMaxAge            = time.Hour
	mdnsCacheTTL               = time.Minute
	refreshRetryAfter          = 5 * time.Minute
	maxLocalWait               = 30 * time.Second
)

// LocalConfig configures local printing (see WithLocal).
type LocalConfig struct {
	// Mode is cloud (default), local, local_first or cloud_first.
	Mode LocalMode
	// LocationID is the location this device prints at. It narrows minted
	// tokens and the endpoint list, filters discovered stations, and is
	// used as JobParams.LocationID when a job sets neither PrinterID nor
	// LocationID.
	LocationID string
	// StationURLs are station URLs to try first, in order, e.g.
	// "https://192-168-1-20.ab3k9x2mqp.local.catzprint.com:7443" or
	// "https://192.168.1.20:7443". IP URLs need a fingerprint (from the
	// endpoint list, mDNS or Fingerprints).
	StationURLs []string
	// Fingerprints pins certificates you got out of band (the station app
	// shows its fingerprint): keys are a station URL, "host:port" or host;
	// values the hex SHA-256 of the certificate (colons allowed).
	Fingerprints map[string]string
	// Discover adds stations from the cloud endpoint list (cached in the
	// token store, refreshed hourly while online) and maps their station IDs
	// to current addresses with mDNS. mDNS alone is never trusted: an
	// announcement is used only for a station on the cloud list (or one whose
	// fingerprint is in Fingerprints).
	Discover bool
	// AllLocations lets the SDK mint tokens valid at every location the API
	// key may use. By default minted tokens are bound to LocationID, which is
	// then required.
	AllLocations bool
	// TokenStore keeps the local token and endpoint list between runs.
	// Default: in memory. Use NewFileTokenStore for a hub that must print
	// after a restart while the internet is down.
	TokenStore TokenStore
	// Token is a fixed token to use instead of minting one: a device token
	// from Local.Pair ("czd_…") or a local token ("czl1.…").
	Token string
	// DeviceName names this device on stations (default: the host name).
	DeviceName string
	// TokenTTLDays is the lifetime of minted tokens, 1..30 (default 30).
	TokenTTLDays int
	// ConnectTimeout bounds connecting to a station, TLS included
	// (default 3s).
	ConnectTimeout time.Duration
	// RequestTimeout bounds one station request (default 15s).
	RequestTimeout time.Duration
	// CloudTimeout bounds the cloud attempt in cloud_first mode and token
	// minting / endpoint refreshes (default 10s).
	CloudTimeout time.Duration
	// DiscoverTimeout is how long an mDNS browse listens (default 1.5s).
	DiscoverTimeout time.Duration
	// Wait asks the station to hold the answer until the job printed or
	// failed, up to 30s (default 0: return as soon as it's queued).
	Wait time.Duration
	// RootCAs verifies public-certificate station hostnames (default: the
	// system roots).
	RootCAs *x509.CertPool
}

// String never reveals the token.
func (c LocalConfig) String() string {
	return fmt.Sprintf("catzprint.LocalConfig{Mode: %q, LocationID: %q, StationURLs: %q, Discover: %v, Token: %q, DeviceName: %q}",
		c.Mode, c.LocationID, c.StationURLs, c.Discover, redactToken(c.Token), c.DeviceName)
}

// GoString never reveals the token (%#v).
func (c LocalConfig) GoString() string { return c.String() }

// Format prints the redacted form for every verb.
func (c LocalConfig) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue keeps the token out of log/slog output.
func (c LocalConfig) LogValue() slog.Value { return slog.StringValue(c.String()) }

// MarshalJSON never includes the token.
func (c LocalConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"mode": c.Mode, "location_id": c.LocationID, "station_urls": c.StationURLs, "discover": c.Discover,
		"all_locations": c.AllLocations, "token": redactToken(c.Token), "device_name": c.DeviceName,
	})
}

// WithLocal enables local printing through CatzPrint stations on the same
// network. See LocalConfig and the README section "Local printing".
func WithLocal(cfg LocalConfig) Option {
	return func(c *Client) {
		cp := cfg
		c.localCfg = &cp
	}
}

type localState struct {
	c        *Client
	cfg      LocalConfig
	storeKey string

	mu         sync.Mutex
	loaded     bool
	state      *StoredToken
	storeErr   error
	mdns       []mdnsStation
	mdnsAt     time.Time
	clients    map[string]*http.Client
	jobURLs    map[string]string // local job id -> station URL
	nextTry    time.Time
	refreshing bool

	mintMu   sync.Mutex
	remintMu sync.Mutex

	bgCtx    context.Context
	bgCancel context.CancelFunc
	wg       sync.WaitGroup

	now      func() time.Time
	mdnsAddr *net.UDPAddr
}

func newLocalState(c *Client, p *LocalConfig) (*localState, error) {
	var cfg LocalConfig
	if p != nil {
		cfg = *p
	}
	switch cfg.Mode {
	case "":
		cfg.Mode = ModeCloud
	case ModeCloud, ModeLocal, ModeLocalFirst, ModeCloudFirst:
	default:
		return nil, fmt.Errorf("catzprint: unknown local mode %q (use cloud, local, local_first or cloud_first)", cfg.Mode)
	}
	urls := make([]string, 0, len(cfg.StationURLs))
	for _, raw := range cfg.StationURLs {
		u, err := normalizeStationURL(raw)
		if err != nil {
			return nil, err
		}
		if !containsStr(urls, u) {
			urls = append(urls, u)
		}
	}
	cfg.StationURLs = urls
	pins := map[string]string{}
	for k, v := range cfg.Fingerprints {
		fp := normalizeFingerprint(v)
		if fp == "" {
			return nil, fmt.Errorf("catzprint: fingerprint for %q must be 64 hex characters (SHA-256)", k)
		}
		pins[pinKey(k)] = fp
	}
	cfg.Fingerprints = pins
	if cfg.Mode != ModeCloud && len(cfg.StationURLs) == 0 && !cfg.Discover {
		return nil, errors.New("catzprint: local printing needs StationURLs or Discover: true")
	}
	if cfg.Mode != ModeCloud && cfg.Token == "" && cfg.LocationID == "" && !cfg.AllLocations {
		return nil, errors.New("catzprint: set LocalConfig.LocationID (minted local tokens are bound to it), or AllLocations: true for a token valid at every location")
	}
	if cfg.Token != "" && !strings.HasPrefix(cfg.Token, "czl1.") && !strings.HasPrefix(cfg.Token, "czd_") {
		return nil, errors.New("catzprint: LocalConfig.Token must be a local token (czl1.…) or a device token (czd_…)")
	}
	if cfg.TokenTTLDays < 0 || cfg.TokenTTLDays > 30 {
		return nil, errors.New("catzprint: TokenTTLDays must be between 1 and 30")
	}
	if cfg.Wait < 0 || cfg.Wait > maxLocalWait {
		return nil, errors.New("catzprint: LocalConfig.Wait must be between 0 and 30s")
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = defaultLocalConnectTimeout
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = defaultLocalRequestTimeout
	}
	if cfg.CloudTimeout <= 0 {
		cfg.CloudTimeout = defaultLocalCloudTimeout
	}
	if cfg.DiscoverTimeout <= 0 {
		cfg.DiscoverTimeout = defaultDiscoverTimeout
	}
	if cfg.TokenStore == nil {
		cfg.TokenStore = NewMemoryTokenStore()
	}
	if cfg.DeviceName == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			cfg.DeviceName = h
		} else {
			cfg.DeviceName = "CatzPrint Go SDK"
		}
	}
	cfg.DeviceName = truncateRunes(cfg.DeviceName, 80)
	kh := sha256.Sum256([]byte(c.apiKey))
	l := &localState{
		c:        c,
		cfg:      cfg,
		storeKey: "v1|" + hex.EncodeToString(kh[:8]) + "|" + cfg.LocationID + "|" + cfg.DeviceName,
		now:      time.Now,
		mdnsAddr: mdnsGroup,
		jobURLs:  map[string]string{},
	}
	l.bgCtx, l.bgCancel = context.WithCancel(context.Background())
	return l, nil
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// normalizeStationURL checks a station URL (https only, no credentials,
// path, query or fragment) and returns scheme://host:port.
func normalizeStationURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("catzprint: station URL %q isn't a valid URL", raw)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("catzprint: station URL %q must use https://", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("catzprint: station URL %q must be just https://host:port", raw)
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// pinKey normalizes a Fingerprints key: a URL becomes host:port, anything
// else is lower-cased.
func pinKey(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	if strings.Contains(k, "://") {
		if u, err := url.Parse(k); err == nil {
			return u.Host
		}
	}
	return strings.TrimSuffix(k, "/")
}

// Close stops background refreshes, waits for them, and closes idle
// connections to stations. The client must not be used afterwards for
// local printing. It is safe to call more than once.
func (c *Client) Close() error {
	if c.local != nil {
		c.local.bgCancel()
		c.local.wg.Wait()
		c.local.closeIdle()
	}
	return nil
}

// ---- token and endpoint state ----

func (l *localState) ensureLoaded(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.loaded {
		return
	}
	l.loaded = true
	st, err := l.cfg.TokenStore.Load(ctx, l.storeKey)
	if err != nil {
		l.storeErr = err
		return
	}
	st = st.clone()
	if st != nil && isRedactedToken(st.Token) {
		// A store that saved a redacted form: treat as "no token" (mint again).
		l.storeErr = errors.New("catzprint: the token store returned a redacted token placeholder; persist tokens with EncodeStoredToken")
		st.Token, st.TokenID = "", ""
	}
	l.state = st
}

func (l *localState) snapshot() *StoredToken {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state.clone()
}

func (l *localState) save(ctx context.Context, st *StoredToken) bool {
	l.mu.Lock()
	l.state = st.clone()
	l.mu.Unlock()
	if err := l.cfg.TokenStore.Save(ctx, l.storeKey, st); err != nil {
		l.mu.Lock()
		l.storeErr = err
		l.mu.Unlock()
		return false
	}
	return true
}

func (l *localState) cloudOpts() callOpts {
	return callOpts{maxRetries: 0, timeout: l.cfg.CloudTimeout}
}

// mint gets a fresh local token from the cloud and stores it (with the
// endpoint list that comes with it). Unless force is set, a concurrent mint
// that already produced a good token is reused.
func (l *localState) mint(ctx context.Context, force bool) (*StoredToken, error) {
	l.mintMu.Lock()
	defer l.mintMu.Unlock()
	if !force {
		if st := l.snapshot(); st.usable(l.now()) {
			return st, nil
		}
	}
	cctx, cancel := context.WithTimeout(ctx, l.cfg.CloudTimeout)
	defer cancel()
	params := LocalTokenParams{DeviceName: l.cfg.DeviceName, TTLDays: l.cfg.TokenTTLDays}
	if l.cfg.LocationID != "" {
		params.LocationIDs = []string{l.cfg.LocationID}
	}
	lt, err := l.c.LocalTokens.create(cctx, params, l.cloudOpts())
	if err != nil {
		return nil, err
	}
	st := l.snapshot()
	if st == nil {
		st = &StoredToken{}
	}
	st.Token, st.TokenID, st.ExpiresAt, st.IssuedAt = lt.Token, lt.TokenID, lt.ExpiresAt, l.now()
	if lt.Stations != nil {
		st.Stations, st.StationsUpdatedAt = lt.Stations, l.now()
	}
	if l.save(ctx, st) {
		// A fresh token was stored: an earlier load problem (e.g. a stored
		// placeholder) is resolved. An insecure store is never cleared.
		l.mu.Lock()
		if l.storeErr != nil && !errors.Is(l.storeErr, ErrInsecureTokenStore) {
			l.storeErr = nil
		}
		l.mu.Unlock()
	}
	return st, nil
}

func (st *StoredToken) usable(now time.Time) bool {
	return st != nil && st.Token != "" && now.Add(time.Minute).Before(st.ExpiresAt)
}

// token returns the token for station requests, minting one when none is
// usable. A token with less than 7 days left is still used while a
// background refresh replaces it.
func (l *localState) token(ctx context.Context) (string, error) {
	if l.cfg.Token != "" {
		l.maybeKickRefresh()
		return l.cfg.Token, nil
	}
	l.ensureLoaded(ctx)
	if err := l.insecureStore(); err != nil {
		return "", err
	}
	if st := l.snapshot(); st.usable(l.now()) {
		l.maybeKickRefresh()
		return st.Token, nil
	}
	st, err := l.mint(ctx, false)
	if err != nil {
		return "", err
	}
	if err := l.insecureStore(); err != nil {
		return "", err
	}
	return st.Token, nil
}

// insecureStore returns the store's refusal (ErrInsecureTokenStore), if
// any: tokens are never kept in a file others could read or replace.
func (l *localState) insecureStore() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if errors.Is(l.storeErr, ErrInsecureTokenStore) {
		return l.storeErr
	}
	return nil
}

// needsRefresh says what is stale: the token (< 7 days left) and/or the
// endpoint list (older than an hour).
func (l *localState) needsRefresh() (tok, eps bool) {
	st := l.snapshot()
	now := l.now()
	if l.cfg.Token == "" {
		tok = st == nil || st.Token == "" || st.ExpiresAt.Sub(now) < l.refreshBefore(st)
	}
	eps = st == nil || st.StationsUpdatedAt.IsZero() || now.Sub(st.StationsUpdatedAt) > endpointsMaxAge
	return tok, eps
}

// refreshBefore is min(7 days, TTL/2): a short-lived token isn't renewed
// on every job.
func (l *localState) refreshBefore(st *StoredToken) time.Duration {
	ttl := time.Duration(l.cfg.TokenTTLDays) * 24 * time.Hour
	if ttl == 0 {
		ttl = 30 * 24 * time.Hour
	}
	if st != nil && !st.IssuedAt.IsZero() && st.ExpiresAt.After(st.IssuedAt) {
		ttl = st.ExpiresAt.Sub(st.IssuedAt)
	}
	return min(tokenRefreshBefore, ttl/2)
}

func (l *localState) maybeKickRefresh() {
	if l.c.apiKey == "" {
		return // paired-device mode: no cloud
	}
	tok, eps := l.needsRefresh()
	if !tok && !eps {
		return
	}
	l.mu.Lock()
	if l.refreshing || l.bgCtx.Err() != nil || l.now().Before(l.nextTry) {
		l.mu.Unlock()
		return
	}
	l.refreshing = true
	l.wg.Add(1)
	l.mu.Unlock()
	go func() {
		defer l.wg.Done()
		ctx, cancel := context.WithTimeout(l.bgCtx, 2*l.cfg.CloudTimeout)
		defer cancel()
		err := l.refresh(ctx, false)
		l.mu.Lock()
		l.refreshing = false
		if err != nil {
			l.nextTry = l.now().Add(refreshRetryAfter)
		}
		l.mu.Unlock()
	}()
}

// refresh renews the token when it has less than 7 days left and the
// endpoint list when it is older than an hour (or always, with force).
func (l *localState) refresh(ctx context.Context, force bool) error {
	l.ensureLoaded(ctx)
	tok, eps := l.needsRefresh()
	if tok {
		var before time.Time
		if prev := l.snapshot(); prev != nil {
			before = prev.StationsUpdatedAt
		}
		st, err := l.mint(ctx, true)
		if err != nil {
			return err
		}
		if !st.StationsUpdatedAt.Equal(before) {
			return nil // the mint brought a fresh endpoint list
		}
	}
	if !eps && !force {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, l.cfg.CloudTimeout)
	defer cancel()
	list, err := l.c.LocalEndpoints.list(cctx, l.cfg.LocationID, l.cloudOpts())
	if err != nil {
		return err
	}
	st := l.snapshot()
	if st == nil {
		st = &StoredToken{}
	}
	st.Stations, st.StationsUpdatedAt = list, l.now()
	l.save(ctx, st)
	return nil
}

// orgHint is the organization this device belongs to, if known without a
// network call (the cached org ID, or the minted token's claims).
func (l *localState) orgHint() string {
	l.c.mu.Lock()
	org := l.c.orgID
	l.c.mu.Unlock()
	if org != "" {
		return org
	}
	tok := l.cfg.Token
	if st := l.snapshot(); tok == "" && st != nil {
		tok = st.Token
	}
	return tokenClaims(tok).Org
}

type localClaims struct {
	Org  string   `json:"org"`
	Live bool     `json:"live"`
	Loc  []string `json:"loc"`
}

// tokenClaims reads (without verifying) a czl1 token's payload.
func tokenClaims(tok string) localClaims {
	var c localClaims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != "czl1" {
		return c
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c
	}
	_ = json.Unmarshal(b, &c)
	return c
}

// ---- candidates ----

// endpointsKnown reports whether the cloud endpoint list was ever fetched.
func (st *StoredToken) endpointsKnown() bool { return st != nil && !st.StationsUpdatedAt.IsZero() }

// privateIP reports whether h is an IP a station may use on the LAN:
// RFC 1918, IPv6 ULA, link-local, or loopback. Anything else from the cloud
// list or mDNS is ignored.
func privateIP(h string) bool {
	ip := net.ParseIP(strings.Trim(h, "[]"))
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

func urlHost(u string) (host, port string) {
	pu, err := url.Parse(u)
	if err != nil {
		return "", ""
	}
	return strings.ToLower(pu.Hostname()), pu.Port()
}

// endpointTargets turns one cloud endpoint into targets. Hostnames come
// only from here (the authenticated cloud list): verified with the system
// roots and pinned to the public key the cloud reports, and reached directly
// at the IP in the name only under the station's own label. IP URLs must be
// private and are pinned to the station's self-signed certificate.
func endpointTargets(ep LocalEndpoint, source string) []stationTarget {
	fp := normalizeFingerprint(ep.CertFingerprintSHA256)
	spki := normalizeFingerprint(ep.PublicSPKISHA256)
	var out []stationTarget
	for _, raw := range ep.URLs {
		u, err := normalizeStationURL(raw)
		if err != nil {
			continue
		}
		host, _ := urlHost(u)
		t := stationTarget{URL: u, TLSMode: ep.TLSMode, StationID: ep.StationID, Source: source}
		if net.ParseIP(host) != nil {
			if !privateIP(host) {
				continue
			}
			t.Fingerprint = fp
		} else {
			t.SPKI = spki
			label := strings.ToLower(ep.LocalLabel)
			if parts := strings.Split(host, "."); label == "" && len(parts) >= 3 {
				label = parts[1] // the hostname itself came from the cloud
			}
			t.Label = label
		}
		out = append(out, t)
	}
	return out
}

// userPinned reports whether fp is one of the fingerprints the user
// configured (LocalConfig.Fingerprints).
func (l *localState) userPinned(fp string) bool {
	if fp == "" {
		return false
	}
	for _, v := range l.cfg.Fingerprints {
		if v == fp {
			return true
		}
	}
	return false
}

// targetFor finds how to trust a configured URL: a pin from
// LocalConfig.Fingerprints, else the cloud endpoint list (by URL, or by
// address and port for IPs), else an mDNS answer for a station on that list.
func (l *localState) targetFor(u, source string, st *StoredToken, mdns []mdnsStation) stationTarget {
	t := stationTarget{URL: u, Source: source}
	host, port := urlHost(u)
	hostport := host + ":" + port
	for _, k := range []string{hostport, host} {
		if fp, ok := l.cfg.Fingerprints[k]; ok {
			t.Fingerprint = fp
			return t
		}
	}
	if st != nil {
		for _, ep := range st.Stations {
			for _, et := range endpointTargets(ep, source) {
				if et.URL == u {
					return et
				}
			}
			if net.ParseIP(host) != nil && privateIP(host) && containsStr(ep.Addresses, host) && strconv.Itoa(ep.Port) == port {
				t.Fingerprint = normalizeFingerprint(ep.CertFingerprintSHA256)
				t.TLSMode, t.StationID = ep.TLSMode, ep.StationID
				return t
			}
		}
	}
	for _, d := range l.acceptedMDNS(mdns, st) {
		if containsStr(d.Addresses, host) && strconv.Itoa(d.Port) == port {
			t.Fingerprint, t.TLSMode, t.StationID = d.Fingerprint, d.TLSMode, d.StationID
			return t
		}
	}
	return t
}

// primaryTargets are the configured URLs, then (with Discover) the cloud
// endpoint list's URLs, public hostnames before raw IPs.
func (l *localState) primaryTargets() []stationTarget {
	st := l.snapshot()
	l.mu.Lock()
	mdns := l.mdns
	l.mu.Unlock()
	var out []stationTarget
	seen := map[string]bool{}
	for _, u := range l.cfg.StationURLs {
		seen[u] = true
		out = append(out, l.targetFor(u, "config", st, mdns))
	}
	if l.cfg.Discover && st != nil {
		for _, ep := range st.Stations {
			if !ep.LocalEnabled || (l.cfg.LocationID != "" && ep.LocationID != "" && ep.LocationID != l.cfg.LocationID) {
				continue
			}
			for _, t := range endpointTargets(ep, "cloud") {
				if !seen[t.URL] {
					seen[t.URL] = true
					out = append(out, t)
				}
			}
		}
	}
	return out
}

// acceptedMDNS filters mDNS announcements. mDNS is unauthenticated, so it
// only maps a station ID to its current addresses: an announcement is used
// for a station on the cloud endpoint list (pinned with the list's
// fingerprint, port from the list) or one whose announced fingerprint the
// user configured. The announced hostname is never used, and only private
// addresses are kept.
func (l *localState) acceptedMDNS(found []mdnsStation, st *StoredToken) []mdnsStation {
	org := l.orgHint()
	var out []mdnsStation
	for _, d := range found {
		if org != "" && d.OrgID != "" && d.OrgID != org {
			continue
		}
		if l.cfg.LocationID != "" && d.LocationID != "" && d.LocationID != l.cfg.LocationID {
			continue
		}
		var addrs []string
		for _, a := range d.Addresses {
			if privateIP(a) {
				addrs = append(addrs, a)
			}
		}
		d.Addresses, d.Hostname = addrs, ""
		var ep *LocalEndpoint
		if st != nil {
			for i := range st.Stations {
				if st.Stations[i].StationID == d.StationID {
					ep = &st.Stations[i]
				}
			}
		}
		switch {
		case ep != nil:
			if !ep.LocalEnabled {
				continue
			}
			d.Fingerprint, d.TLSMode = normalizeFingerprint(ep.CertFingerprintSHA256), "self_signed"
			if ep.Port > 0 {
				d.Port = ep.Port
			}
		case l.userPinned(d.Fingerprint):
		default:
			continue
		}
		if d.Fingerprint == "" || len(d.Addresses) == 0 {
			continue
		}
		out = append(out, d)
	}
	return out
}

// mdnsTargets are the pinned IP URLs of an accepted announcement.
func mdnsTargets(d mdnsStation) []stationTarget {
	var out []stationTarget
	port := strconv.Itoa(d.Port)
	for _, a := range d.Addresses {
		out = append(out, stationTarget{URL: "https://" + net.JoinHostPort(a, port), Fingerprint: d.Fingerprint, TLSMode: "self_signed", StationID: d.StationID, Source: "mdns"})
	}
	return out
}

// browse runs (or reuses, for a minute) an mDNS browse.
func (l *localState) browse(ctx context.Context, fresh bool) ([]mdnsStation, error) {
	l.mu.Lock()
	if !fresh && !l.mdnsAt.IsZero() && l.now().Sub(l.mdnsAt) < mdnsCacheTTL {
		found := l.mdns
		l.mu.Unlock()
		return found, nil
	}
	addr := l.mdnsAddr
	l.mu.Unlock()
	found, err := mdnsBrowse(ctx, l.cfg.DiscoverTimeout, addr)
	l.mu.Lock()
	l.mdns, l.mdnsAt = found, l.now()
	l.mu.Unlock()
	return found, err
}

// eachTarget calls try for every candidate in order: configured URLs, cloud
// endpoint URLs, then (with Discover, only if those all failed) stations
// found over mDNS. preferred, when set, goes first. It stops when try
// returns stop=true.
func (l *localState) eachTarget(ctx context.Context, preferred string, try func(stationTarget) bool) {
	tried := map[string]bool{}
	targets := l.primaryTargets()
	if preferred != "" {
		for i, t := range targets {
			if t.URL == preferred {
				targets = append([]stationTarget{t}, append(targets[:i:i], targets[i+1:]...)...)
				break
			}
		}
	}
	for _, t := range targets {
		tried[t.URL] = true
		if try(t) || ctx.Err() != nil {
			return
		}
	}
	if !l.cfg.Discover {
		return
	}
	found, _ := l.browse(ctx, false)
	if ctx.Err() != nil {
		return
	}
	for _, d := range l.acceptedMDNS(found, l.snapshot()) {
		for _, t := range mdnsTargets(d) {
			if tried[t.URL] {
				continue
			}
			tried[t.URL] = true
			if try(t) || ctx.Err() != nil {
				return
			}
		}
	}
}

// ---- jobs ----

// localCapable says whether a job can go to a station at all.
func localCapable(p *JobParams) error {
	switch {
	case p.Sealed:
		return errors.New("sealed jobs go through the cloud")
	case p.ScheduledFor != nil:
		return errors.New("scheduled jobs go through the cloud")
	case len(p.Content) > 0:
		k := p.Kind
		if k == "" {
			k = detectKind(p.Content, p.FileName)
		}
		if k != "escpos" && k != "text" {
			return errors.New("PDFs, images and documents go through the cloud")
		}
	}
	switch p.Kind {
	case "", "commands", "template", "text", "escpos", "test":
		return nil
	}
	return errors.New("PDFs, images and documents go through the cloud")
}

func unsupportedLocally(why error) error {
	return &ValidationError{&APIError{Status: http.StatusUnprocessableEntity, Code: "unsupported_locally",
		Message: "This job can't print locally: " + why.Error() + ". Send PDFs, images and documents through the cloud."}}
}

func isTokenRejected(err error) bool {
	var ae *AuthenticationError
	return errors.As(err, &ae)
}

// shouldFallBackToLocal: in cloud_first, which cloud failures go to the
// stations (network errors, timeouts, 5xx).
func shouldFallBackToLocal(err error) bool {
	var ce *ConnectionError
	var se *ServerError
	return errors.As(err, &ce) || errors.As(err, &se)
}

// mintErrorIsUnreachable: a token that can't be minted because the cloud
// can't be reached makes local printing impossible ("unreachable"); a 4xx
// from the cloud (e.g. a missing scope) is returned as is.
func mintErrorIsUnreachable(err error) bool { return shouldFallBackToLocal(err) }

// remintInterval limits re-minting after a station refused a token.
const remintInterval = 10 * time.Minute

// remint answers a 401 with a fresh token, but only for token_expired
// (never device_revoked: a device revoked at the station must stay
// revoked), only for minted tokens, and at most once per 10 minutes per
// store key (persisted, so restarts don't reset it).
func (l *localState) remint(ctx context.Context, rejected error) (string, bool, error) {
	if l.cfg.Token != "" || l.c.apiKey == "" || ErrorCode(rejected) != "token_expired" {
		return "", false, nil
	}
	l.remintMu.Lock()
	defer l.remintMu.Unlock()
	st := l.snapshot()
	if st == nil {
		st = &StoredToken{}
	}
	now := l.now()
	if !st.LastRemintAt.IsZero() && now.Sub(st.LastRemintAt) < remintInterval {
		return "", false, nil
	}
	st.LastRemintAt = now
	l.save(ctx, st)
	nst, err := l.mint(ctx, true)
	if err != nil {
		return "", false, err
	}
	return nst.Token, true, nil
}

// createLocal sends a job to the first station that takes it.
func (s *JobsService) createLocal(ctx context.Context, p JobParams) (*Job, error) {
	l := s.c.local
	body, err := s.body(ctx, &p)
	if err != nil {
		return nil, err
	}
	delete(body, "file_name")
	sue := &StationUnreachableError{}
	tok, err := l.token(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, &ConnectionError{Err: ctx.Err()}
		}
		if !mintErrorIsUnreachable(err) {
			return nil, err
		}
		sue.add("", fmt.Errorf("no local token (the cloud couldn't mint one): %w", err))
		return nil, sue
	}
	q := url.Values{}
	if l.cfg.Wait > 0 {
		q.Set("wait", strconv.Itoa(int((l.cfg.Wait+time.Second-1)/time.Second)))
	}
	reminted := false
	var result *Job
	var final error
	key := p.IdempotencyKey
	l.eachTarget(ctx, "", func(t stationTarget) bool {
		var lj LocalJob
		kind, err := l.sendX(ctx, t, http.MethodPost, "/local/v1/jobs", q, tok, body, &lj, l.cfg.Wait, false)
		if kind == outAnswered && isTokenRejected(err) && !reminted {
			// 401 token_expired: mint a fresh token (rate-limited) and retry
			// this station once.
			reminted = true
			nt, ok, merr := l.remint(ctx, err)
			if ok {
				tok = nt
				kind, err = l.sendX(ctx, t, http.MethodPost, "/local/v1/jobs", q, tok, body, &lj, l.cfg.Wait, false)
			} else if merr != nil && ctx.Err() == nil {
				err = fmt.Errorf("%w (and a fresh token couldn't be minted: %v)", err, merr)
			}
		}
		postInProgress := false
		if kind == outAnswered && isInProgress(err) {
			// The station is still processing a job with this key: wait for
			// it by probing (Q1). Never send it elsewhere.
			kind = outNoAnswer
			postInProgress = true
		}
		if kind == outOK && lj.ID == "" {
			// A 2xx we can't use: the station has the job (or not); find out.
			kind, err = outNoAnswer, &APIError{Status: http.StatusCreated, Code: "invalid_response", Message: "The station answered without a job."}
		}
		if kind == outNoAnswer && ctx.Err() == nil {
			// The station got the job but its answer was lost: ask it, by
			// idempotency key, whether it recorded the job. Never send it
			// anywhere else while that is unknown.
			switch pj, res, perr := l.probeByKey(ctx, t, tok, key); res {
			case probeFound:
				lj, err, kind = *pj, nil, outOK
			case probeNotFound:
				if postInProgress {
					// The station said it was processing this key: a 404
					// now doesn't mean "never recorded" (S4).
					final = &OutcomeUnknownError{URL: t.URL, IdempotencyKey: key, Cause: err}
					return true
				}
				kind = outNotDelivered
			case probeConflict:
				final = perr // 409 duplicate: an answer, no fallback
				return true
			default:
				final = &OutcomeUnknownError{URL: t.URL, IdempotencyKey: key, Cause: err}
				return true
			}
		}
		unreachable := kind == outNotDelivered
		switch {
		case err == nil:
			lj.StationURL = t.URL
			result = lj.toJob(t, p, tokenLive(tok))
			l.rememberJob(lj.ID, t.URL)
			return true
		case ctx.Err() != nil:
			if kind == outNoAnswer {
				// Cancelled after the job was sent: it may print.
				final = &OutcomeUnknownError{URL: t.URL, IdempotencyKey: key, Cause: err}
			} else {
				final = &ConnectionError{Err: ctx.Err()}
			}
			return true
		case unreachable:
			sue.add(t.URL, err)
			return false
		case isTokenRejected(err):
			// Still refused: in the fallback modes this means "use the
			// cloud"; in local mode the 401 is the answer.
			if l.cfg.Mode == ModeLocal {
				final = err
			} else {
				sue.add(t.URL, err)
				final = sue
			}
			return true
		default:
			final = err
			return true
		}
	})
	if result != nil {
		return result, nil
	}
	if final != nil {
		return nil, final
	}
	if ctx.Err() != nil {
		return nil, &ConnectionError{Err: ctx.Err()}
	}
	return nil, sue
}

type probeResult int

const (
	probeUnknown probeResult = iota
	probeFound
	probeNotFound
	probeConflict // 409 duplicate: the key belongs to a job this caller can't see
)

// probeByKey asks the station that may have a job for it by idempotency
// key: up to 3 tries within min(5s, what's left of ctx), on fresh
// connections with the same pinning.
func (l *localState) probeByKey(ctx context.Context, t stationTarget, tok, key string) (*LocalJob, probeResult, error) {
	budget := 5 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < budget {
			budget = left
		}
	}
	if budget <= 0 {
		return nil, probeUnknown, nil
	}
	pctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	q := url.Values{"idempotency_key": {key}}
	sawInProgress := false
	for i := 0; i < 3; i++ {
		var lj LocalJob
		kind, err := l.sendX(pctx, t, http.MethodGet, "/local/v1/jobs", q, tok, nil, &lj, 0, true)
		var nf *NotFoundError
		var cf *ConflictError
		switch {
		case kind == outOK && lj.ID != "":
			return &lj, probeFound, nil
		case kind == outAnswered && isInProgress(err):
			sawInProgress = true // the station is processing this key: a later 404 isn't "never recorded"
		case kind == outAnswered && errors.As(err, &nf) && nf.Code == "not_found":
			if sawInProgress {
				return nil, probeUnknown, nil // T2: it said in_progress, then 404: unknown
			}
			return nil, probeNotFound, nil
		case kind == outAnswered && errors.As(err, &cf) && cf.Code == "duplicate":
			return nil, probeConflict, err
		case pctx.Err() != nil:
			return nil, probeUnknown, nil
		}
		if i < 2 && sleepCtx(pctx, budget/6) != nil {
			return nil, probeUnknown, nil
		}
	}
	return nil, probeUnknown, nil
}

func (l *localState) rememberJob(id, u string) {
	if id == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.jobURLs) >= 1000 {
		l.jobURLs = map[string]string{}
	}
	l.jobURLs[id] = u
}

// tokenLive is the live flag a token implies: paired devices (czd_) are
// live; local tokens carry it in their claims.
func tokenLive(tok string) bool {
	if strings.HasPrefix(tok, "czd_") {
		return true
	}
	return tokenClaims(tok).Live
}

func (lj *LocalJob) toJob(t stationTarget, p JobParams, live bool) *Job {
	if lj.Live != nil {
		live = *lj.Live // the station's answer wins
	}
	j := &Job{
		ID:             lj.ID,
		Live:           live,
		Source:         "local",
		Kind:           p.Kind,
		Status:         lj.Status,
		StatusDetail:   lj.Detail,
		Title:          lj.Title,
		Reference:      lj.Reference,
		Copies:         lj.Copies,
		CreatedAt:      lj.CreatedAt,
		FinishedAt:     lj.FinishedAt,
		PrintedLocally: true,
		IdempotencyKey: lj.IdempotencyKey,
		Via:            ViaLocal,
		Local:          lj,
	}
	if j.Kind == "" {
		j.Kind = inferKind(p)
	}
	str := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}
	j.PrinterID, j.PrinterName, j.LocationID, j.StationID = str(lj.PrinterID), str(lj.PrinterName), str(lj.LocationID), str(t.StationID)
	if lj.Status == StatusPrinted && lj.FinishedAt != nil {
		j.PrintedAt = lj.FinishedAt
	}
	if lj.Status == StatusFailed && lj.ErrorCode != "" && j.StatusDetail == "" {
		j.StatusDetail = lj.ErrorCode
	}
	return j
}

func inferKind(p JobParams) string {
	switch {
	case p.Text != "":
		return "text"
	case len(p.Commands) > 0:
		return "commands"
	case p.TemplateID != "":
		return "template"
	case len(p.Content) > 0:
		return detectKind(p.Content, p.FileName)
	}
	return ""
}

// cloudNotDelivered: the cloud surely doesn't have the job (never sent, or
// a 502/503/504 from the edge): safe to go to a station.
func cloudNotDelivered(err error) bool {
	if IsOutcomeUnknown(err) {
		return false // the cloud may have the job: never "not delivered"
	}
	var ns *notSentError
	if errors.As(err, &ns) {
		return true
	}
	var ce *ConnectionError
	if errors.As(err, &ce) {
		return !ce.delivered
	}
	var se *ServerError
	if errors.As(err, &se) {
		return se.Status == http.StatusBadGateway || se.Status == http.StatusServiceUnavailable || se.Status == http.StatusGatewayTimeout
	}
	return false
}

// cloudAmbiguous: the cloud may have the job (sent with no usable answer,
// a 500, a redirect or an unreadable answer).
func cloudAmbiguous(err error) bool {
	var ns *notSentError
	if IsOutcomeUnknown(err) || errors.As(err, &ns) {
		return false
	}
	var ce *ConnectionError
	if errors.As(err, &ce) {
		return ce.delivered
	}
	var api *APIError
	if !errors.As(err, &api) {
		return false
	}
	switch {
	case api.Status >= 500:
		return !cloudNotDelivered(err)
	case api.Status >= 300 && api.Status < 400:
		return true
	}
	return api.Code == "response_too_large" || api.Code == "invalid_response"
}

// notSentError marks a failure before the job POST was sent (e.g. the
// org-ID lookup): the cloud surely doesn't have the job.
type notSentError struct{ err error }

func (e *notSentError) Error() string { return e.err.Error() }
func (e *notSentError) Unwrap() error { return e.err }

// isConflictInProgress: a 409 saying a job with this key exists or is
// being created right now.
func isConflictInProgress(err error) bool {
	var ce *ConflictError
	return errors.As(err, &ce) && (ce.Code == "duplicate" || strings.Contains(strings.ToLower(ce.Message), "being created"))
}

// isInProgress: a station's 409 "in_progress" (a job with this key is
// still being processed).
func isInProgress(err error) bool {
	var ce *ConflictError
	return errors.As(err, &ce) && ce.Code == "in_progress"
}

// sentAndLost: the request was written, then the answer was lost.
func sentAndLost(err error) bool {
	var ce *ConnectionError
	return errors.As(err, &ce) && ce.delivered
}

// createCloudCareful creates a job in the cloud without automatic retries:
//   - an ambiguous answer (sent without answer, any 5xx but 502/503/504, a
//     redirect, an unreadable body) gets one retry with the same key;
//   - a 409 "duplicate"/"being created" gets up to 3 re-sends, 1 s apart;
//   - if it stays ambiguous, or a re-send isn't delivered, the result is an
//     *OutcomeUnknownError: the cloud may have the job, so never a station;
//   - a caller cancellation after the request was written is an
//     *OutcomeUnknownError wrapping the cancellation.
func (s *JobsService) createCloudCareful(ctx context.Context, p JobParams, o callOpts) (*Job, error) {
	unknown := func(e error) error {
		return &OutcomeUnknownError{URL: s.c.baseURL, IdempotencyKey: p.IdempotencyKey, Cause: e}
	}
	r, err := s.prepareCloud(ctx, p)
	if err != nil {
		return nil, err // not sent (or invalid parameters)
	}
	job, err := s.postCloud(ctx, r, o)
	if err == nil {
		return job, nil
	}
	if ctx.Err() != nil {
		if sentAndLost(err) {
			return nil, unknown(err)
		}
		return nil, err
	}
	ambiguous := false
	if cloudAmbiguous(err) {
		ambiguous = true
		job, err = s.postCloud(ctx, r, o) // the exact same bytes
		switch {
		case err == nil:
			return job, nil
		case ctx.Err() != nil:
			return nil, unknown(err) // the first attempt was already ambiguous
		case isConflictInProgress(err):
			// fall through to the 409 loop
		case p.Sealed && sealedRejected(err):
			// fall through to the re-seal
		case cloudAmbiguous(err) || cloudNotDelivered(err):
			return nil, unknown(err)
		default:
			return nil, err
		}
	}
	if p.Sealed && sealedRejected(err) {
		return s.resealAndResend(ctx, p, o, err, ambiguous, unknown)
	}
	if isConflictInProgress(err) {
		return s.resendWhileInProgress(ctx, r, o, err, unknown)
	}
	return nil, err
}

// resendWhileInProgress re-sends the identical create after a 409
// "duplicate"/"being created": up to 3 times, 1 s apart. A 409 that is
// still there afterwards is the cloud's (definite) answer and is returned;
// only a re-send that isn't delivered or is ambiguous becomes
// OutcomeUnknown. Cancelled while waiting (nothing sent): the cancellation.
func (s *JobsService) resendWhileInProgress(ctx context.Context, r *cloudRequest, o callOpts, err error, unknown func(error) error) (*Job, error) {
	for i := 0; i < 3; i++ {
		if werr := sleepCtx(ctx, time.Second); werr != nil {
			return nil, &ConnectionError{Err: werr}
		}
		var job *Job
		job, err = s.postCloud(ctx, r, o) // identical re-send
		switch {
		case err == nil:
			return job, nil
		case ctx.Err() != nil:
			if sentAndLost(err) {
				return nil, unknown(err)
			}
			return nil, err
		case isConflictInProgress(err):
			continue
		case cloudAmbiguous(err) || cloudNotDelivered(err) || sealedRejected(err):
			// A job with this key exists or is being created: an answer
			// that isn't the job leaves the outcome open.
			return nil, unknown(err)
		default:
			return nil, err
		}
	}
	return nil, err // still 409: the cloud's answer
}

// sealedRejected: a 400/422 saying the API couldn't use sealed_content
// (usually: the server key was rotated after it was fetched).
func sealedRejected(err error) bool {
	var ve *ValidationError
	if !errors.As(err, &ve) {
		return false
	}
	_, ok := ve.Fields["sealed_content"]
	return ok
}

// resealAndResend answers a sealed_content 400/422 (S1): drop the cached
// server key, fetch it again, seal again and re-send once with the same
// idempotency key. After an ambiguous attempt (the cloud may have the job),
// anything but a job or a definite 409 answer is OutcomeUnknown; without
// one, the first 400 was a definite answer, so the re-send's own error is
// returned (a re-send that may have arrived is still OutcomeUnknown).
func (s *JobsService) resealAndResend(ctx context.Context, p JobParams, o callOpts, first error, ambiguous bool, unknown func(error) error) (*Job, error) {
	s.c.dropServerKey()
	r, err := s.prepareCloud(ctx, p)
	if err != nil {
		if ambiguous {
			return nil, unknown(err)
		}
		return nil, first // nothing more was sent: the API's answer stands
	}
	amb := false
	o.ambiguous = &amb
	job, err := s.postCloud(ctx, r, o)
	ambiguous = ambiguous || amb
	switch {
	case err == nil:
		return job, nil
	case ctx.Err() != nil:
		if ambiguous || sentAndLost(err) {
			return nil, unknown(err)
		}
		return nil, err
	case isConflictInProgress(err):
		return s.resendWhileInProgress(ctx, r, o, err, unknown)
	case cloudAmbiguous(err):
		return nil, unknown(err)
	case ambiguous:
		return nil, unknown(err) // e.g. sealed_content again: the first attempt may have the job
	default:
		return nil, err // definite (or not delivered: the cloud has no job)
	}
}

// checkIdempotencyKey treats a blank key as "no key" and rejects keys with
// leading/trailing whitespace or control characters (never silently
// changed).
func checkIdempotencyKey(k string) (string, error) {
	if strings.TrimSpace(k) == "" {
		return "", nil
	}
	if k != strings.TrimSpace(k) {
		return "", invalidParams("idempotency_key", "The idempotency key must not start or end with whitespace.")
	}
	for _, r := range k {
		if unicode.IsControl(r) {
			return "", invalidParams("idempotency_key", "The idempotency key must not contain control characters.")
		}
	}
	return k, nil
}

// create routes a job according to the local mode.
func (s *JobsService) create(ctx context.Context, params JobParams) (*Job, error) {
	l := s.c.local
	key, err := checkIdempotencyKey(params.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	params.IdempotencyKey = key
	if l == nil || l.cfg.Mode == ModeCloud {
		return s.createCloudMode(ctx, params)
	}
	// The same key goes to the station and to the cloud, so a fallback can
	// never print twice.
	if params.IdempotencyKey == "" {
		params.IdempotencyKey = "sdk-" + newUUID()
	}
	if params.PrinterID == "" && params.LocationID == "" {
		params.LocationID = l.cfg.LocationID
	}
	capErr := localCapable(&params)
	switch l.cfg.Mode {
	case ModeLocal:
		if capErr != nil {
			return nil, unsupportedLocally(capErr)
		}
		return s.createLocal(ctx, params)
	case ModeLocalFirst:
		if capErr != nil {
			return s.createCloudMode(ctx, params) // can't print locally: the cloud-mode create
		}
		job, err := s.createLocal(ctx, params)
		var sue *StationUnreachableError
		if err == nil || !errors.As(err, &sue) || ctx.Err() != nil {
			return job, err
		}
		job, cerr := s.createCloudCareful(ctx, params, callOpts{maxRetries: 0, timeout: s.c.timeout})
		if cerr != nil {
			if cloudNotDelivered(cerr) {
				sue.CloudErr = cerr
				return nil, sue
			}
			return nil, cerr
		}
		return job, nil
	default: // ModeCloudFirst
		if capErr != nil {
			return s.createCloudMode(ctx, params) // can't print locally: the cloud-mode create
		}
		job, err := s.createCloudCareful(ctx, params, l.cloudOpts())
		if err == nil || ctx.Err() != nil || !cloudNotDelivered(err) {
			return job, err
		}
		job, lerr := s.createLocal(ctx, params)
		if lerr == nil {
			return job, nil
		}
		var sue *StationUnreachableError
		if errors.As(lerr, &sue) {
			sue.CloudErr = err
			return nil, sue
		}
		return nil, lerr
	}
}

// ---- LocalService ----

// LocalService talks to CatzPrint stations on the local network. Use it via
// Client.Local.
type LocalService struct{ c *Client }

// Mode returns the configured local mode.
func (s *LocalService) Mode() LocalMode { return s.c.local.cfg.Mode }

// Status returns the status of the first station that answers (printers,
// paper, unsynced jobs, offline allowance).
func (s *LocalService) Status(ctx context.Context) (*LocalStatus, error) {
	var out *LocalStatus
	err := s.authed(ctx, "", func(t stationTarget, tok string) (bool, error) {
		var st LocalStatus
		unreachable, err := s.c.local.send(ctx, t, http.MethodGet, "/local/v1/status", nil, tok, nil, &st, 0)
		if err == nil {
			st.StationURL = t.URL
			out = &st
		}
		return unreachable, err
	})
	return out, err
}

// GetJob returns a local job ("lj_…") from the station that has it.
// Jobs.Get and Jobs.WaitFor call it for local job IDs.
func (s *LocalService) GetJob(ctx context.Context, id string) (*Job, error) {
	l := s.c.local
	l.mu.Lock()
	pref := l.jobURLs[id]
	l.mu.Unlock()
	var out *Job
	var notFound error
	err := s.authed(ctx, pref, func(t stationTarget, tok string) (bool, error) {
		var lj LocalJob
		unreachable, err := l.send(ctx, t, http.MethodGet, "/local/v1/jobs/"+url.PathEscape(id), nil, tok, nil, &lj, 0)
		if err == nil {
			lj.StationURL = t.URL
			out = lj.toJob(t, JobParams{}, tokenLive(tok))
			l.rememberJob(id, t.URL)
			return false, nil
		}
		var nf *NotFoundError
		if errors.As(err, &nf) && pref == "" {
			// Another station may have it.
			notFound = err
			return true, err
		}
		return unreachable, err
	})
	if err != nil && notFound != nil && errors.Is(err, ErrStationUnreachable) {
		return nil, notFound
	}
	return out, err
}

// authed runs fn against each candidate station with a token until one
// answers. fn returns unreachable=true to move on to the next station.
func (s *LocalService) authed(ctx context.Context, preferred string, fn func(stationTarget, string) (bool, error)) error {
	l := s.c.local
	tok, err := l.token(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return &ConnectionError{Err: ctx.Err()}
		}
		if !mintErrorIsUnreachable(err) {
			return err
		}
		sue := &StationUnreachableError{}
		sue.add("", fmt.Errorf("no local token (the cloud couldn't mint one): %w", err))
		return sue
	}
	sue := &StationUnreachableError{}
	var final error
	done := false
	reminted := false
	l.eachTarget(ctx, preferred, func(t stationTarget) bool {
		unreachable, err := fn(t, tok)
		if err != nil && !unreachable && isTokenRejected(err) && !reminted {
			reminted = true
			if nt, ok, _ := l.remint(ctx, err); ok {
				tok = nt
				unreachable, err = fn(t, tok)
			}
		}
		switch {
		case err == nil:
			done = true
			return true
		case ctx.Err() != nil:
			final = &ConnectionError{Err: ctx.Err()}
			return true
		case unreachable:
			sue.add(t.URL, err)
			return false
		default:
			final = err
			return true
		}
	})
	switch {
	case done:
		return nil
	case final != nil:
		return final
	case ctx.Err() != nil:
		return &ConnectionError{Err: ctx.Err()}
	}
	return sue
}

// Info returns a station's public information (GET /local/v1/info, no
// token needed). stationURL must be trusted like any station URL: a public
// hostname, or an IP with a fingerprint from the endpoint list, mDNS or
// LocalConfig.Fingerprints.
func (s *LocalService) Info(ctx context.Context, stationURL string) (*LocalInfo, error) {
	t, err := s.target(ctx, stationURL)
	if err != nil {
		return nil, err
	}
	var info LocalInfo
	unreachable, err := s.c.local.send(ctx, t, http.MethodGet, "/local/v1/info", nil, "", nil, &info, 0)
	if err != nil {
		if unreachable {
			sue := &StationUnreachableError{}
			sue.add(t.URL, err)
			return nil, sue
		}
		return nil, err
	}
	return &info, nil
}

// PairOption configures Local.Pair.
type PairOption func(*pairConfig)

type pairConfig struct{ fingerprint string }

// PairFingerprint passes the certificate fingerprint shown in the station
// app next to the pairing code.
func PairFingerprint(fp string) PairOption { return func(p *pairConfig) { p.fingerprint = fp } }

// Pair pairs this device with one station using the 8-digit code shown in
// the station app ("Pair a device"). The returned device token ("czd_…")
// works only on that station and without any cloud account; pass it as
// LocalConfig.Token.
//
// The station must be authenticated before the code is sent, or a device on
// the LAN could relay it: an IP URL needs the fingerprint shown in the
// station app (PairFingerprint, or LocalConfig.Fingerprints) or a cloud
// endpoint list containing that address; a hostname URL must be on the
// cloud endpoint list. mDNS is never enough.
func (s *LocalService) Pair(ctx context.Context, stationURL, code, deviceName string, opts ...PairOption) (*LocalPairing, error) {
	if len(code) != 8 || strings.Trim(code, "0123456789") != "" {
		return nil, invalidParams("code", "The pairing code is the 8 digits shown in the station app.")
	}
	var pc pairConfig
	for _, o := range opts {
		o(&pc)
	}
	if deviceName == "" {
		deviceName = s.c.local.cfg.DeviceName
	}
	t, err := s.pairTarget(ctx, stationURL, pc.fingerprint)
	if err != nil {
		return nil, err
	}
	var out LocalPairing
	unreachable, err := s.c.local.send(ctx, t, http.MethodPost, "/local/v1/pair", nil, "",
		map[string]any{"code": code, "device_name": truncateRunes(deviceName, 80)}, &out, 0)
	if err != nil {
		if unreachable {
			sue := &StationUnreachableError{}
			sue.add(t.URL, err)
			return nil, sue
		}
		return nil, err
	}
	if out.Token == "" {
		return nil, &APIError{Status: http.StatusCreated, Code: "invalid_response", Message: "The station answered without a token."}
	}
	return &out, nil
}

// pairTarget resolves trust for pairing without mDNS.
func (s *LocalService) pairTarget(ctx context.Context, stationURL, fp string) (stationTarget, error) {
	l := s.c.local
	u, err := normalizeStationURL(stationURL)
	if err != nil {
		return stationTarget{}, err
	}
	host, _ := urlHost(u)
	if fp != "" {
		if fp = normalizeFingerprint(fp); fp == "" {
			return stationTarget{}, invalidParams("fingerprint", "The fingerprint is the 64 hex characters (SHA-256) shown in the station app.")
		}
		if net.ParseIP(host) == nil {
			return stationTarget{}, invalidParams("url", "Pair with the station's IP address URL when you pass the fingerprint from the station app.")
		}
		return stationTarget{URL: u, Fingerprint: fp, TLSMode: "self_signed", Source: "config"}, nil
	}
	l.ensureLoaded(ctx)
	t := l.targetFor(u, "config", l.snapshot(), nil)
	if (t.needsPin() && t.Fingerprint == "") || (!t.needsPin() && t.StationID == "") {
		return stationTarget{}, invalidParams("fingerprint",
			"Pairing needs the certificate fingerprint shown in the station app (PairFingerprint), or a station on the cloud endpoint list.")
	}
	return t, nil
}

// target resolves trust for an explicit station URL, browsing mDNS once if
// an IP URL has no known fingerprint yet.
func (s *LocalService) target(ctx context.Context, stationURL string) (stationTarget, error) {
	l := s.c.local
	u, err := normalizeStationURL(stationURL)
	if err != nil {
		return stationTarget{}, err
	}
	l.ensureLoaded(ctx)
	st := l.snapshot()
	l.mu.Lock()
	mdns := l.mdns
	l.mu.Unlock()
	t := l.targetFor(u, "config", st, mdns)
	if t.needsPin() && t.Fingerprint == "" && l.cfg.Discover {
		if found, _ := l.browse(ctx, true); len(found) > 0 {
			t = l.targetFor(u, "config", st, found)
		}
	}
	return t, nil
}

// Discover lists stations from the cloud endpoint list (refreshed now when
// the cloud answers, otherwise the cached copy) and from an mDNS browse,
// merged by station ID. It doesn't need LocalConfig.Discover.
func (s *LocalService) Discover(ctx context.Context) ([]LocalStation, error) {
	l := s.c.local
	l.ensureLoaded(ctx)
	cloudErr := l.refresh(ctx, true)
	if ctx.Err() != nil {
		return nil, &ConnectionError{Err: ctx.Err()}
	}
	st := l.snapshot()
	found, mdnsErr := l.browse(ctx, true)
	if ctx.Err() != nil {
		return nil, &ConnectionError{Err: ctx.Err()}
	}
	var out []LocalStation
	idx := map[string]int{}
	if st != nil {
		for _, ep := range st.Stations {
			if l.cfg.LocationID != "" && ep.LocationID != "" && ep.LocationID != l.cfg.LocationID {
				continue
			}
			ls := LocalStation{
				StationID: ep.StationID, Name: ep.Name, LocationID: ep.LocationID, Port: ep.Port,
				Addresses: append([]string(nil), ep.Addresses...), TLSMode: ep.TLSMode,
				Fingerprint: normalizeFingerprint(ep.CertFingerprintSHA256), FromCloud: true,
				LocalEnabled: ep.LocalEnabled, Connected: ep.Connected, OrgID: l.orgHint(),
			}
			for _, t := range endpointTargets(ep, "cloud") {
				ls.URLs = append(ls.URLs, t.URL)
			}
			idx[ep.StationID] = len(out)
			out = append(out, ls)
		}
	}
	for _, d := range l.acceptedMDNS(found, st) {
		var urls []string
		for _, t := range mdnsTargets(d) {
			urls = append(urls, t.URL)
		}
		if i, ok := idx[d.StationID]; ok {
			ls := &out[i]
			ls.FromMDNS = true
			for _, a := range d.Addresses {
				if !containsStr(ls.Addresses, a) {
					ls.Addresses = append(ls.Addresses, a)
				}
			}
			for _, u := range urls {
				if !containsStr(ls.URLs, u) {
					ls.URLs = append(ls.URLs, u)
				}
			}
			continue
		}
		idx[d.StationID] = len(out)
		out = append(out, LocalStation{
			StationID: d.StationID, Name: d.Instance, OrgID: d.OrgID, LocationID: d.LocationID, Port: d.Port,
			Addresses: d.Addresses, URLs: urls, TLSMode: d.TLSMode, Fingerprint: d.Fingerprint,
			FromMDNS: true, LocalEnabled: true,
		})
	}
	if len(out) == 0 {
		if cloudErr != nil {
			return out, cloudErr
		}
		if mdnsErr != nil {
			return out, mdnsErr
		}
	}
	return out, nil
}

// Refresh renews the local token (when it has less than 7 days left) and
// re-reads the cloud endpoint list now. The SDK also does this by itself in
// the background, hourly while online; call Refresh at start-up or after
// network changes.
func (s *LocalService) Refresh(ctx context.Context) error {
	return s.c.local.refresh(ctx, true)
}

// Token returns the token the SDK uses for stations (minting one when
// needed), e.g. to hand to a browser POS that uses catzprint/local.
func (s *LocalService) Token(ctx context.Context) (string, error) {
	return s.c.local.token(ctx)
}

// StoreError returns the last error from the token store (nil if none).
// Store failures never stop printing; they only mean the token or endpoint
// list won't survive a restart.
func (s *LocalService) StoreError() error {
	l := s.c.local
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.storeErr
}
