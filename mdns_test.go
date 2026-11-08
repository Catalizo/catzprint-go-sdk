package catzprint

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type mdnsRR struct {
	name string
	body dnsmessage.ResourceBody
}

// buildResponse crafts an mDNS response with the given answers and
// additionals. Class carries the cache-flush bit like real responders.
func buildResponse(t *testing.T, answers, additionals []mdnsRR) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, Authoritative: true})
	b.EnableCompression()
	add := func(rr mdnsRR) {
		h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(rr.name), Class: dnsmessage.ClassINET | 0x8000, TTL: 120}
		var err error
		switch r := rr.body.(type) {
		case *dnsmessage.PTRResource:
			err = b.PTRResource(h, *r)
		case *dnsmessage.SRVResource:
			err = b.SRVResource(h, *r)
		case *dnsmessage.TXTResource:
			err = b.TXTResource(h, *r)
		case *dnsmessage.AResource:
			err = b.AResource(h, *r)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(h, *r)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, rr := range answers {
		add(rr)
	}
	if err := b.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	for _, rr := range additionals {
		add(rr)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func a4(s string) *dnsmessage.AResource {
	var r dnsmessage.AResource
	copy(r.A[:], net.ParseIP(s).To4())
	return &r
}

// mdnsAnswer is a complete station announcement as §4.8 describes it.
func mdnsAnswer(t *testing.T, name, id, org, loc string, port int, fp, ip string, extraTXT ...string) []byte {
	inst := name + " (CatzPrint)." + mdnsService
	host := "catzprint-" + id + ".local."
	// Extra entries go first: with duplicate keys the first one wins.
	txt := append(append([]string(nil), extraTXT...), "v=1", "id="+id, "org="+org, "loc="+loc, "port="+strconv.Itoa(port), "fp="+fp, "tls=self_signed", "host=")
	return buildResponse(t,
		[]mdnsRR{{mdnsService, &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(inst)}}},
		[]mdnsRR{
			{inst, &dnsmessage.SRVResource{Port: uint16(port), Target: dnsmessage.MustNewName(host)}},
			{inst, &dnsmessage.TXTResource{TXT: txt}},
			{host, a4(ip)},
			{host, &dnsmessage.AAAAResource{}},
		})
}

func TestMDNSQuery(t *testing.T) {
	q, err := buildMDNSQuery()
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		t.Fatal(err)
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 || qs[0].Type != dnsmessage.TypePTR || qs[0].Name.String() != mdnsService || qs[0].Class&0x8000 == 0 {
		t.Fatalf("query %+v %v", qs, err)
	}
}

func TestMDNSParse(t *testing.T) {
	fp := strings.Repeat("a1", 32)
	col := newMDNSCollector()
	col.add(mdnsAnswer(t, "Kitchen PC", "st1", "org1", "loc1", 7443, fp, "192.168.1.20"), net.ParseIP("192.168.1.20"))
	got := col.stations()
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	s := got[0]
	if s.Instance != "Kitchen PC (CatzPrint)" || s.StationID != "st1" || s.OrgID != "org1" || s.LocationID != "loc1" || s.Port != 7443 ||
		s.Fingerprint != fp || s.TLSMode != "self_signed" || len(s.Addresses) != 1 || s.Addresses[0] != "192.168.1.20" || s.Hostname != "" {
		t.Fatalf("parsed %+v", s)
	}
	urls := mdnsTargets(s)
	if len(urls) != 1 || urls[0].URL != "https://192.168.1.20:7443" || urls[0].Fingerprint != fp {
		t.Fatalf("targets %+v", urls)
	}
}

func TestMDNSParseSplitPacketsPublicHostAndSourceFallback(t *testing.T) {
	fp := strings.Repeat("0f", 32)
	inst := "Bar (CatzPrint)." + mdnsService
	col := newMDNSCollector()
	// PTR alone, then SRV+TXT in another packet without an A record: the
	// packet's source address is used.
	col.add(buildResponse(t, []mdnsRR{{mdnsService, &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName(inst)}}}, nil), net.ParseIP("10.0.0.9"))
	if len(col.stations()) != 0 {
		t.Fatal("incomplete announcement accepted")
	}
	col.add(buildResponse(t, []mdnsRR{
		{inst, &dnsmessage.SRVResource{Port: 7000, Target: dnsmessage.MustNewName("catzprint-st2.local.")}},
		{inst, &dnsmessage.TXTResource{TXT: []string{"v=1", "id=st2", "org=org1", "loc=loc1", "port=7443", "FP=" + strings.ToUpper(fp), "tls=public", "host=10-0-0-9.abcdefghij.local.catzprint.com"}}},
	}, nil), net.ParseIP("10.0.0.9"))
	got := col.stations()
	if len(got) != 1 || got[0].Port != 7443 || got[0].Fingerprint != fp || got[0].Addresses[0] != "10.0.0.9" {
		t.Fatalf("got %+v", got)
	}
	// The announced hostname is parsed but never becomes a target.
	ts := mdnsTargets(got[0])
	if len(ts) != 1 || ts[0].URL != "https://10.0.0.9:7443" || ts[0].Fingerprint != fp {
		t.Fatalf("targets %+v", ts)
	}
}

func TestMDNSParseRejectsBadAnnouncements(t *testing.T) {
	cases := map[string][]byte{
		"wrong version":     mdnsAnswer(t, "A", "st1", "o", "l", 7443, strings.Repeat("aa", 32), "192.168.1.2", "v=2"),
		"bad fingerprint":   mdnsAnswer(t, "B", "st1", "o", "l", 7443, "zz", "192.168.1.2"),
		"missing id":        mdnsAnswer(t, "C", "", "o", "l", 7443, strings.Repeat("aa", 32), "192.168.1.2"),
		"truncated garbage": mdnsAnswer(t, "D", "st1", "o", "l", 7443, strings.Repeat("aa", 32), "192.168.1.2")[:40],
		"not a response":    func() []byte { q, _ := buildMDNSQuery(); return q }(),
	}
	for name, msg := range cases {
		col := newMDNSCollector()
		col.add(msg, net.ParseIP("192.168.1.2"))
		if got := col.stations(); len(got) != 0 {
			t.Errorf("%s: accepted %+v", name, got)
		}
	}
	// An unrelated service's records are ignored.
	other := buildResponse(t, []mdnsRR{
		{"_http._tcp.local.", &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("x._http._tcp.local.")}},
		{"x._http._tcp.local.", &dnsmessage.TXTResource{TXT: []string{"v=1", "id=evil"}}},
		{"x._http._tcp.local.", &dnsmessage.SRVResource{Port: 80, Target: dnsmessage.MustNewName("x.local.")}},
	}, nil)
	col := newMDNSCollector()
	col.add(other, net.ParseIP("192.168.1.3"))
	if len(col.stations()) != 0 {
		t.Fatal("foreign service accepted")
	}
}

// startFakeResponder answers every query with reply, unicast to the sender
// (what a responder does for a QU / legacy-unicast query).
func startFakeResponder(t *testing.T, reply []byte) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			if _, err := p.Start(buf[:n]); err != nil {
				continue
			}
			qs, err := p.AllQuestions()
			if err != nil || len(qs) != 1 || qs[0].Name.String() != mdnsService {
				continue
			}
			_, _ = conn.WriteToUDP(reply, from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

func TestMDNSBrowse(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	addr := startFakeResponder(t, mdnsAnswer(t, "Kitchen PC", "st1", "org1", "loc1", 7443, fp, "192.168.1.20"))
	start := time.Now()
	got, err := mdnsBrowse(context.Background(), 300*time.Millisecond, addr)
	if err != nil || len(got) != 1 || got[0].StationID != "st1" {
		t.Fatalf("got %+v %v", got, err)
	}
	if el := time.Since(start); el < 250*time.Millisecond || el > 2*time.Second {
		t.Fatalf("browse took %v", el)
	}
	// Cancellation ends the browse early.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start = time.Now()
	_, err = mdnsBrowse(ctx, 5*time.Second, addr)
	if !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatalf("cancel: %v after %v", err, time.Since(start))
	}
}

func TestMDNSDiscoveredStationIsUsedWithItsFingerprint(t *testing.T) {
	st := newFakeStation(t, nil)
	port, _ := strconv.Atoi(st.url[strings.LastIndex(st.url, ":")+1:])
	resp := startFakeResponder(t, mdnsAnswer(t, "Kitchen PC", "st1", "org1", "loc1", port, st.fp, "127.0.0.1"))
	// The cloud is unreachable and the endpoint list was never fetched: an
	// announcement alone is not trusted, even with a fingerprint.
	offline := &fakeCloud{srv: &httptest.Server{}}
	c0 := newLocalClient(t, offline, LocalConfig{Mode: ModeLocal, LocationID: "loc1", Discover: true, DiscoverTimeout: 200 * time.Millisecond, Token: "czd_paired"})
	c0.local.mdnsAddr = resp
	if _, err := c0.Jobs.Create(context.Background(), JobParams{Text: "x"}); !IsStationUnreachable(err) || len(st.requests()) != 0 {
		t.Fatalf("unverified mDNS station used: %v", err)
	}
	// With the fingerprint from the station app configured, mDNS maps it to
	// the station's current address.
	pins := map[string]string{"kitchen-pc": st.fp}
	c := newLocalClient(t, offline, LocalConfig{Mode: ModeLocal, LocationID: "loc1", Discover: true, DiscoverTimeout: 200 * time.Millisecond, Token: "czd_paired", Fingerprints: pins})
	c.local.mdnsAddr = resp
	job, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	if err != nil || job.Local.StationURL != st.url || !job.Live {
		t.Fatalf("got %v %v", job, err)
	}
	// A wrong org or location is ignored.
	for _, ann := range [][]byte{
		mdnsAnswer(t, "Other org", "st1", "org2", "loc1", port, st.fp, "127.0.0.1"),
		mdnsAnswer(t, "Other loc", "st1", "org1", "loc2", port, st.fp, "127.0.0.1"),
	} {
		c2 := newLocalClient(t, offline, LocalConfig{Mode: ModeLocal, LocationID: "loc1", Discover: true, DiscoverTimeout: 150 * time.Millisecond, Token: "czd_paired", Fingerprints: pins})
		c2.local.mdnsAddr = startFakeResponder(t, ann)
		if _, err := c2.Jobs.Create(context.Background(), JobParams{Text: "x"}); !IsStationUnreachable(err) {
			t.Fatalf("foreign station used: %v", err)
		}
	}
}

func TestMDNSUnknownStationIgnoredOnceEndpointListKnown(t *testing.T) {
	fc := newFakeCloud(t)
	st := newFakeStation(t, nil)
	port, _ := strconv.Atoi(st.url[strings.LastIndex(st.url, ":")+1:])
	// The cloud lists st1 only; an impostor announces "st666" with its own
	// certificate (here: the fake station's) on the LAN.
	fc.stations = []LocalEndpoint{{StationID: "st1", LocalEnabled: true, URLs: []string{deadURL(t)}, CertFingerprintSHA256: strings.Repeat("cd", 32)}}
	c := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, Discover: true, DiscoverTimeout: 150 * time.Millisecond})
	c.local.mdnsAddr = startFakeResponder(t, mdnsAnswer(t, "Impostor", "st666", "org1", "loc1", port, st.fp, "127.0.0.1"))
	_, err := c.Jobs.Create(context.Background(), JobParams{Text: "x"})
	if !IsStationUnreachable(err) || len(st.requests()) != 0 {
		t.Fatalf("impostor used: %v (requests %d)", err, len(st.requests()))
	}
	// The listed station announcing a new address is used, pinned with the
	// fingerprint from the list (which here doesn't match: rejected).
	c2 := newLocalClient(t, fc, LocalConfig{Mode: ModeLocal, Discover: true, DiscoverTimeout: 150 * time.Millisecond})
	c2.local.mdnsAddr = startFakeResponder(t, mdnsAnswer(t, "Kitchen", "st1", "org1", "loc1", port, st.fp, "127.0.0.1"))
	_, err = c2.Jobs.Create(context.Background(), JobParams{Text: "x"})
	var pm *PinMismatchError
	if !IsStationUnreachable(err) || !errors.As(err.(*StationUnreachableError).Attempts[1].Err, &pm) || len(st.requests()) != 0 {
		t.Fatalf("want pin mismatch on the mDNS address, got %v", err)
	}
}
