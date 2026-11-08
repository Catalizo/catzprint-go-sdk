package catzprint

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// mdnsService is the DNS-SD service type stations advertise.
const mdnsService = "_catzprint._tcp.local."

var mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// mdnsStation is one station as announced over mDNS.
type mdnsStation struct {
	Instance    string
	StationID   string
	OrgID       string
	LocationID  string
	Port        int
	Fingerprint string
	TLSMode     string
	Hostname    string // TXT host: public-cert hostname, may be empty
	Addresses   []string
}

// buildMDNSQuery builds a PTR query for the CatzPrint service with the
// unicast-response (QU) bit set.
func buildMDNSQuery() ([]byte, error) {
	name, err := dnsmessage.NewName(mdnsService)
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 64), dnsmessage.Header{})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET | 0x8000}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// mdnsCollector accumulates records from any number of responses.
type mdnsCollector struct {
	ptr  map[string]bool                   // instance names (lower case)
	srv  map[string]dnsmessage.SRVResource // instance -> SRV
	txt  map[string]map[string]string      // instance -> TXT key/values
	addr map[string][]string               // host (lower case) -> IPv4s
	src  map[string]string                 // instance -> source IP of the packet
	name map[string]string                 // instance lower -> instance as sent
}

func newMDNSCollector() *mdnsCollector {
	return &mdnsCollector{
		ptr: map[string]bool{}, srv: map[string]dnsmessage.SRVResource{}, txt: map[string]map[string]string{},
		addr: map[string][]string{}, src: map[string]string{}, name: map[string]string{},
	}
}

func isServiceInstance(n string) bool {
	return strings.HasSuffix(n, "."+mdnsService) && len(n) > len(mdnsService)+1
}

// Bounds on what a collector keeps, so a flood of announcements can't grow
// memory without limit.
const (
	mdnsMaxInstances = 256
	mdnsMaxHosts     = 256
	mdnsMaxAddrs     = 32
)

// roomFor reports whether instance name can be added (known, or under the cap).
func (c *mdnsCollector) roomFor(name string) bool {
	if _, ok := c.name[name]; ok {
		return true
	}
	return len(c.name) < mdnsMaxInstances
}

// add parses one mDNS response packet. Malformed packets and unrelated
// records are ignored.
func (c *mdnsCollector) add(msg []byte, from net.IP) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	src := ""
	if v4 := from.To4(); v4 != nil {
		src = v4.String()
	}
	section := func(next func() (dnsmessage.ResourceHeader, error), skip func() error) bool {
		for {
			rh, err := next()
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				return true
			}
			if err != nil {
				return false
			}
			name := strings.ToLower(rh.Name.String())
			switch rh.Type {
			case dnsmessage.TypePTR:
				r, err := p.PTRResource()
				if err != nil {
					return false
				}
				if name == mdnsService {
					inst := r.PTR.String()
					if isServiceInstance(strings.ToLower(inst)) && c.roomFor(strings.ToLower(inst)) {
						c.ptr[strings.ToLower(inst)] = true
						c.name[strings.ToLower(inst)] = inst
					}
				}
			case dnsmessage.TypeSRV:
				r, err := p.SRVResource()
				if err != nil {
					return false
				}
				if isServiceInstance(name) && c.roomFor(name) {
					c.srv[name] = r
					c.name[name] = rh.Name.String()
					if src != "" {
						c.src[name] = src
					}
				}
			case dnsmessage.TypeTXT:
				r, err := p.TXTResource()
				if err != nil {
					return false
				}
				if isServiceInstance(name) && c.roomFor(name) {
					kv := map[string]string{}
					for _, s := range r.TXT {
						k, v, _ := strings.Cut(s, "=")
						k = strings.ToLower(strings.TrimSpace(k))
						if k != "" {
							if _, dup := kv[k]; !dup { // RFC 6763: first one wins
								kv[k] = v
							}
						}
					}
					c.txt[name] = kv
					c.name[name] = rh.Name.String()
					if src != "" {
						c.src[name] = src
					}
				}
			case dnsmessage.TypeA:
				r, err := p.AResource()
				if err != nil {
					return false
				}
				ip := net.IP(r.A[:]).String()
				_, known := c.addr[name]
				if (known || len(c.addr) < mdnsMaxHosts) && len(c.addr[name]) < mdnsMaxAddrs && !containsStr(c.addr[name], ip) {
					c.addr[name] = append(c.addr[name], ip)
				}
			default:
				if err := skip(); err != nil {
					return false
				}
			}
		}
	}
	if !section(p.AnswerHeader, p.SkipAnswer) {
		return
	}
	if err := p.SkipAllAuthorities(); err != nil {
		return
	}
	section(p.AdditionalHeader, p.SkipAdditional)
}

// stations returns every complete, valid station seen so far, sorted by
// instance name.
func (c *mdnsCollector) stations() []mdnsStation {
	var names []string
	for n := range c.txt {
		if _, ok := c.srv[n]; ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var out []mdnsStation
	for _, n := range names {
		kv := c.txt[n]
		srv := c.srv[n]
		if kv["v"] != "1" || kv["id"] == "" {
			continue
		}
		port := int(srv.Port)
		if p, err := strconv.Atoi(kv["port"]); err == nil && p > 0 && p < 65536 {
			port = p
		}
		if port <= 0 {
			continue
		}
		fp := normalizeFingerprint(kv["fp"])
		if kv["fp"] != "" && fp == "" {
			continue // malformed fingerprint: ignore the whole announcement
		}
		st := mdnsStation{
			Instance:    strings.TrimSuffix(c.name[n], "."+mdnsService),
			StationID:   kv["id"],
			OrgID:       kv["org"],
			LocationID:  kv["loc"],
			Port:        port,
			Fingerprint: fp,
			TLSMode:     kv["tls"],
			Hostname:    strings.ToLower(strings.TrimSuffix(kv["host"], ".")),
		}
		for _, ip := range c.addr[strings.ToLower(srv.Target.String())] {
			if !containsStr(st.Addresses, ip) {
				st.Addresses = append(st.Addresses, ip)
			}
		}
		if len(st.Addresses) == 0 && c.src[n] != "" {
			st.Addresses = []string{c.src[n]}
		}
		out = append(out, st)
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// mdnsBrowse sends a query to dst (the mDNS group, or a unicast address in
// tests) and collects answers until timeout or ctx ends. It returns what it
// found; all its goroutines and sockets are gone when it returns.
func mdnsBrowse(ctx context.Context, timeout time.Duration, dst *net.UDPAddr) ([]mdnsStation, error) {
	query, err := buildMDNSQuery()
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	conns := []*net.UDPConn{conn}
	multicast := dst.IP.IsMulticast()
	if multicast {
		// Responders that ignore the QU bit answer to the group: listen
		// there too when the port can be shared (it can't always be).
		if mc, err := net.ListenMulticastUDP("udp4", nil, mdnsGroup); err == nil {
			conns = append(conns, mc)
		}
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	for _, cn := range conns {
		_ = cn.SetReadDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() {
		for _, cn := range conns {
			_ = cn.SetReadDeadline(time.Now())
		}
	})

	send := func() {
		if !multicast {
			_, _ = conn.WriteToUDP(query, dst)
			return
		}
		pc := ipv4.NewPacketConn(conn)
		_ = pc.SetMulticastTTL(255)
		sent := false
		ifaces, _ := net.Interfaces()
		for i := range ifaces {
			ifi := &ifaces[i]
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
				continue
			}
			if !hasIPv4(ifi) {
				continue
			}
			if err := pc.SetMulticastInterface(ifi); err != nil {
				continue
			}
			if _, err := pc.WriteTo(query, nil, dst); err == nil {
				sent = true
			}
		}
		if !sent {
			_, _ = conn.WriteToUDP(query, dst)
		}
	}
	send()

	col := newMDNSCollector()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, cn := range conns {
		wg.Add(1)
		go func(cn *net.UDPConn) {
			defer wg.Done()
			buf := make([]byte, 9000)
			for {
				n, from, err := cn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				mu.Lock()
				col.add(buf[:n], from.IP)
				mu.Unlock()
			}
		}(cn)
	}
	// One resend shortly after the first query: UDP may drop packets.
	resend := time.NewTimer(min(300*time.Millisecond, timeout/3))
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-resend.C:
		send()
		<-done
	case <-done:
		resend.Stop()
	}
	stop()
	for _, cn := range conns {
		_ = cn.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if err := ctx.Err(); err != nil {
		return col.stations(), err
	}
	return col.stations(), nil
}

func hasIPv4(ifi *net.Interface) bool {
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			return true
		}
	}
	return false
}
