package dnssd

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

type browseConn struct {
	read chan *Request
}

func (c *browseConn) SendQuery(*Query) error               { return nil }
func (c *browseConn) SendResponse(*Response) error         { return nil }
func (c *browseConn) Read(context.Context) <-chan *Request { return c.read }
func (c *browseConn) Drain(context.Context)                {}
func (c *browseConn) Close()                               {}

// A probing host announces its records in the authority section of a query:
// SRV, A and AAAA, but no TXT (RFC 6762 8.1). The TXT record follows in the
// response. LookupType must deliver it, even though the instance was already
// reported when the probe was received.
func TestLookupTypeDeliversTXTArrivingAfterFirstSighting(t *testing.T) {
	svc, err := NewService(Config{
		Name: "TestInstance",
		Type: "_test._tcp",
		Host: "testhost",
		Port: 12345,
		IPs:  []net.IP{net.ParseIP("192.168.1.10")},
		Text: map[string]string{"id": "abc123"},
	})
	if err != nil {
		t.Fatal(err)
	}

	iface := &net.Interface{Name: "lo0"}

	probe := new(dns.Msg)
	probe.Ns = []dns.RR{SRV(svc)}
	for _, rr := range A(svc, iface) {
		probe.Ns = append(probe.Ns, rr)
	}

	announce := new(dns.Msg)
	announce.Answer = []dns.RR{SRV(svc), PTR(svc), TXT(svc)}
	for _, rr := range A(svc, iface) {
		announce.Answer = append(announce.Answer, rr)
	}

	conn := &browseConn{read: make(chan *Request)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var entries []BrowseEntry
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = lookupType(ctx, svc.ServiceName(), conn,
			func(e BrowseEntry) { entries = append(entries, e) },
			func(BrowseEntry) {},
		)
	}()

	conn.read <- &Request{msg: probe, iface: iface}
	conn.read <- &Request{msg: announce, iface: iface}
	// The send below only returns once lookupType received it, which means
	// both messages above have been fully processed.
	conn.read <- &Request{msg: new(dns.Msg), iface: iface}

	cancel()
	<-done

	if len(entries) < 2 {
		t.Fatalf("add called %d time(s); TXT arriving after the first sighting was not delivered", len(entries))
	}
	if got := entries[len(entries)-1].Text["id"]; got != "abc123" {
		t.Fatalf("last delivered TXT id = %q, want %q", got, "abc123")
	}
}

func TestUniqueIPs(t *testing.T) {
	ip := net.ParseIP("192.168.1.10")
	ips := uniqueIPs([]net.IP{ip, net.ParseIP("fe80::1"), ip})

	if len(ips) != 2 {
		t.Fatalf("uniqueIPs returned %d addresses, want 2", len(ips))
	}
}
