package dnssd

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRemove(t *testing.T) {
	cfg := Config{
		Name: "Test",
		Type: "_asdf._tcp",
		Port: 1234,
	}

	si, err := NewService(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{SRV(si), TXT(si)}

	answers := []dns.RR{SRV(si), TXT(si), PTR(si)}
	unknown := remove(msg.Answer, answers)

	if x := len(unknown); x != 1 {
		t.Fatal(x)
	}

	rr := unknown[0]
	if _, ok := rr.(*dns.PTR); !ok {
		t.Fatal("Invalid type", rr)
	}
}

func TestRegisterServiceWithExplicitIP(t *testing.T) {
	testIface, _ = net.InterfaceByName("lo0")
	if testIface == nil {
		testIface, _ = net.InterfaceByName("lo")
	}

	if testIface == nil {
		t.Fatal("can not find the local interface")
	}

	cfg := Config{
		Host:   "Computer",
		Name:   "Test",
		Type:   "_asdf._tcp",
		Domain: "local",
		Port:   12345,
		Ifaces: []string{testIface.Name},
	}

	sv, err := NewService(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	sv.ifaceIPs = map[string][]net.IP{
		testIface.Name: {{192, 168, 0, 123}},
	}

	conn := newTestConn()
	otherConn := newTestConn()
	conn.in = otherConn.out
	conn.out = otherConn.in

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	go func() {
		r := newResponder(conn)
		r.addManaged(sv) // don't probe

		if resErr := r.Respond(ctx); resErr != nil {
			t.Error(resErr)
		}
	}()

	srv, err := lookupInstance(ctx, "Test._asdf._tcp.local.", otherConn)
	if err != nil {
		t.Fatal(err)
	}

	if is, want := srv.Name, "Test"; is != want {
		t.Fatalf("%v != %v", is, want)
	}

	if is, want := srv.Type, "_asdf._tcp"; is != want {
		t.Fatalf("%v != %v", is, want)
	}

	if is, want := srv.Host, "Computer"; is != want {
		t.Fatalf("%v != %v", is, want)
	}

	ips := srv.IPsAtInterface(&net.Interface{Name: "lo0"})
	if is, want := len(ips), 1; is != want {
		t.Fatalf("%v != %v", is, want)
	}

	if is, want := ips[0].String(), "192.168.0.123"; is != want {
		t.Fatalf("%v != %v", is, want)
	}
}
