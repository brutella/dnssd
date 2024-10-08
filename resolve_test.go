package dnssd

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestRegisterServiceWithSpecialName(t *testing.T) {
	cfg := Config{
		Host:   "Computer",
		Name:   "Test With Spaces",
		Type:   "_asdf._tcp",
		Domain: "local",
		Port:   12345,
		Ifaces: []string{"lo0"},
	}
	sv, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sv.ifaceIPs = map[string][]net.IP{
		"lo0": []net.IP{net.IP{192, 168, 0, 123}},
	}

	conn := newTestConn()
	otherConn := newTestConn()
	conn.in = otherConn.out
	conn.out = otherConn.in

	ctx, cancel := context.WithCancel(context.Background())
	t.Run("resolver", func(t *testing.T) {
		t.Parallel()

		lookupCtx, lookupCancel := context.WithTimeout(ctx, 5*time.Second)

		defer lookupCancel()
		defer cancel()

		srv, err := lookupInstance(lookupCtx, "Test With Spaces._asdf._tcp.local.", otherConn)
		if err != nil {
			t.Fatal(err)
		}

		if is, want := srv.Name, "Test With Spaces"; is != want {
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
	})

	t.Run("responder", func(t *testing.T) {
		t.Parallel()

		r := newResponder(conn)
		r.addManaged(sv) // don't probe
		r.Respond(ctx)
	})
}
