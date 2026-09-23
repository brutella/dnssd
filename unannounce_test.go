package dnssd

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The goodbye packets for a service are sent on every one of its interfaces,
// twice, 250ms apart. The interfaces are independent, so the walk must take one
// 250ms gap in total — not one per interface, which on a host with many
// interfaces held a cancelled Respond for seconds before it closed its conn.
func TestUnannounceSendsGoodbyesOnAllInterfacesConcurrently(t *testing.T) {
	ifaces := MulticastInterfaces()
	if len(ifaces) == 0 {
		t.Skip("no up multicast interface on this host")
	}
	names := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		names = append(names, iface.Name)
	}
	sv, err := NewService(Config{
		Name:   "Goodbye",
		Type:   "_asdf._tcp",
		Domain: "local",
		Host:   "Computer",
		Port:   12345,
		Ifaces: names,
	})
	if err != nil {
		t.Fatal(err)
	}

	conn := newTestConn()
	sent := make(chan *dns.Msg, 4*len(ifaces))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			select {
			case msg := <-conn.out:
				sent <- msg
			case <-ctx.Done():
				return
			}
		}
	}()

	r := newResponder(conn)
	start := time.Now()
	r.unannounce([]*Service{&sv})
	elapsed := time.Since(start)

	want := 2 * len(ifaces)
	deadline := time.After(2 * time.Second)
	for got := 0; got < want; got++ {
		select {
		case msg := <-sent:
			if len(msg.Answer) == 0 || msg.Answer[0].Header().Ttl != 0 {
				t.Fatalf("goodbye must carry TTL 0 answers, got %v", msg)
			}
		case <-deadline:
			t.Fatalf("got %d of %d goodbye packets across %d interfaces", got, want, len(ifaces))
		}
	}
	// One gap for the whole walk. The sequential walk took 250ms × interfaces,
	// which this bound rejects for any host with more than two interfaces.
	if limit := 250*time.Millisecond + 300*time.Millisecond; elapsed > limit {
		t.Fatalf("unannounce over %d interfaces took %v, want < %v", len(ifaces), elapsed, limit)
	}
}
