package dnssd

import (
	"testing"
	"time"
)

func TestEarliestExpirationEmpty(t *testing.T) {
	c := NewCache()
	exp := c.EarliestExpiration()
	if !exp.IsZero() {
		t.Errorf("expected zero time for empty cache, got %v", exp)
	}
}

func TestEarliestExpirationTracking(t *testing.T) {
	c := NewCache()

	later := time.Now().Add(10 * time.Second)
	sooner := time.Now().Add(5 * time.Second)

	s1 := newService("Test1._test._tcp.local.")
	s1.expiration = later
	c.services["t1"] = s1
	c.updateEarliestExpiry(s1.expiration)

	if !c.EarliestExpiration().Equal(later) {
		t.Errorf("expected earliest to be %v, got %v", later, c.EarliestExpiration())
	}

	s2 := newService("Test2._test._tcp.local.")
	s2.expiration = sooner
	c.services["t2"] = s2
	c.updateEarliestExpiry(s2.expiration)

	if !c.EarliestExpiration().Equal(sooner) {
		t.Errorf("expected earliest to be %v (sooner), got %v", sooner, c.EarliestExpiration())
	}
}

func TestEarliestExpirationRecalcOnRemove(t *testing.T) {
	c := NewCache()

	s1 := newService("ServiceOne._test._tcp.local.")
	s1.expiration = time.Now().Add(-1 * time.Second) // already expired
	c.services["svc1"] = s1
	c.updateEarliestExpiry(s1.expiration)

	s2 := newService("ServiceTwo._test._tcp.local.")
	s2.expiration = time.Now().Add(10 * time.Second)
	c.services["svc2"] = s2
	c.updateEarliestExpiry(s2.expiration)

	if len(c.services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(c.services))
	}

	c.removeExpired()

	if len(c.services) != 1 {
		t.Fatalf("expected 1 service after removal, got %d", len(c.services))
	}

	// earliest should be s2 (the only remaining service)
	if c.EarliestExpiration().IsZero() {
		t.Error("earliest should not be zero with one service remaining")
	}

	remaining := time.Until(c.EarliestExpiration())
	if remaining < 9*time.Second || remaining > 11*time.Second {
		t.Errorf("expected ~10s remaining, got %v", remaining)
	}
}

func TestEarliestExpirationAllRemoved(t *testing.T) {
	c := NewCache()

	s1 := newService("Gone._test._tcp.local.")
	s1.expiration = time.Now().Add(-1 * time.Second)
	c.services["gone"] = s1
	c.updateEarliestExpiry(s1.expiration)

	c.removeExpired()

	if !c.EarliestExpiration().IsZero() {
		t.Error("earliest should be zero after all services removed")
	}
	if len(c.services) != 0 {
		t.Errorf("expected 0 services, got %d", len(c.services))
	}
}
