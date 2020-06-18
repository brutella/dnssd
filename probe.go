package dnssd

import (
	"context"
	"fmt"
	"github.com/brutella/dnssd/log"
	"github.com/miekg/dns"
	"math/rand"
	"net"
	"strings"
	"time"
)

// ProbeService probes for the hostname and service instance name of srv.
// If err == nil, the returned service is verified to be unique on the local network.
func ProbeService(ctx context.Context, srv Service) (Service, error) {
	conn, err := newMDNSConn()

	if err != nil {
		return srv, err
	}

	defer conn.close()

	// After one minute of probing, if the Multicast DNS responder has been
	// unable to find any unused name, it should log an error (RFC6762 9)
	probeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// When ready to send its Multicast DNS probe packet(s) the host should
	// first wait for a short random delay time, uniformly distributed in
	// the range 0-250 ms. (RFC6762 8.1)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	delay := time.Duration(r.Intn(250)) * time.Millisecond
	log.Debug.Println("Probing delay", delay)
	time.Sleep(delay)

	return probeService(probeCtx, conn, srv, 1*time.Millisecond, false)
}

func ReprobeService(ctx context.Context, srv Service) (Service, error) {
	conn, err := newMDNSConn()

	if err != nil {
		return srv, err
	}

	defer conn.close()
	return probeService(ctx, conn, srv, 1*time.Millisecond, true)
}

func probeService(ctx context.Context, conn MDNSConn, srv Service, delay time.Duration, probeOnce bool) (s Service, e error) {
	candidate := srv.Copy()
	prevConflict := probeConflict{}

	// Keep track of the number of conflicts
	numHostConflicts := 0
	numNameConflicts := 0

	for i := 1; i <= 100; i++ {
		conflict, err := probe(ctx, conn, *candidate)
		if err != nil {
			e = err
			return
		}

		if conflict.hasNone() {
			s = *candidate
			return
		}

		candidate = candidate.Copy()

		if conflict.hostname && (prevConflict.hostname || probeOnce) {
			numHostConflicts++
			candidate.Host = fmt.Sprintf("%s-%d", srv.Host, numHostConflicts+1)
			conflict.hostname = false
		}

		if conflict.serviceName && (prevConflict.serviceName || probeOnce) {
			numNameConflicts++
			candidate.Name = fmt.Sprintf("%s-%d", srv.Name, numNameConflicts+1)
			conflict.serviceName = false
		}

		prevConflict = conflict

		if conflict.hasAny() {
			// If the host finds that its own data is lexicographically earlier,
			// then it defers to the winning host by waiting one second,
			// and then begins probing for this record again. (RFC6762 8.2)
			log.Debug.Println("Increase wait time after receiving conflicting data")
			delay = 1 * time.Second
		} else {
			delay = 250 * time.Millisecond
		}

		log.Debug.Println("Probing wait", delay)
		time.Sleep(delay)
	}

	return
}

func probe(ctx context.Context, conn MDNSConn, service Service) (conflict probeConflict, err error) {
	for _, iface := range service.Interfaces() {
		log.Debug.Printf("Probing at %s\n", iface.Name)
		conflict, err := probeAtInterface(ctx, conn, service, iface)
		if conflict.hasAny() {
			return conflict, err
		}
	}

	return probeConflict{}, nil
}

func probeAtInterface(ctx context.Context, conn MDNSConn, service Service, iface net.Interface) (conflict probeConflict, err error) {

	msg := new(dns.Msg)

	instanceQ := dns.Question{
		Name:   service.ServiceInstanceName(),
		Qtype:  dns.TypeANY,
		Qclass: dns.ClassINET,
	}

	hostQ := dns.Question{
		Name:   service.Hostname(),
		Qtype:  dns.TypeANY,
		Qclass: dns.ClassINET,
	}

	// TODO Responses to probe should be unicast
	// setQuestionUnicast(&instanceQ)
	// setQuestionUnicast(&hostQ)

	msg.Question = []dns.Question{instanceQ, hostQ}

	srv := SRV(service)
	as := A(service, iface)
	aaaas := AAAA(service, iface)

	var authority = []dns.RR{srv}
	for _, a := range as {
		authority = append(authority, a)
	}
	for _, aaaa := range aaaas {
		authority = append(authority, aaaa)
	}
	msg.Ns = authority

	readCtx, readCancel := context.WithCancel(ctx)
	defer readCancel()

	// Multicast DNS responses received *before* the first probe packet is sent
	// MUST be silently ignored. (RFC6762 8.1)
	conn.Drain(readCtx)
	ch := conn.Read(readCtx)

	queryTime := time.After(1 * time.Millisecond)
	queriesCount := 1

	for {
		select {
		case req := <-ch:
			if req.iface.Name != iface.Name {
				log.Debug.Println("Ignore msg from", req.iface.Name)
				break
			}

			answers := filterRecords(req.msg, &service)
			reqAs, reqAAAAs, reqSRVs := splitRecords(answers)

			if len(reqAs) > 0 && !equalAs(reqAs, as) {
				log.Debug.Printf("%v:%d@%s denies A\n", req.from.IP, req.from.Port, req.iface.Name)
				log.Debug.Printf("%v != %v\n", reqAs, as)
				conflict.hostname = true
			} else if len(reqAAAAs) > 0 && !equalAAAAs(reqAAAAs, aaaas) {
				log.Debug.Printf("%v:%d@%s denies AAAA\n", req.from.IP, req.from.Port, req.iface.Name)
				log.Debug.Printf("%v != %v\n", reqAAAAs, aaaas)
				conflict.hostname = true
			}

			for _, reqSRV := range reqSRVs {
				if isDenyingSRV(reqSRV, srv) {
					conflict.serviceName = true
				}
			}

		case <-ctx.Done():
			err = ctx.Err()
			return

		case <-queryTime:
			// Stop on conflict
			if conflict.hasAny() {
				return
			}

			// Stop after 3 probe queries
			if queriesCount > 3 {
				return
			}

			queriesCount++
			log.Debug.Println("Sending probe", msg)
			q := &Query{msg: msg, iface: &iface}
			conn.SendQuery(q)

			delay := 250 * time.Millisecond
			log.Debug.Println("Waiting for conflicting data", delay)
			queryTime = time.After(delay)
		}
	}

	return
}

type probeConflict struct {
	hostname    bool
	serviceName bool
}

func (pr probeConflict) hasNone() bool {
	return !pr.hostname && !pr.serviceName
}

func (pr probeConflict) hasAny() bool {
	return pr.hostname || pr.serviceName
}

func isDenyingA(this *dns.A, that *dns.A) bool {
	if strings.EqualFold(this.Hdr.Name, that.Hdr.Name) {
		log.Debug.Println("Same hosts")

		if !isValidRR(this) {
			log.Debug.Println("Invalid record produces conflict")
			return true
		}

		switch compareIP(this.A.To4(), that.A.To4()) {
		case -1:
			log.Debug.Println("Lexicographical earlier")
			break
		case 1:
			log.Debug.Println("Lexicographical later")
			return true
		default:
			log.Debug.Println("No conflict")
			break
		}
	}

	return false
}

// isDenyingAAAA returns true if this denies that.
func isDenyingAAAA(this *dns.AAAA, that *dns.AAAA) bool {
	if strings.EqualFold(this.Hdr.Name, that.Hdr.Name) {
		log.Debug.Println("Same hosts")
		if !isValidRR(this) {
			log.Debug.Println("Invalid record produces conflict")
			return true
		}

		switch compareIP(this.AAAA.To16(), that.AAAA.To16()) {
		case -1:
			log.Debug.Println("Lexicographical earlier")
			break
		case 1:
			log.Debug.Println("Lexicographical later")
			return true
		default:
			log.Debug.Println("No conflict")
			break
		}
	}

	return false
}

func equalAs(this []*dns.A, that []*dns.A) bool {
	var tmp = that
	for _, ti := range this {
		var found = false
		for i, ta := range tmp {
			if compareIP(ti.A.To4(), ta.A.To4()) == 0 {
				tmp = append(tmp[:i], tmp[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return len(tmp) == 0
}

func equalAAAAs(this []*dns.AAAA, that []*dns.AAAA) bool {
	var tmp = that
	for _, ti := range this {
		var found = false
		for i, ta := range tmp {
			if compareIP(ti.AAAA.To16(), ta.AAAA.To16()) == 0 {
				tmp = append(tmp[:i], tmp[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return len(tmp) == 0
}

func containedInAs(this *dns.A, aaas []*dns.A) bool {
	for _, that := range aaas {
		if strings.EqualFold(this.Hdr.Name, that.Hdr.Name) {
			if !isValidRR(this) {
				log.Debug.Println("Invalid record produces conflict")
				return false
			}

			if compareIP(this.A.To4(), that.A.To4()) == 0 {
				return true
			}
		}
	}

	return false
}

func containedInAAAAs(this *dns.AAAA, aaas []*dns.AAAA) bool {
	for _, that := range aaas {
		if strings.EqualFold(this.Hdr.Name, that.Hdr.Name) {
			if !isValidRR(this) {
				log.Debug.Println("Invalid record produces conflict")
				return false
			}

			if compareIP(this.AAAA.To16(), that.AAAA.To16()) == 0 {
				return true
			}
		}
	}

	return false
}

// isDenyingSRV returns true if this denies that.
func isDenyingSRV(this *dns.SRV, that *dns.SRV) bool {
	if strings.EqualFold(this.Hdr.Name, that.Hdr.Name) {
		log.Debug.Println("Same SRV")
		if !isValidRR(this) {
			log.Debug.Println("Invalid record produces conflict")
			return true
		}

		switch compareSRV(this, that) {
		case -1:
			log.Debug.Println("Lexicographical earlier")
			break
		case 1:
			log.Debug.Println("Lexicographical later")
			return true
		default:
			log.Debug.Println("No conflict")
			break
		}
	}

	return false
}

func isValidRR(rr dns.RR) bool {
	switch r := rr.(type) {
	case *dns.A:
		return !net.IPv4zero.Equal(r.A)
	case *dns.AAAA:
		return !net.IPv6zero.Equal(r.AAAA)
	case *dns.SRV:
		return len(r.Target) > 0 && r.Port != 0
	default:
		break
	}

	return true
}

func compareIP(this net.IP, that net.IP) int {
	count := len(this)
	if count > len(that) {
		count = len(that)
	}

	for i := 0; i < count; i++ {
		if this[i] < that[i] {
			return -1
		} else if this[i] > that[i] {
			return 1
		}
	}

	if len(this) < len(that) {
		return -1
	} else if len(this) > len(that) {
		return 1
	}
	return 0
}

func compareSRV(this *dns.SRV, that *dns.SRV) int {
	if this.Priority < that.Priority {
		return -1
	} else if this.Priority > that.Priority {
		return 1
	}

	if this.Weight < that.Weight {
		return -1
	} else if this.Weight > that.Weight {
		return 1
	}

	if this.Port < that.Port {
		return -1
	} else if this.Port > that.Port {
		return 1
	}

	return strings.Compare(this.Target, that.Target)
}
