package dnssd

import (
	"context"
	"github.com/brutella/dnssd/log"
	"github.com/miekg/dns"
)

// LookupInstance resolves a service by its service instance name.
func LookupInstance(ctx context.Context, instance string) (Service, error) {
	var srv Service

	conn, err := NewMDNSConn()
	if err != nil {
		return srv, err
	}

	return lookupInstance(ctx, instance, conn)
}

func lookupInstance(ctx context.Context, instance string, conn MDNSConn) (srv Service, err error) {
	var cache = NewCache()

	m := new(dns.Msg)

	srvQ := dns.Question{instance, dns.TypeSRV, dns.ClassINET}
	txtQ := dns.Question{instance, dns.TypeTXT, dns.ClassINET}
	setQuestionUnicast(&srvQ)
	setQuestionUnicast(&txtQ)

	m.Question = []dns.Question{srvQ, txtQ}

	readCtx, readCancel := context.WithCancel(ctx)
	defer readCancel()

	ch := conn.Read(readCtx)

	qs := make(chan *Query)
	go func() {
		for _, iface := range multicastInterfaces() {
			iface := iface
			q := &Query{msg: m, iface: iface}
			qs <- q
		}
	}()

	for {
		select {
		case q := <-qs:
			if err := conn.SendQuery(q); err != nil {
				log.Info.Println(err)
			}
		case req := <-ch:
			cache.UpdateFrom(req.msg, req.iface)
			if s, ok := cache.services[instance]; ok {
				srv = *s
				return
			}
		case <-ctx.Done():
			err = ctx.Err()
			return
		}
	}

	return
}
