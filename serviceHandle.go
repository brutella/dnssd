package dnssd

import (
	"net"
	"time"

	"github.com/brutella/dnssd/log"
	"github.com/miekg/dns"
)

// ServiceHandle serves a middleman between a service and a responder.
type ServiceHandle interface {
	UpdateText(text map[string]string, r Responder)
	Service() *Service
}

type serviceHandle struct {
	service *Service
}

func (h *serviceHandle) UpdateText(text map[string]string, r Responder) {
	h.service.Text = text

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{TXT(h.service)}
	msg.Response = true
	msg.Authoritative = true

	setAnswerCacheFlushBit(msg)

	resp := &Response{msg: msg}

	rr := r.(*responder)

	if err := rr.conn.SendResponse(resp); err != nil {
		log.Debug.Printf("Failed to send 1st update text response: %s\n", err)
	}

	time.Sleep(1 * time.Second)

	if err := rr.conn.SendResponse(resp); err != nil {
		log.Debug.Printf("Failed to send 2nd update text response: %s\n", err)
	}

	log.Debug.Println("Reannounce TXT", text)
}

func (h *serviceHandle) Service() *Service {
	return h.service
}

func (h *serviceHandle) IPv4s() []net.IP {
	var result []net.IP

	for _, ip := range h.service.IPs {
		if ip.To4() != nil {
			result = append(result, ip)
		}
	}

	return result
}

func (h *serviceHandle) IPv6s() []net.IP {
	var result []net.IP

	for _, ip := range h.service.IPs {
		if ip.To16() != nil {
			result = append(result, ip)
		}
	}

	return result
}
