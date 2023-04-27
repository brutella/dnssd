package dnssd

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Cache struct {
	services map[string]*Service
}

func NewCache() *Cache {
	return &Cache{
		services: make(map[string]*Service),
	}
}

func (c *Cache) Services() []*Service {
	tmp := []*Service{}
	for _, s := range c.services {
		tmp = append(tmp, s)
	}
	return tmp
}

// UpdateFrom updates the cache from resource records in msg.
// TODO consider the cache-flush bit to make records as to be deleted in one second
func (c *Cache) UpdateFrom(msg *dns.Msg, iface *net.Interface) (adds []*Service, rmvs []*Service) {
	answers := filterRecords(msg, iface, nil)
	sort.Sort(byType(answers))

	for _, answer := range answers {
		switch rr := answer.(type) {
		case *dns.PTR:
			ttl := time.Duration(rr.Hdr.Ttl) * time.Second

			var entry *Service
			if e, ok := c.services[rr.Ptr]; !ok {
				if ttl == 0 {
					// Ignore new records with no ttl
					break
				}
				entry = newService(rr.Ptr)
				adds = append(adds, entry)
				c.services[entry.ServiceInstanceName()] = entry
			} else {
				entry = e
			}

			entry.TTL = ttl
			entry.expiration = time.Now().Add(ttl)

		case *dns.SRV:
			ttl := time.Duration(rr.Hdr.Ttl) * time.Second
			var entry *Service
			if e, ok := c.services[rr.Hdr.Name]; !ok {
				if ttl == 0 {
					// Ignore new records with no ttl
					break
				}
				entry = newService(rr.Hdr.Name)
				adds = append(adds, entry)
				c.services[entry.ServiceInstanceName()] = entry
			} else {
				entry = e
			}

			entry.SetHostname(rr.Target)
			entry.TTL = ttl
			entry.expiration = time.Now().Add(ttl)
			entry.Port = int(rr.Port)

		case *dns.A:
			for _, entry := range c.services {
				if entry.Hostname() == rr.Hdr.Name {
					entry.addIP(rr.A, iface)
				}
			}

		case *dns.AAAA:
			for _, entry := range c.services {
				if entry.Hostname() == rr.Hdr.Name {
					entry.addIP(rr.AAAA, iface)
				}
			}

		case *dns.TXT:
			if entry, ok := c.services[rr.Hdr.Name]; ok {
				text := make(map[string]string)
				for _, txt := range rr.Txt {
					elems := strings.SplitN(txt, "=", 2)
					if len(elems) == 2 {
						key := elems[0]
						value := elems[1]

						// Don't override existing keys
						// TODO make txt records case insensitive
						if _, ok := text[key]; !ok {
							text[key] = value
						}

						text[key] = value
					}
				}

				entry.Text = text
				entry.TTL = time.Duration(rr.Hdr.Ttl) * time.Second
				entry.expiration = time.Now().Add(entry.TTL)
			}
		default:
			// ignore
		}
	}

	// TODO remove outdated services regularly
	rmvs = c.removeExpired()

	return
}

func (c *Cache) removeExpired() []*Service {
	var outdated []*Service
	var services = c.services
	for key, srv := range services {
		if time.Now().After(srv.expiration) {
			outdated = append(outdated, srv)
			delete(c.services, key)
		}
	}

	return outdated
}

type byType []dns.RR

func (a byType) Len() int      { return len(a) }
func (a byType) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a byType) Less(i, j int) bool {
	// Sort in the following order
	// 1. SRV or PTR
	// 2. Anything else
	switch a[i].(type) {
	case *dns.SRV:
		return true
	case *dns.PTR:
		return true
	}

	return false
}

func filterRecords(m *dns.Msg, iface *net.Interface, service *Service) []dns.RR {
	if iface != nil && service != nil && len(service.Ifaces) > 0 {
		if !service.IsVisibleAtInterface(iface.Name) {
			// Ignnore message if coming from a ignored interface.
			return []dns.RR{}
		}
	}
	var all []dns.RR
	all = append(all, m.Answer...)
	all = append(all, m.Ns...)
	all = append(all, m.Extra...)

	if service == nil {
		return all
	}

	var answers []dns.RR
	for _, answer := range all {
		switch rr := answer.(type) {
		case *dns.SRV:
			if rr.Hdr.Name != service.ServiceInstanceName() {
				continue
			}
		case *dns.A:
			if service.Hostname() != rr.Hdr.Name {
				continue
			}
		case *dns.AAAA:
			if service.Hostname() != rr.Hdr.Name {
				continue
			}
		}
		answers = append(answers, answer)
	}

	return answers
}
