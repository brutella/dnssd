package dnssd

import (
	"github.com/brutella/dnssd/log"

	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type Config struct {
	// Name of the service
	Name string

	// Type is the service type, for example "_hap._tcp".
	Type string

	// Domain is the name of the domain, for example "local".
	// If empty, "local" is used.
	Domain string

	// Host is the name of the host (no trailing dot).
	// If empty the local host name is used.
	Host string

	// Txt records
	Text map[string]string

	// IP addresses of the service.
	// This field is deprecated and should not be used.
	IPs []net.IP

	// Port is the port of the service.
	Port int

	// Interfaces at which the service should be registered
	Ifaces []string
}

// Service represents a DNS-SD service instance
type Service struct {
	Name   string
	Type   string
	Domain string
	Host   string
	Text   map[string]string
	TTL    time.Duration // Original time to live
	Port   int
	IPs    []net.IP
	Ifaces []string

	// stores ips by interface name for caching purposes
	ifaceIPs   map[string][]net.IP
	expiration time.Time
}

func NewService(cfg *Config) (s *Service, err error) {
	name := cfg.Name
	typ := cfg.Type
	port := cfg.Port

	if name == "" {
		err = fmt.Errorf("invalid name \"%s\"", name)
		return
	}

	if typ == "" {
		err = fmt.Errorf("invalid type \"%s\"", typ)
		return
	}

	if port == 0 {
		err = fmt.Errorf("invalid port \"%d\"", port)
		return
	}

	domain := cfg.Domain
	if domain == "" {
		domain = "local"
	}

	host := cfg.Host
	if host == "" {
		host = hostname()
	}

	text := cfg.Text
	if text == nil {
		text = map[string]string{}
	}

	ips := []net.IP{}
	var Ifaces []string

	if cfg.IPs != nil && len(cfg.IPs) > 0 {
		ips = cfg.IPs
	}

	if cfg.Ifaces != nil && len(cfg.Ifaces) > 0 {
		Ifaces = cfg.Ifaces
	}

	return &Service{
		Name:     name,
		Type:     typ,
		Domain:   domain,
		Host:     host,
		Text:     text,
		Port:     port,
		IPs:      ips,
		Ifaces:   Ifaces,
		ifaceIPs: map[string][]net.IP{},
	}, nil
}

// Interfaces returns the network interfaces for which the service is registered,
// or all multicast network interfaces, if no IP addresses are specified.
func (s *Service) Interfaces() []*net.Interface {
	if len(s.Ifaces) > 0 {
		ifis := []*net.Interface{}
		for _, name := range s.Ifaces {
			if ifi, err := net.InterfaceByName(name); err == nil {
				ifis = append(ifis, ifi)
			}
		}

		return ifis
	}

	return multicastInterfaces()
}

// IPsAtInterface returns the ip address at a specific interface.
func (s *Service) IPsAtInterface(iface *net.Interface) []net.IP {
	if ips, ok := s.ifaceIPs[iface.Name]; ok {
		return ips
	}

	if len(s.IPs) > 0 {
		return s.IPs
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return []net.IP{}
	}

	ips := []net.IP{}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			log.Debug.Println(err)
			continue
		}

		ips = append(ips, ip)
	}

	return ips
}

func (s *Service) Copy() *Service {
	return &Service{
		Name:       s.Name,
		Type:       s.Type,
		Domain:     s.Domain,
		Host:       s.Host,
		Text:       s.Text,
		TTL:        s.TTL,
		IPs:        s.IPs,
		Port:       s.Port,
		Ifaces:     s.Ifaces,
		ifaceIPs:   s.ifaceIPs,
		expiration: s.expiration,
	}
}

func (s *Service) ServiceInstanceName() string {
	return fmt.Sprintf("%s.%s.%s.", s.Name, s.Type, s.Domain)
}

func (s *Service) ServiceName() string {
	return fmt.Sprintf("%s.%s.", s.Type, s.Domain)
}

func (s *Service) Hostname() string {
	return fmt.Sprintf("%s.%s.", s.Host, s.Domain)
}

func (s *Service) SetHostname(hostname string) {
	name, domain := parseHostname(hostname)
	if domain == s.Domain {
		s.Host = name
	}
}

func (s *Service) ServicesMetaQueryName() string {
	return fmt.Sprintf("_services._dns-sd._udp.%s.", s.Domain)
}

func (s *Service) addIP(ip net.IP, iface *net.Interface) {
	s.IPs = append(s.IPs, ip)

	if iface != nil {
		if _, ok := s.ifaceIPs[iface.Name]; !ok {
			s.ifaceIPs[iface.Name] = []net.IP{}
		}

		s.ifaceIPs[iface.Name] = append(s.ifaceIPs[iface.Name], ip)
	}
}

func newService(instance string) *Service {
	name, typ, domain := parseServiceInstanceName(instance)
	return &Service{
		Name:     name,
		Type:     typ,
		Domain:   domain,
		Text:     map[string]string{},
		IPs:      []net.IP{},
		Ifaces:   []string{},
		ifaceIPs: map[string][]net.IP{},
	}
}

func parseServiceInstanceName(str string) (name, service, domain string) {
	elems := strings.Split(str, ".")
	if len(elems) > 0 {
		name = elems[0]
	}

	if len(elems) > 2 {
		service = fmt.Sprintf("%s.%s", elems[1], elems[2])
	}

	if len(elems) > 3 {
		domain = elems[3]
	}

	return
}

// Get Fully Qualified Domain Name
// returns "unknown" or hostanme in case of error
func hostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}

	name, _ := parseHostname(hostname)
	return sanitizeHostname(name)
}

func sanitizeHostname(name string) string {
	return strings.ReplaceAll(name, " ", "-")
}

func parseHostname(str string) (name, domain string) {
	elems := strings.Split(str, ".")
	if len(elems) > 0 {
		name = elems[0]
	}

	if len(elems) > 1 {
		domain = elems[1]
	}

	return
}

// multicastInterfaces returns a list of all available multicast network interfaces.
func multicastInterfaces() []*net.Interface {
	var tmp []*net.Interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range ifaces {
		iface := iface
		if (iface.Flags & net.FlagUp) == 0 {
			continue
		}

		if (iface.Flags & net.FlagMulticast) == 0 {
			continue
		}

		// check for a valid ip at that interface
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if _, _, err := net.ParseCIDR(addr.String()); err == nil {
				tmp = append(tmp, &iface)
				break
			}
		}
	}

	return tmp
}
