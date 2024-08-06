package dnssd

import (
	"bytes"

	"github.com/brutella/dnssd/log"

	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type Config struct {
	// Name of the service.
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

func (c Config) Copy() Config {
	return Config{
		Name:   c.Name,
		Type:   c.Type,
		Domain: c.Domain,
		Host:   c.Host,
		Text:   c.Text,
		IPs:    c.IPs,
		Port:   c.Port,
		Ifaces: c.Ifaces,
	}
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

// NewService returns a new service for the given config.
func NewService(cfg Config) (s Service, err error) {
	// Escape dots in the name (RFC6763 4.3).
	// Spaces and backslashes are escaped by "github.com/miekg/dns".
	name := strings.Replace(cfg.Name, ".", "\\.", -1)
	typ := cfg.Type
	port := cfg.Port

	if len(name) == 0 {
		err = fmt.Errorf("invalid name \"%s\"", name)
		return
	}

	if len(typ) == 0 {
		err = fmt.Errorf("invalid type \"%s\"", typ)
		return
	}

	if port == 0 {
		err = fmt.Errorf("invalid port \"%d\"", port)
		return
	}

	domain := cfg.Domain
	if len(domain) == 0 {
		domain = "local"
	}

	host := cfg.Host
	if len(host) == 0 {
		host = hostname()
	}

	text := cfg.Text
	if text == nil {
		text = map[string]string{}
	}

	ips := []net.IP{}
	var ifaces []string

	if cfg.IPs != nil && len(cfg.IPs) > 0 {
		ips = cfg.IPs
	}

	if cfg.Ifaces != nil && len(cfg.Ifaces) > 0 {
		ifaces = cfg.Ifaces
	}

	return Service{
		Name:     name,
		Type:     typ,
		Domain:   domain,
		Host:     host,
		Text:     text,
		Port:     port,
		IPs:      ips,
		Ifaces:   ifaces,
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

	return MulticastInterfaces()
}

// IsVisibleAtInterface returns true, if the service is published
// at the network interface with name n.
func (s *Service) IsVisibleAtInterface(n string) bool {
	if len(s.Ifaces) == 0 {
		return true
	}

	for _, name := range s.Ifaces {
		if name == n {
			return true
		}
	}

	return false
}

// IPsAtInterface returns the ip address at a specific interface.
func (s *Service) IPsAtInterface(iface *net.Interface) []net.IP {
	if iface == nil {
		return []net.IP{}
	}

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
		if ip, _, err := net.ParseCIDR(addr.String()); err == nil {
			ips = append(ips, ip)
		} else {
			log.Debug.Println(err)
		}
	}

	return ips
}

// HasIPOnAnyInterface returns true, if the service defines
// the ip address on any network interface.
func (s *Service) HasIPOnAnyInterface(ip net.IP) bool {
	for _, iface := range s.Interfaces() {
		ips := s.IPsAtInterface(iface)
		for _, ifaceIP := range ips {
			if ifaceIP.Equal(ip) {
				return true
			}
		}
	}

	return false
}

// Copy returns a copy of the service.
func (s Service) Copy() *Service {
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

// ServiceInstanceName returns the service instance name
// in the form of <instance name>.<service>.<domain>.
// (Note the trailing dot.)
func (s Service) ServiceInstanceName() string {
	return fmt.Sprintf("%s.%s.%s.", s.Name, s.Type, s.Domain)
}

// UnescapedServiceInstanceName returns the same as `ServiceInstanceName()`
// but removes any escape characters.
func (s Service) UnescapedServiceInstanceName() string {
	return fmt.Sprintf("%s.%s.%s.", s.UnescapedName(), s.Type, s.Domain)
}

// UnescapedName returns the unescaped instance name.
func (s Service) UnescapedName() string {
	return unescape.Replace(s.Name)
}

// ServiceName returns the service name in the
// form of "<service>.<domain>."
// (Note the trailing dot.)
func (s Service) ServiceName() string {
	return fmt.Sprintf("%s.%s.", s.Type, s.Domain)
}

// Hostname returns the hostname in the
// form of "<hostname>.<domain>."
// (Note the trailing dot.)

func (s Service) Hostname() string {
	return fmt.Sprintf("%s.%s.", s.Host, s.Domain)
}

// SetHostname sets the service's host name and
// domain (if specified as "<hostname>.<domain>.").
// (Note the trailing dot.)
func (s *Service) SetHostname(hostname string) {
	name, domain := parseHostname(hostname)

	if domain == s.Domain {
		s.Host = name
	}
}

// ServicesMetaQueryName returns the name of the meta query
// for the service domain in the form of "_services._dns-sd._udp.<domain.".
// (Note the trailing dot.)
func (s Service) ServicesMetaQueryName() string {
	return fmt.Sprintf("_services._dns-sd._udp.%s.", s.Domain)
}

func (s *Service) addIP(ip net.IP, iface *net.Interface) {
	s.IPs = append(s.IPs, ip)
	if iface != nil {
		ifaceIPs := []net.IP{ip}
		if ips, ok := s.ifaceIPs[iface.Name]; ok {
			ifaceIPs = append(ips, ip)
		}
		s.ifaceIPs[iface.Name] = ifaceIPs
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

var unescape = strings.NewReplacer("\\", "")

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// parseServiceInstanceName parses str to get the instance, service and domain name.
func parseServiceInstanceName(str string) (name string, service string, domain string) {
	r := bytes.NewBufferString(reverse(strings.Trim(str, ".")))
	l, err := r.ReadString('.')
	if err != nil {
		return
	}
	domain = strings.Trim(l, ".")
	domain = reverse(domain)

	proto, err := r.ReadString('.')
	if err != nil {
		return
	}
	typee, err := r.ReadString('.')
	if err != nil {
		return
	}
	service = fmt.Sprintf("%s.%s", strings.Trim(reverse(typee), "."), strings.Trim(reverse(proto), "."))
	name = reverse(r.String())

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
	return strings.Replace(name, " ", "-", -1)
}

func parseHostname(str string) (name string, domain string) {
	elems := strings.Split(str, ".")
	if len(elems) > 0 {
		name = elems[0]
	}

	if len(elems) > 1 {
		domain = elems[1]
	}

	return
}

// MulticastInterfaces returns a list of all active multicast network interfaces.
func MulticastInterfaces(filters ...string) []*net.Interface {
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

		if !containsIfaces(iface.Name, filters) {
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

func containsIfaces(iface string, filters []string) bool {
	if filters == nil || len(filters) <= 0 {
		return true
	}

	for _, ifn := range filters {
		if ifn == iface {
			return true
		}
	}

	return false
}
