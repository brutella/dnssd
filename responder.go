package dnssd

import (
	"context"
	"fmt"
	"github.com/brutella/dnssd/log"
	"github.com/miekg/dns"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

type ReadFunc func(*Request)

// Responder represents a mDNS responder.
type Responder interface {
	// Add adds a service to the responder.
	// Use the returned service handle to update service properties.
	Add(srv Service) (ServiceHandle, error)

	// Remove removes the service associated with the service handle from the responder.
	Remove(srv ServiceHandle)

	// Respond makes the receiver announcing and managing services.
	Respond(ctx context.Context) error

	// Debug calls a function for every dns request the responder receives.
	Debug(ctx context.Context, fn ReadFunc)
}

type responder struct {
	isRunning bool

	conn      MDNSConn
	unmanaged []*serviceHandle
	managed   []*serviceHandle

	mutex     *sync.Mutex
	truncated *Request
	random    *rand.Rand
	upIfaces  []string
}

func NewResponder() (Responder, error) {
	conn, err := newMDNSConn()
	if err != nil {
		return nil, err
	}

	return newResponder(conn), nil
}

func newResponder(conn MDNSConn) *responder {
	return &responder{
		isRunning: false,
		conn:      conn,
		unmanaged: []*serviceHandle{},
		managed:   []*serviceHandle{},
		mutex:     &sync.Mutex{},
		random:    rand.New(rand.NewSource(time.Now().UnixNano())),
		upIfaces:  []string{},
	}
}

func (r *responder) Remove(h ServiceHandle) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for i, s := range r.managed {
		if h == s {
			handle := h.(*serviceHandle)
			r.unannounce([]*Service{handle.service})
			r.managed = append(r.managed[:i], r.managed[i+1:]...)
			return
		}
	}
}

func (r *responder) Add(srv Service) (ServiceHandle, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.isRunning {
		ctx, cancel := context.WithCancel(context.TODO())
		defer cancel()

		if srv, err := r.register(ctx, srv); err != nil {
			return nil, err
		} else {
			return r.addManaged(srv), nil
		}
	}

	return r.addUnmanaged(srv), nil
}

func (r *responder) Respond(ctx context.Context) error {
	r.mutex.Lock()
	r.isRunning = true
	for _, h := range r.unmanaged {
		log.Debug.Println(h.service)
		if srv, err := r.register(ctx, *h.service); err != nil {
			return err
		} else {
			h.service = &srv
			r.managed = append(r.managed, h)
		}
	}
	r.unmanaged = []*serviceHandle{}
	r.mutex.Unlock()

	return r.respond(ctx)
}

// announce sends announcement messages including all services.
func (r *responder) announce(services []*Service) {
	for _, service := range services {
		for _, iface := range service.Interfaces() {
			go r.announceAtInterface(service, iface)
		}
	}
}

func (r *responder) announceAtInterface(service *Service, iface *net.Interface) {
	ips := service.IPsAtInterface(iface)
	if len(ips) == 0 {
		log.Debug.Printf("No IPs for service %s at %s\n", service.ServiceInstanceName(), iface.Name)
		return
	}

	var answer []dns.RR
	answer = append(answer, SRV(*service))
	answer = append(answer, PTR(*service))
	answer = append(answer, TXT(*service))
	for _, a := range A(*service, iface) {
		answer = append(answer, a)
	}
	for _, aaaa := range AAAA(*service, iface) {
		answer = append(answer, aaaa)
	}
	msg := new(dns.Msg)
	msg.Answer = answer
	msg.Response = true
	msg.Authoritative = true

	setAnswerCacheFlushBit(msg)

	resp := &Response{msg: msg, iface: iface}

	log.Debug.Println("Sending 1st announcement", msg)
	r.conn.SendResponse(resp)
	time.Sleep(1 * time.Second)
	log.Debug.Println("Sending 2nd announcement", msg)
	r.conn.SendResponse(resp)
}

func (r *responder) register(ctx context.Context, srv Service) (Service, error) {
	if !r.isRunning {
		return srv, fmt.Errorf("cannot register service when responder is not responding")
	}

	log.Debug.Printf("Probing for host %s and service %s…\n", srv.Hostname(), srv.ServiceInstanceName())
	probed, err := ProbeService(ctx, srv)
	if err != nil {
		return srv, err
	}

	srvs := []*Service{&probed}
	for _, h := range r.managed {
		srvs = append(srvs, h.service)
	}
	go r.announce(srvs)

	return probed, nil
}

func (r *responder) addManaged(srv Service) ServiceHandle {
	h := &serviceHandle{&srv}
	r.managed = append(r.managed, h)
	return h
}

func (r *responder) addUnmanaged(srv Service) ServiceHandle {
	h := &serviceHandle{&srv}
	r.unmanaged = append(r.unmanaged, h)
	return h
}

func (r *responder) respond(ctx context.Context) error {
	if !r.isRunning {
		return fmt.Errorf("isRunning should be true before calling respond()")
	}

	readCtx, readCancel := context.WithCancel(ctx)
	defer readCancel()
	ch := r.conn.Read(readCtx)

	for {
		select {
		case req := <-ch:
			r.mutex.Lock()
			r.handleRequest(req)
			r.mutex.Unlock()

		case <-ctx.Done():
			r.unannounce(services(r.managed))
			r.conn.Close()
			r.isRunning = false
			return ctx.Err()
		}
	}
}

func (r *responder) handleRequest(req *Request) {
	if len(r.managed) == 0 {
		// Ignore requests when no services are managed
		return
	}

	// If messages is truncated, we wait for the next message to come (RFC6762 18.5)
	if req.msg.Truncated {
		r.truncated = req
		log.Debug.Println("Waiting for additional answers...")
		return
	}

	// append request
	if r.truncated != nil && r.truncated.from.IP.Equal(req.from.IP) {
		log.Debug.Println("Add answers to truncated message")
		msgs := []*dns.Msg{r.truncated.msg, req.msg}
		r.truncated = nil
		req.msg = mergeMsgs(msgs)
	}

	// Conflicting records remove managed services from
	// the responder and trigger reprobing
	conflicts := findConflicts(req, r.managed)
	for _, h := range conflicts {
		log.Debug.Println("Reprobe for", h.service)
		go r.reprobe(h)

		for i, m := range r.managed {
			if h == m {
				r.managed = append(r.managed[:i], r.managed[i+1:]...)
				break
			}
		}
	}

	r.handleQuery(req, services(r.managed))
}

func (r *responder) unannounce(services []*Service) {
	if len(services) == 0 {
		return
	}

	log.Debug.Println("Send goodbye for", services)

	// collect records per interface
	rrsByIfaceName := map[string][]dns.RR{}
	for _, srv := range services {
		rr := PTR(*srv)
		rr.Header().Ttl = 0
		for _, iface := range srv.Interfaces() {
			ips := srv.IPsAtInterface(iface)
			if len(ips) == 0 {
				continue
			}
			if rrs, ok := rrsByIfaceName[iface.Name]; ok {
				rrsByIfaceName[iface.Name] = append(rrs, rr)
			} else {
				rrsByIfaceName[iface.Name] = []dns.RR{rr}
			}
		}
	}

	// send on goodbye packet on every interface
	for name, rrs := range rrsByIfaceName {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			log.Debug.Printf("Interface %s not found\n", name)
			continue
		}
		msg := new(dns.Msg)
		msg.Answer = rrs
		msg.Response = true
		msg.Authoritative = true
		resp := &Response{msg: msg, iface: iface}
		r.conn.SendResponse(resp)
		time.Sleep(250 * time.Millisecond)
		r.conn.SendResponse(resp)
	}
}

func (r *responder) handleQuery(req *Request, services []*Service) {
	for _, q := range req.msg.Question {
		msgs := []*dns.Msg{}
		for _, srv := range services {
			log.Debug.Printf("%s tries to give response to question %v\n", srv.ServiceInstanceName(), q)
			if msg := r.handleQuestion(q, req, *srv); msg != nil {
				msgs = append(msgs, msg)
			} else {
				log.Debug.Println("No response")
			}
		}

		msg := mergeMsgs(msgs)
		msg.SetReply(req.msg)
		msg.Question = nil
		msg.Response = true
		msg.Authoritative = true

		if len(msg.Answer) == 0 {
			log.Debug.Println("No answers")
			continue
		}

		if isUnicastQuestion(q) {
			resp := &Response{msg: msg, addr: req.from, iface: req.iface}
			log.Debug.Printf("Send unicast response\n%v to %v\n", msg, resp.addr)
			if err := r.conn.SendResponse(resp); err != nil {
				log.Debug.Println(err)
			}
		} else {
			resp := &Response{msg: msg, iface: req.iface}
			log.Debug.Printf("Send multicast response\n%v\n", msg)
			if err := r.conn.SendResponse(resp); err != nil {
				log.Debug.Println(err)
			}
		}
	}
}

func (r *responder) reprobe(h *serviceHandle) {
	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()

	probed, err := ReprobeService(ctx, *h.service)
	if err != nil {
		return
	}
	h.service = &probed

	r.mutex.Lock()
	managed := append(r.managed, h)
	r.managed = managed
	r.mutex.Unlock()

	log.Debug.Println("Reannouncing services", managed)
	go r.announce(services(managed))
}

func (r *responder) handleQuestion(q dns.Question, req *Request, srv Service) *dns.Msg {
	resp := new(dns.Msg)

	switch strings.ToLower(q.Name) {
	case strings.ToLower(srv.ServiceName()):
		ptr := PTR(srv)
		resp.Answer = []dns.RR{ptr}

		extra := []dns.RR{SRV(srv), TXT(srv)}

		for _, a := range A(srv, req.iface) {
			extra = append(extra, a)
		}

		for _, aaaa := range AAAA(srv, req.iface) {
			extra = append(extra, aaaa)
		}

		extra = append(extra, NSEC(ptr, srv, req.iface))
		resp.Extra = extra

		// Wait 20-125 msec for shared resource responses
		delay := time.Duration(r.random.Intn(105)+20) * time.Millisecond
		log.Debug.Println("Shared record response wait", delay)
		time.Sleep(delay)

	case strings.ToLower(srv.ServiceInstanceName()):
		resp.Answer = []dns.RR{SRV(srv), TXT(srv), PTR(srv)}

		var extra []dns.RR

		for _, a := range A(srv, req.iface) {
			extra = append(extra, a)
		}

		for _, aaaa := range AAAA(srv, req.iface) {
			extra = append(extra, aaaa)
		}

		nsec := NSEC(SRV(srv), srv, req.iface)
		if nsec != nil {
			extra = append(extra, nsec)
		}

		resp.Extra = extra

		// Set cache flush bit for non-shared records
		setAnswerCacheFlushBit(resp)

	case strings.ToLower(srv.Hostname()):
		var answer []dns.RR

		for _, a := range A(srv, req.iface) {
			answer = append(answer, a)
		}

		for _, aaaa := range AAAA(srv, req.iface) {
			answer = append(answer, aaaa)
		}

		resp.Answer = answer
		nsec := NSEC(SRV(srv), srv, req.iface)

		if nsec != nil {
			resp.Extra = []dns.RR{nsec}
		}

		// Set cache flush bit for non-shared records
		setAnswerCacheFlushBit(resp)

	case strings.ToLower(srv.ServicesMetaQueryName()):
		resp.Answer = []dns.RR{DNSSDServicesPTR(srv)}

	default:
		return nil
	}

	// Supress known answers
	resp.Answer = remove(req.msg.Answer, resp.Answer)

	resp.SetReply(req.msg)
	resp.Question = nil
	resp.Response = true
	resp.Authoritative = true

	return resp
}

func findConflicts(req *Request, hs []*serviceHandle) []*serviceHandle {
	var conflicts []*serviceHandle
	for _, h := range hs {
		if containsConflictingAnswers(req, h) {
			log.Debug.Println("Received conflicting record", req.msg)
			conflicts = append(conflicts, h)
		}
	}

	return conflicts
}

func services(hs []*serviceHandle) []*Service {
	var result []*Service
	for _, h := range hs {
		result = append(result, h.service)
	}

	return result
}

func containsConflictingAnswers(req *Request, handle *serviceHandle) bool {
	as := A(*handle.service, req.iface)
	aaaas := AAAA(*handle.service, req.iface)
	srv := SRV(*handle.service)

	reqAs, reqAAAAs, reqSRVs := splitRecords(filterRecords(req.msg, handle.service))

	if len(reqAs) > 0 && areDenyingAs(reqAs, as) {
		log.Debug.Printf("%v != %v\n", reqAs, as)
		return true
	}

	if len(reqAAAAs) > 0 && areDenyingAAAAs(reqAAAAs, aaaas) {
		log.Debug.Printf("%v != %v\n", reqAAAAs, aaaas)
		return true
	}

	for _, reqSRV := range reqSRVs {
		if isDenyingSRV(reqSRV, srv) {
			return true
		}
	}

	return false
}
