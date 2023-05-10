// dnssd is a utilty to register and browser DNS-SD services.
package main

import (
	"log"
	"net"

	"github.com/brutella/dnssd"

	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

var nameFlag = flag.String("Name", "", "Service Name")
var typeFlag = flag.String("Type", "", "Service type")
var domainFlag = flag.String("Domain", "local", "Service Domain")
var hostFlag = flag.String("Host", "", "Hostname")
var ipFlag = flag.String("IP", "", "")
var portFlag = flag.Int("Port", 0, "")
var interfaceFlag = flag.String("Interface", "", "")
var timeFormat = "15:04:05.000"

// Name of the invoked executable.
var name = filepath.Base(os.Args[0])

func printUsage() {
	log.Println("A DNS-SD utilty to register, browse and resolve Bonjour services.\n\n" +
		"Usage:\n" +
		"  " + name + " register -Name <string> -Type <string> -Port <int> [-Domain <string> (-Interface <string> | -Host <string> -IP <string> )]\n" +
		"  " + name + " browse                  -Type <string>             [-Domain <string>]\n" +
		"  " + name + " resolve  -Name <string> -Type <string>             [-Domain <string>]\n")
}

func resolve(typee, instance string) {
	fmt.Printf("Lookup %s\n", instance)
	fmt.Printf("DATE: –––%s–––\n", time.Now().Format("Mon Jan 2 2006"))
	fmt.Printf("%s	...STARTING...\n", time.Now().Format(timeFormat))

	addFn := func(e dnssd.BrowseEntry) {
		if e.UnescapedServiceInstanceName() == instance {
			text := ""
			for key, value := range e.Text {
				text += fmt.Sprintf("%s=%s", key, value)
			}
			fmt.Printf("%s	%s can be reached at %s.%s.:%d %v\n", time.Now().Format(timeFormat), e.UnescapedServiceInstanceName(), e.Host, e.Domain, e.Port, text)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := dnssd.LookupType(ctx, typee, addFn, func(dnssd.BrowseEntry) {}); err != nil {
		fmt.Println(err)
		return
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	<-stop
	cancel()
}

func register(instance string) {
	if *portFlag == 0 {
		log.Println("invalid port", *portFlag)
		printUsage()
		return
	}

	var ips []net.IP
	if *ipFlag != "" {
		ip := net.ParseIP(*ipFlag)
		if ip == nil {
			log.Println("invalid ip", *ipFlag)
			printUsage()
			return
		}
		ips = []net.IP{ip}
	}

	fmt.Printf("Registering Service %s port %d\n", instance, *portFlag)
	fmt.Printf("DATE: –––%s–––\n", time.Now().Format("Mon Jan 2 2006"))
	fmt.Printf("%s	...STARTING...\n", time.Now().Format(timeFormat))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if resp, err := dnssd.NewResponder(); err != nil {
		fmt.Println(err)
	} else {
		ifaces := []string{}
		if len(*interfaceFlag) > 0 {
			ifaces = append(ifaces, *interfaceFlag)
		}

		cfg := dnssd.Config{
			Name:   *nameFlag,
			Type:   *typeFlag,
			Domain: *domainFlag,
			Port:   *portFlag,
			Ifaces: ifaces,
			IPs:    ips,
			Host:   *hostFlag,
		}
		srv, err := dnssd.NewService(cfg)
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			stop := make(chan os.Signal, 1)
			signal.Notify(stop, os.Interrupt)

			<-stop
			cancel()
		}()

		go func() {
			time.Sleep(1 * time.Second)
			handle, err := resp.Add(srv)
			if err != nil {
				fmt.Println(err)
			} else {
				fmt.Printf("%s	Got a reply for service %s: Name now registered and active\n", time.Now().Format(timeFormat), handle.Service().ServiceInstanceName())
			}
		}()
		err = resp.Respond(ctx)

		if err != nil {
			fmt.Println(err)
		}
	}
}

func browse(typee string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("Browsing for %s\n", typee)
	fmt.Printf("DATE: –––%s–––\n", time.Now().Format("Mon Jan 2 2006"))
	fmt.Printf("%s  ...STARTING...\n", time.Now().Format(timeFormat))
	fmt.Printf("Timestamp	A/R	if Domain	Service Type	Instance Name\n")

	addFn := func(e dnssd.BrowseEntry) {
		fmt.Printf("%s	Add	%s	%s	%s	%s (%s)\n", time.Now().Format(timeFormat), e.IfaceName, e.Domain, e.Type, e.UnescapedName(), e.IPs)
	}

	rmvFn := func(e dnssd.BrowseEntry) {
		fmt.Printf("%s	Rmv	%s	%s	%s	%s\n", time.Now().Format(timeFormat), e.IfaceName, e.Domain, e.Type, e.UnescapedName())
	}

	if err := dnssd.LookupType(ctx, typee, addFn, rmvFn); err != nil {
		fmt.Println(err)
		return
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	<-stop
	cancel()
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		return
	}

	// The first argument is the command.
	cmd := args[0]

	// Use the remaining arguments as flags.
	flag.CommandLine.Parse(os.Args[2:])

	if *typeFlag == "" {
		printUsage()
		return
	}

	typee := fmt.Sprintf("%s.%s.", strings.Trim(*typeFlag, "."), strings.Trim(*domainFlag, "."))
	instance := fmt.Sprintf("%s.%s.%s.", strings.Trim(*nameFlag, "."), strings.Trim(*typeFlag, "."), strings.Trim(*domainFlag, "."))

	switch cmd {
	case "register":
		if *nameFlag == "" {
			printUsage()
			return
		}
		register(instance)
	case "browse":
		browse(typee)
	case "resolve":
		if *nameFlag == "" {
			printUsage()
			return
		}
		resolve(typee, instance)
	default:
		printUsage()
		return
	}
}
