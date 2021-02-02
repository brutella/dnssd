// Command register registers a dns-sd service instance.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/brutella/dnssd"
	"github.com/brutella/dnssd/log"

	slog "log"
)

var (
	instanceFlag  = flag.String("Name", "Service", "Service name")
	serviceFlag   = flag.String("Type", "_asdf._tcp", "Service type")
	domainFlag    = flag.String("Domain", "local", "domain")
	portFlag      = flag.Int("Port", 12345, "Port")
	verboseFlag   = flag.Bool("Verbose", false, "Verbose logging")
	interfaceFlag = flag.String("Interface", "", "Network interface name")
	timeFormat    = "15:04:05.000"
)

func main() {
	flag.Parse()

	if *instanceFlag == "" || *serviceFlag == "" || *domainFlag == "" {
		flag.Usage()
		return
	}

	if *verboseFlag {
		log.Debug.Enable()
	}

	instance := fmt.Sprintf("%s.%s.%s.", strings.Trim(*instanceFlag, "."), strings.Trim(*serviceFlag, "."), strings.Trim(*domainFlag, "."))

	fmt.Printf("Registering Service %s port %d\n", instance, *portFlag)
	fmt.Printf("DATE: –––%s–––\n", time.Now().Format("Mon Jan 2 2006"))
	fmt.Printf("%s	...STARTING...\n", time.Now().Format(timeFormat))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resp, err := dnssd.NewResponder()
	if err != nil {
		fmt.Println(err)
		return
	}

	ifaces := []string{}
	if len(*interfaceFlag) > 0 {
		ifaces = append(ifaces, *interfaceFlag)
	}

	cfg := dnssd.Config{
		Name:   *instanceFlag,
		Type:   *serviceFlag,
		Domain: *domainFlag,
		Port:   *portFlag,
		Ifaces: ifaces,
	}

	srv, err := dnssd.NewService(&cfg)
	if err != nil {
		slog.Fatal(err)
	}

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt)

		<-stop
		cancel()
	}()

	go func() {
		time.Sleep(1 * time.Second)

		handle, addErr := resp.Add(srv)
		if addErr != nil {
			fmt.Println(addErr)
			return
		}

		fmt.Printf("%s	Got a reply for service %s: Name now registered and active\n", time.Now().Format(timeFormat), handle.Service().ServiceInstanceName())
	}()

	err = resp.Respond(ctx)
	if err != nil {
		fmt.Println(err)
	}
}
