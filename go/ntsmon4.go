package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
	"unicode"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"
)

var ntpversion int = 4

func main() {

	serverPtr := flag.String("server", "nts.time.nl", "NTS server")
	stratumPtr := flag.Int("stratum", 1, "expected stratum")
	verbosePtr := flag.Bool("verbose", false, "verbose output")
	insecurePtr := flag.Bool("insecure", false, "accept invalid certificates")
	requestedServerPtr := flag.String("requested-server", "", "requested NTP server (optional)")
	requestedPortPtr := flag.String("requested-port", "123", "requested NTP port (optional)")

	flag.Parse()

	TestQuery(*serverPtr, uint8(*stratumPtr), *verbosePtr, *insecurePtr, *requestedServerPtr, *requestedPortPtr)
}

func TestQuery(host string, stratum uint8, verbose, insecure bool, requestedServer, requestedPort string) {

	opt := &nts.SessionOptions{
		TLSConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}

	// Alleen instellen als er een requested server is opgegeven
	if requestedServer != "" {
		opt.RequestedNTPServerAddress = requestedServer
		if requestedPort != "" {
			portInt, err := strconv.Atoi(requestedPort)
			if err != nil {
				fmt.Printf("Invalid requested port: %v\n", err)
				os.Exit(1)
			}
			opt.RequestedNTPServerPort = portInt
		}
	}

	session, err := nts.NewSessionWithOptions(host, opt)
	if err != nil {
		fmt.Printf("NTS session could not be established: %v\n", err)
		os.Exit(1)
	}

	// Gebruik de server die NTS daadwerkelijk teruggeeft
	ntphost, ntpport, err := net.SplitHostPort(session.Address())
	if err != nil {
		fmt.Printf("Could not deduce NTP host and port: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nNTS server: %s\n", host)
	if requestedServer != "" {
		fmt.Printf("Requested NTP server: %s:%s\n", requestedServer, requestedPort)
	}

	//bug #10 r, err := ntp.QueryWithOptions(session.Address(), ntp.QueryOptions{
	r, err := session.QueryWithOptions(&ntp.QueryOptions{
		Version: ntpversion,
		Timeout: 1 * time.Second,
	})
	if err != nil {
		fmt.Printf("    Result: Error - %v\n\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("  Resolver: [%s]:%s\n", ntphost, ntpport)
		fmt.Printf("       RTT: %v\n", r.RTT)
		fmt.Printf("    Offset: %v\n", r.ClockOffset)
		fmt.Printf("      Poll: %v\n", r.Poll)
		fmt.Printf(" Precision: %v\n", r.Precision)
		fmt.Printf("   Stratum: %v\n", r.Stratum)
		if r.Stratum == 1 {
			fmt.Printf("     RefID: %v\n", RefidToString(r.ReferenceID))
		} else {
			fmt.Printf("     RefID: 0x%08X\n", r.ReferenceID)
		}
		fmt.Printf(" RootDelay: %v\n", r.RootDelay)
		fmt.Printf("  RootDisp: %v\n", r.RootDispersion)
		fmt.Printf("  RootDist: %v\n", r.RootDistance)
		fmt.Printf("  MinError: %v\n", r.MinError)
		fmt.Printf("      Leap: %v\n", r.Leap)
		fmt.Printf("  KissCode: %v\n", stringOrEmpty(r.KissCode))
	}

	err = r.Validate()
	if err != nil {
		fmt.Printf("    Result: Error - %v\n\n", err)
		os.Exit(2)
	} else {
		if r.Stratum != stratum {
			fmt.Printf("    Result: Error - stratum mismatch, expected: %d and received: %v\n\n", stratum, r.Stratum)
			os.Exit(3)
		}
		if r.ClockOffset > 100000000 || r.ClockOffset < -100000000 {
			fmt.Printf("    Result: Error - offset out of bounds\n\n")
			os.Exit(4)
		}
	}

	fmt.Printf("    Result: OK - test successful\n\n")
	os.Exit(0)
}

func stringOrEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}

func RefidToString(refID uint32) string {
	result := []rune{}
	for i := 0; i < 4; i++ {
		c := rune((refID >> (24 - uint(i)*8)) & 0xff)
		if unicode.IsPrint(c) {
			result = append(result, c)
		}
	}
	return string(result)
}
