// Inspired by session_test.go

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/beevik/nts"
	"github.com/beevik/ntp"
)

var host string = "nts1.time.nl"

func init() {
	if h := os.Getenv("NTS_HOST"); h != "" {
		host = h
	}
}

func main() {
	s, err := nts.NewSession(host)
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}

	h, port, err := net.SplitHostPort(s.Address())
	if err != nil {
		log.Fatalf("Failed to parse host/port: %v", err)
	}
	fmt.Printf("NTP host: %s\n", h)
	fmt.Printf("NTP port: %s\n", port)

	const iterations = 10
	var minPoll = 2 * time.Second
	for i := 1; i <= iterations; i++ {
		r, err := s.Query()
		if err != nil {
			log.Fatalf("Query failed: %v", err)
		}

		fmt.Println(strings.Repeat("=", 48))
		fmt.Printf("Query %d of %d\n", i, iterations)
		logResponse(r)

		wait := r.Poll
		if wait < minPoll {
			wait = minPoll
		}

		if i < iterations {
			fmt.Printf("Waiting %s for next query...\n", wait)
			time.Sleep(wait)
		}
	}
}

func logResponse(r *ntp.Response) {
	const timeFormat = "Mon Jan _2 2006  15:04:05.00000000 (MST)"

	now := time.Now()
	fmt.Printf("[%s] ClockOffset: %s\n", host, r.ClockOffset)
	fmt.Printf("[%s]  SystemTime: %s\n", host, now.Format(timeFormat))
	fmt.Printf("[%s]   ~TrueTime: %s\n", host, now.Add(r.ClockOffset).Format(timeFormat))
	fmt.Printf("[%s]    XmitTime: %s\n", host, r.Time.Format(timeFormat))
	fmt.Printf("[%s]     Stratum: %d\n", host, r.Stratum)
	fmt.Printf("[%s]       RefID: %s (0x%08x)\n", host, r.ReferenceString(), r.ReferenceID)
	fmt.Printf("[%s]     RefTime: %s\n", host, r.ReferenceTime.Format(timeFormat))
	fmt.Printf("[%s]         RTT: %s\n", host, r.RTT)
	fmt.Printf("[%s]        Poll: %s\n", host, r.Poll)
	fmt.Printf("[%s]   Precision: %s\n", host, r.Precision)
	fmt.Printf("[%s]   RootDelay: %s\n", host, r.RootDelay)
	fmt.Printf("[%s]    RootDisp: %s\n", host, r.RootDispersion)
	fmt.Printf("[%s]    RootDist: %s\n", host, r.RootDistance)
	fmt.Printf("[%s]    MinError: %s\n", host, r.MinError)
	fmt.Printf("[%s]        Leap: %d\n", host, r.Leap)
	fmt.Printf("[%s]    KissCode: %s\n", host, stringOrEmpty(r.KissCode))
}

func stringOrEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}
