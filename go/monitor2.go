package main

import (
	"fmt"
	"os"
	"time"
	"unicode"
	"flag"

	"github.com/beevik/ntp"
)

var emptyTime time.Time

func main() {

        serverPtr := flag.String("server", "any.time.nl", "server")
	stratumPtr := flag.Int("stratum", 1, "stratum")
	verbosePtr := flag.Bool("verbose", false, "verbose")
	
	

	flag.Parse()
	
	TestQuery(*serverPtr, uint8(*stratumPtr), *verbosePtr)
}

func TestQuery(host string, stratum uint8, verbose bool) {

	fmt.Printf("\n    Server: %s\n", host)

	r, err := ntp.QueryWithOptions(host, ntp.QueryOptions{Version: 4, Timeout: 1 * time.Second})
	if err != nil {
		fmt.Printf("    Result: Error - %v\n\n", err.Error())
		os.Exit(1)
	}

	if verbose {
	/*
		fmt.Printf(" LocalTime: %v\n", time.Now())
		fmt.Printf("  XmitTime: %v\n", r.Time)
		fmt.Printf("   RefTime: %v\n", r.ReferenceTime)
	*/
		fmt.Printf("       RTT: %v\n", r.RTT)
		fmt.Printf("    Offset: %v\n", r.ClockOffset)
		fmt.Printf("      Poll: %v\n", r.Poll)
		fmt.Printf(" Precision: %v\n", r.Precision)
		fmt.Printf("   Stratum: %v\n", r.Stratum)
		// Only stratum 1 servers can have TMNL or something else as string refID
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
	// Validate checks if the response is valid for the purposes of time synchronization.
	// Will log KoD errors among a couple of other things, see
	// https://github.com/beevik/ntp/blob/master/ntp.go#L245	

	if err != nil {
		fmt.Printf("    Result: Error - %v\n\n", err.Error())
		os.Exit(2)
	} else {	
		if r.Stratum != stratum {
			fmt.Printf("    Result: Error - stratum mismatch, expected: %d and received: %v\n\n", stratum, r.Stratum)
			os.Exit(3)
		}
		// 100000000 nanoseconds is 0.1 second
		if (r.ClockOffset > 100000000) || (r.ClockOffset < -100000000) {
		//if (r.ClockOffset > 10000) || (r.ClockOffset < -10000) { // test values
			fmt.Printf("    Result: Error - oOffset out of bounds\n\n")
			os.Exit(4) // exit 2 for this particular case
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

// RefidToString decodes ASCII string encoded as uint32
// Only stratum 1 servers can have TMNL or something else as string refID
// thanks to https://github.com/facebook/time/
func RefidToString(refID uint32) string {
	result := []rune{}

	for i := 0; i < 4 && i < 64-1; i++ {
		c := rune((refID >> (24 - uint(i)*8)) & 0xff)
		if unicode.IsPrint(c) {
			result = append(result, c)
		}
	}

	return string(result)
}
