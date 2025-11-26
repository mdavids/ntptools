package main

import (
	"fmt"
	"os"
	"time"
	"strconv"

	"github.com/beevik/ntp"
)

var emptyTime time.Time

var usage = `Usage: monitor <host> [<stratum>]
Default expected stratum is 1, but this can optionally be changed.`

func main() {

	var stratumopt int

        if len(os.Args[1:]) < 1 {
                fmt.Println(usage)
                os.Exit(0)
        }
        if len(os.Args[1:]) ==  2 {
        	stratopt, err := strconv.Atoi(os.Args[2])
        	if err != nil {
        		panic(err)
        	}
        	stratumopt = stratopt
	} else {
		stratumopt = 1
	}
	RunQuery(os.Args[1], uint8(stratumopt))
}

func RunQuery(host string, stratum uint8) {
	//fmt.Printf("[%s] NTP protocol version %d\n", host, 4)
/*
	fmt.Printf("[%s] Stratcheck: %d\n", host, stratum)
	fmt.Printf("[%s] ----------------------\n", host)
*/
	r, err := ntp.QueryWithOptions(host, ntp.QueryOptions{Version: 4})
	if err != nil {
		fmt.Printf("[%s] %v Error: Time could not be get: %v\n", host, time.Now(), err.Error())
		os.Exit(1)
	}
/*
	fmt.Printf("[%s]  LocalTime: %v\n", host, time.Now())
	fmt.Printf("[%s]   XmitTime: %v\n", host, r.Time)
	fmt.Printf("[%s]    RefTime: %v\n", host, r.ReferenceTime)
	fmt.Printf("[%s]        RTT: %v\n", host, r.RTT)
	fmt.Printf("[%s]     Offset: %v\n", host, r.ClockOffset)
	fmt.Printf("[%s]       Poll: %v\n", host, r.Poll)
	fmt.Printf("[%s]  Precision: %v\n", host, r.Precision)
	fmt.Printf("[%s]    Stratum: %v\n", host, r.Stratum)
	fmt.Printf("[%s]      RefID: 0x%08x\n", host, r.ReferenceID)
	fmt.Printf("[%s]  RootDelay: %v\n", host, r.RootDelay)
	fmt.Printf("[%s]   RootDisp: %v\n", host, r.RootDispersion)
	fmt.Printf("[%s]   RootDist: %v\n", host, r.RootDistance)
	fmt.Printf("[%s]   MinError: %v\n", host, r.MinError)
	fmt.Printf("[%s]       Leap: %v\n", host, r.Leap)
	fmt.Printf("[%s]   KissCode: %v\n", host, stringOrEmpty(r.KissCode))
*/	
	err = r.Validate()
	// https://github.com/beevik/ntp/blob/master/ntp.go#L245

	if err != nil {
		fmt.Printf("[%s] %v Error: %v\n", host, time.Now(), err.Error())
		os.Exit(1)
	} else {	
		if r.Stratum != stratum {
			fmt.Printf("[%s] %v Error: Stratum mismatch, expected: %d and received: %v\n", host, time.Now(), stratum, r.Stratum)
			os.Exit(1)
		}
	}
	//fmt.Printf("\n\n")
}

func stringOrEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}
