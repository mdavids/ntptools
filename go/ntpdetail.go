package main

import (
	"fmt"
	"os"
	"time"

	"github.com/beevik/ntp"
)

//const (
//	host  = "ntp4.linocomm.net" // ntp.vsl.nl, time1.ea.int of pool.ntp.org enz.
//)

var emptyTime time.Time

var usage = `Usage: gettime [HOST]
Get the time reported by the NTP server HOST.`

func main() {

	args := os.Args[1:]

        if len(args) < 1 {
                fmt.Println(usage)
                os.Exit(0)
        }
	TestQuery(args[0])
}

func TestQuery(host string) {
	fmt.Printf("\n\n[%s] ----------------------\n", host)
	fmt.Printf("[%s] NTP protocol version %d\n", host, 4)

	r, err := ntp.QueryWithOptions(host, ntp.QueryOptions{Version: 4})
	if err != nil {
		fmt.Printf("Time could not be get: %v\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("[%s]  LocalTime: %v\n", host, time.Now())
	//fmt.Printf("[%s]  LocalTime+Offset: %v\n", host, time.Now().Add(r.ClockOffset))
	fmt.Printf("[%s]   XmitTime: %v\n", host, r.Time)
	fmt.Printf("[%s]    RefTime: %v\n", host, r.ReferenceTime)
	//MD kan niet fmt.Printf("[%s]   OrigTime: %v\n", host, r.OriginTime)	
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
	
	err = r.Validate()
	if err != nil {
		fmt.Printf("\nError: %v\n", err.Error())
		os.Exit(1)
	}
	
	fmt.Printf("\n\n")
}

func stringOrEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}
