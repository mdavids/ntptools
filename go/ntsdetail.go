package main

//
// Work in progres!
//
// Is ntpdetail met kleine aanpassingen, zodat het werkt met NTS - is althans de bedoeling
//	TODO: checken of ntpversion echt anders is met huidige code (via wireshark)
//
import (
	"fmt"
	"net"
	"os"
	"time"

//	"github.com/beevik/ntp"
	"github.com/beevik/nts"
)

var emptyTime time.Time
var ntpversion int=4

var usage = `Usage: ntsdetail [HOST]
Get the time reported by the NTS server HOST.`

func main() {

	args := os.Args[1:]

        if len(args) < 1 {
                fmt.Println(usage)
                os.Exit(0)
        }
	TestQuery(args[0])
}

func customResolver(addr string) string {
	return "94.198.159.15:123"
}

func TestQuery(host string) {
	
	session, err := nts.NewSession(host)
	// met opties:
	//opt := &nts.SessionOptions{
	//	Resolver: customResolver,
	//}
	//session, err := nts.NewSessionWithOptions(host, opt)
	if err != nil {
		fmt.Printf("NTS session could not be established: %v\n", err.Error())
                os.Exit(1)
        }
        
        ntphost, ntpport, err := net.SplitHostPort(session.Address())
	if err != nil {
                fmt.Printf("Could not deduct NTP host and port: %v\n", err.Error())
                os.Exit(1)
        }

	fmt.Printf("\n\n[%s] ----------------------\n", host)
//	fmt.Printf("[%s] NTP protocol version %d\n", host, ntpversion)
	fmt.Printf("[%s] NTP host and port [%s]:%s\n", host, ntphost, ntpport)
	fmt.Printf("[%s] ----------------------\n", host)
	// oud, uit ntpdetail: 
	//r, err := ntp.QueryWithOptions(host, ntp.QueryOptions{Version: ntpversion})
	// nieuw, zonder opties:
	r, err := session.Query();
	// nieuw, met opties:
	//opt := &ntp.QueryOptions{ Version: ntpversion}
	//r, err :=session.QueryWithOptions(opt)
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
