package main

import (
        "fmt"
        "os"
        "time"
        "math"
        "unicode"
        "net"
        "encoding/binary"

        "github.com/beevik/ntp"
)

var emptyTime time.Time

const (
        timeFormat = "Mon Jan _2 2006  15:04:05.000000000 (MST)"
)

var usage = `Usage: ntpdetail [HOST]
Get the details reported by the NTP server HOST.`

func main() {

        args := os.Args[1:]

        if len(args) < 1 {
                fmt.Println(usage)
                os.Exit(0)
        }
        TestQuery(args[0])
}

func TestQuery(host string) {
        now := time.Now()
        fmt.Printf("\n\n[%s] ----------------------\n", host)
        fmt.Printf("[%s] NTP protocol version %d\n", host, 4)
        fmt.Printf("[%s]  LocalTime: %v\n", host, now.Format(timeFormat))
        
        r, err := ntp.QueryWithOptions(host, ntp.QueryOptions{Version: 4})
        if err != nil {
                fmt.Printf("Failed to get time: %v\n", err.Error())
                os.Exit(1)
        }

        fmt.Printf("[%s]    +Offset: %v\n", host, time.Now().Add(r.ClockOffset).Format(timeFormat))
        fmt.Printf("[%s]   XmitTime: %v\n", host, r.Time.Format(timeFormat))
        fmt.Printf("[%s]    RefTime: %v\n", host, r.ReferenceTime.Format(timeFormat))
        //MD kan niet fmt.Printf("[%s]   OrigTime: %v\n", host, r.OriginTime)   
        fmt.Printf("[%s]        RTT: %v\n", host, r.RTT)
        fmt.Printf("[%s]     Offset: %v\n", host, r.ClockOffset)
        fmt.Printf("[%s]       Poll: %v (%v)\n", host, fromInterval(r.Poll),r.Poll)
        fmt.Printf("[%s]  Precision: %v (%v)\n", host, fromInterval(r.Precision),r.Precision)
        fmt.Printf("[%s]    Stratum: %v\n", host, r.Stratum)
        // Only stratum 1 servers can have TMNL or something else as string refID
        if r.Stratum == 1 {
                fmt.Printf("[%s]      RefID: %v (0x%08x)\n", host, RefidToString(r.ReferenceID), r.ReferenceID)
        } else {
                fmt.Printf("[%s]      RefID: %v (0x%08x)\n", host, RefidToIPv4(r.ReferenceID), r.ReferenceID)
        }
        //beevik/ntp has this too - either missed it or it was added later ;-)
        //fmt.Printf("[%s]      RefID: %s (0x%08x)\n", host, r.ReferenceString(), r.ReferenceID)
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

// Poor man's method to get h.Poll back
// Probably not the recommended best way - but it works for now.
func fromInterval(d time.Duration) int8 {
        seconds := d.Seconds()
        exp := math.Log2(seconds)
        return int8(math.Round(exp))
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

func RefidToIPv4(refID uint32) string {
        ip := make(net.IP, 4)
        binary.BigEndian.PutUint32(ip, refID)
        return ip.String()
}
