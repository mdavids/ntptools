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
        
	TestTime(args[0])
}

func TestTime(host string) {
	t, err := ntp.Time(host)
	if err != nil {
		fmt.Printf("Time could not be get: %v\n", err.Error())
		os.Exit(1)
	}
	now := time.Now()
	fmt.Printf("Local Time %v\n", now)
	fmt.Printf("~True Time %v\n", t)
	fmt.Printf("Offset %v\n", t.Sub(now))
}

