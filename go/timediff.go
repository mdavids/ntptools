//
// M. Davids
// SIDN Labs
// Credits: https://github.com/beevik/ntp/blob/master/ntp_test.go#L51
//
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/beevik/ntp"
)

var emptyTime time.Time

var usage = `Usage: timediff [HOST]
Get the time difference reported by the NTP server HOST.`

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
