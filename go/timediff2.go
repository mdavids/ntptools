package main

import (
	"fmt"
	"os"
	"time"

	"github.com/beevik/ntp"
)

var emptyTime time.Time

var usage = `Usage: timediff2 [HOST]
Get the time difference reported by the NTP server HOST.
Exit with error if offset is too high.`

func main() {

	args := os.Args[1:]

        if len(args) < 1 {
                fmt.Println(usage)
                os.Exit(1)
        }
        
	GetTime(args[0])
}

func GetTime(host string) {
	t, err := ntp.Time(host)
	if err != nil {
		fmt.Printf("Time could not be get: %v\n", err.Error())
		os.Exit(1)
	}
	now := time.Now()
	offset := t.Sub(now)
	offsetint := offset.Nanoseconds()
	// fmt.Printf("Local Time %v\n", now)
	// fmt.Printf("NTP Time %v\n", t)
	fmt.Printf("Offset %v\n", offset)
	// production values,  100 ms, als het goed is ;-)
	if (offsetint > 100000000) || (offsetint < -100000000) {
	// test values
	//if (offsetint > 100000) || (offsetint < -100000) {
		// fmt.Printf("Offset too high!\n")
		os.Exit(2) // exit 2 for this particular case
	}		
}

