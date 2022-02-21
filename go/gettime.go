package main

import (
	"fmt"
	"os"
	"time"

	"github.com/beevik/ntp"
)

var emptyTime time.Time

var usage = `Usage: gettime [HOST]
Get the time reported by the NTP server HOST.`

func main() {
	args := os.Args[1:]

	if len(args) < 1 {
		fmt.Println(usage)
		os.Exit(0)
	}

	tm, err := getTime(args[0])
	if err != nil {
		fmt.Printf("Time could not be get: %v\n", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Time sucessfully fetched: %v\n", tm)
}

func getTime(host string) (time.Time, error) {
	r, err := ntp.Query(host)
	if err != nil {
		return emptyTime, err
	}

	err = r.Validate()
	if err != nil {
		return emptyTime, err
	}

	t := time.Now().Add(r.ClockOffset)

	return t, err
}
