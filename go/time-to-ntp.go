package main

import (
	"fmt"
	"time"
)

// timeToNtp zet een time.Time om naar NTP timestamp (seconds, fractional)
func timeToNtp(t time.Time) (uint32, uint32) {
	const ntpEpochOffset = 2208988800 // Aantal seconden tussen 1900 en 1970
	unixSecs := uint64(t.Unix()) + ntpEpochOffset
	nanos := uint64(t.Nanosecond())
	frac := (nanos * (1 << 32)) / 1_000_000_000
	return uint32(unixSecs), uint32(frac)
}

// ntpFractionToFloat zet een NTP fractioneel deel (32 bit) om naar fractie van een seconde
func ntpFractionToFloat(frac uint32) float64 {
	return float64(frac) / float64(1<<32)
}

func main() {
	// Huidige tijd
	now := time.Now().UTC()

	// Omzetten naar NTP-timestamp
	sec, frac := timeToNtp(now)

	// Format string (nanoseconden + tijdzone)
	timeFormat := "Mon Jan _2 2006 15:04:05.000000000 (MST)"
	
	// Decimale timestamp
	ntpFloat := float64(sec) + ntpFractionToFloat(frac)

	// Resultaten printen
	fmt.Printf("\nHuidige tijd: %s\n", now.Format(timeFormat))
	fmt.Printf("   Unix time:   %d seconds, %d nanoseconds\n", now.Unix(), now.Nanosecond())
	//fmt.Printf("    NTP tijd:    %08x.%08x (seconds.fraction)\n\n", sec, frac)
	fmt.Printf("    NTP tijd:     %08x.%08x (%.9f)\n", sec, frac, ntpFloat)
}
