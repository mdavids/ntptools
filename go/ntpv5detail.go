package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/beevik/ntp"
)

func main() {
	var (
		server  string
		version int
		timeout time.Duration
		verbose bool
	)

	flag.StringVar(&server, "server", "pool.ntp.org", "NTP server address")
	flag.IntVar(&version, "version", 5, "NTP protocol version (4 or 5)")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "Query timeout")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output")
	flag.Parse()

	if version != 4 && version != 5 {
		log.Fatal("Version must be 4 or 5")
	}

	fmt.Printf("=== NTP Query Detail Tool ===\n")
	fmt.Printf("Server: %s\n", server)
	fmt.Printf("Version: %d\n", version)
	fmt.Printf("Timeout: %v\n\n", timeout)

	// Configure query options
	opts := ntp.QueryOptions{
		Timeout: timeout,
		Version: version,
	}

	// Perform the query
	fmt.Printf("Querying server...\n")
	startTime := time.Now()
	response, err := ntp.QueryWithOptions(server, opts)
	queryDuration := time.Since(startTime)

	if err != nil {
		log.Fatalf("Query failed: %v", err)
	}

	// Display results
	fmt.Printf("\n=== Query Results ===\n")
	fmt.Printf("Query duration: %v\n", queryDuration)
	fmt.Printf("Local time: %v\n", time.Now())
	fmt.Printf("Server time: %v\n", response.Time)
	fmt.Printf("Clock offset: %v\n", response.ClockOffset)
	fmt.Printf("Corrected local time: %v\n\n", time.Now().Add(response.ClockOffset))

	// Display detailed NTP packet information
	fmt.Printf("=== NTP Packet Details ===\n")
	displayPacketInfo(response, version, verbose)

	// Validate response
	fmt.Printf("\n=== Response Validation ===\n")
	if err := response.Validate(); err != nil {
		fmt.Printf("❌ Validation failed: %v\n", err)
	} else {
		fmt.Printf("✓ Response is valid for time synchronization\n")
	}

	// Display accuracy metrics
	fmt.Printf("\n=== Accuracy Metrics ===\n")
	displayAccuracyMetrics(response)

	// Exit with appropriate code
	if err := response.Validate(); err != nil {
		os.Exit(1)
	}
}

func displayPacketInfo(r *ntp.Response, version int, verbose bool) {
	// Basic fields present in all versions
	fmt.Printf("Leap Indicator: %v", leapIndicatorString(r.Leap))
	if r.Leap != ntp.LeapNoWarning {
		fmt.Printf(" ⚠️")
	}
	fmt.Printf("\n")

	fmt.Printf("Version: %d\n", version)
	fmt.Printf("Stratum: %d", r.Stratum)
	if r.Stratum == 0 {
		fmt.Printf(" (Kiss-o'-Death)")
		if r.KissCode != "" {
			fmt.Printf(" - Code: %s", r.KissCode)
		}
	} else if r.Stratum == 1 {
		fmt.Printf(" (Primary Reference)")
	} else {
		fmt.Printf(" (Secondary Reference)")
	}
	fmt.Printf("\n")

	// Reference ID
	fmt.Printf("Reference ID: 0x%08X", r.ReferenceID)
	if r.Stratum == 0 && r.KissCode != "" {
		fmt.Printf(" (%s)", r.KissCode)
	} else if r.Stratum == 1 {
		// Try to decode as ASCII for stratum 1
		ref := make([]byte, 4)
		ref[0] = byte(r.ReferenceID >> 24)
		ref[1] = byte(r.ReferenceID >> 16)
		ref[2] = byte(r.ReferenceID >> 8)
		ref[3] = byte(r.ReferenceID)
		fmt.Printf(" (%s)", string(ref))
	}
	fmt.Printf("\n")

	// Timing information
	fmt.Printf("Reference Time: %v\n", r.ReferenceTime)
	fmt.Printf("Origin Time: [Client transmit time]\n")
	fmt.Printf("Receive Time: [Server receive time]\n")
	fmt.Printf("Transmit Time: %v\n", r.Time)

	// Precision and accuracy
	fmt.Printf("Precision: %v\n", r.Precision)
	fmt.Printf("Poll Interval: %v\n", r.Poll)

	// Network delays and dispersions
	fmt.Printf("Root Delay: %v\n", r.RootDelay)
	fmt.Printf("Root Dispersion: %v\n", r.RootDispersion)
	fmt.Printf("Root Distance: %v\n", r.RootDistance)

	// Round-trip time
	fmt.Printf("Round-Trip Time (RTT): %v\n", r.RTT)
	fmt.Printf("Min Error: %v\n", r.MinError)

	// Version-specific information
	if version == 5 {
		fmt.Printf("\n--- NTPv5 Specific Fields ---\n")
		fmt.Printf("Note: NTPv5 features enhanced security, better loop detection,\n")
		fmt.Printf("      support for multiple timescales, and improved resolution.\n")
		
		if verbose {
			fmt.Printf("\nNTPv5 Improvements over NTPv4:\n")
			fmt.Printf("  • Era number support (extends time range to ~35000 years)\n")
			fmt.Printf("  • Separate flags for synchronized server clock\n")
			fmt.Printf("  • Enhanced reference ID (120-bit) for better loop prevention\n")
			fmt.Printf("  • Improved root delay/dispersion resolution (~4ns vs ~15μs)\n")
			fmt.Printf("  • Explicit interleaved mode flag\n")
			fmt.Printf("  • Support for non-UTC timescales\n")
			fmt.Printf("  • Only client-server mode (broadcast/symmetric modes removed)\n")
		}
	}
}

func displayAccuracyMetrics(r *ntp.Response) {
	// Calculate various accuracy metrics
	fmt.Printf("Server Stratum: %d\n", r.Stratum)
	
	// Estimate accuracy based on stratum and delays
	var estimatedAccuracy string
	switch {
	case r.Stratum == 0:
		estimatedAccuracy = "Invalid (Kiss-o'-Death)"
	case r.Stratum == 1:
		estimatedAccuracy = "< 1 ms (directly connected to reference clock)"
	case r.Stratum <= 3:
		estimatedAccuracy = "1-10 ms (good)"
	case r.Stratum <= 6:
		estimatedAccuracy = "10-100 ms (acceptable)"
	default:
		estimatedAccuracy = "> 100 ms (poor quality)"
	}
	fmt.Printf("Estimated Accuracy: %s\n", estimatedAccuracy)

	// Display synchronization quality
	fmt.Printf("RTT Quality: ")
	if r.RTT < 10*time.Millisecond {
		fmt.Printf("Excellent (< 10ms)\n")
	} else if r.RTT < 50*time.Millisecond {
		fmt.Printf("Good (< 50ms)\n")
	} else if r.RTT < 100*time.Millisecond {
		fmt.Printf("Fair (< 100ms)\n")
	} else {
		fmt.Printf("Poor (≥ 100ms)\n")
	}

	// Root distance quality
	fmt.Printf("Root Distance Quality: ")
	if r.RootDistance < 10*time.Millisecond {
		fmt.Printf("Excellent (< 10ms)\n")
	} else if r.RootDistance < 50*time.Millisecond {
		fmt.Printf("Good (< 50ms)\n")
	} else if r.RootDistance < 100*time.Millisecond {
		fmt.Printf("Fair (< 100ms)\n")
	} else {
		fmt.Printf("Poor (≥ 100ms)\n")
	}
}

func leapIndicatorString(leap ntp.LeapIndicator) string {
	switch leap {
	case ntp.LeapNoWarning:
		return "No warning"
	case ntp.LeapAddSecond:
		return "Last minute of day has 61 seconds"
	case ntp.LeapDelSecond:
		return "Last minute of day has 59 seconds"
	case ntp.LeapNotInSync:
		return "Clock not synchronized"
	default:
		return fmt.Sprintf("Unknown (%d)", leap)
	}
}
