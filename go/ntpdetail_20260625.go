// ntpdetail queries one or more NTP servers and reports the details of
// their response: offset, RTT, stratum, reference info, root distance,
// leap-second status, etc.
//
// Vibe coded improvement of ntpdetail.go - made with Claude.ai
//
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/beevik/ntp"
)

const timeFormat = "Mon Jan _2 2006  15:04:05.000000000 (MST)"

var usage = `Usage: ntpdetail [options] HOST [HOST ...]
Query one or more NTP servers and report the details of their response.

Options:
  -version int    NTP protocol version to use: 2, 3 or 4 (default 4)
  -timeout dur    Query timeout, e.g. 2s, 500ms (default 5s)
  -port int       UDP port to query (default 123)
  -4              Force IPv4
  -6              Force IPv6
  -json           Emit machine-readable JSON instead of formatted text
`

// ---------------------------------------------------------------------
// Result captures everything we report about one host, for both the
// formatted and JSON output paths.
// ---------------------------------------------------------------------

type Result struct {
	Host string `json:"host"`

	LocalTime  time.Time `json:"local_time"`
	OffsetTime time.Time `json:"offset_time"`
	XmitTime   time.Time `json:"xmit_time"`
	RefTime    time.Time `json:"ref_time"`

	RTT    time.Duration `json:"rtt_ns"`
	Offset time.Duration `json:"offset_ns"`

	Poll         time.Duration `json:"poll_ns"`
	PollExp      int8          `json:"poll_exponent"`
	Precision    time.Duration `json:"precision_ns"`
	PrecisionExp int8          `json:"precision_exponent"`

	Stratum  uint8  `json:"stratum"`
	RefID    string `json:"ref_id"`
	RefIDRaw uint32 `json:"ref_id_raw"`

	RootDelay      time.Duration `json:"root_delay_ns"`
	RootDispersion time.Duration `json:"root_dispersion_ns"`
	RootDistance   time.Duration `json:"root_distance_ns"`
	MinError       time.Duration `json:"min_error_ns"`

	Leap    string `json:"leap"`
	LeapRaw uint8  `json:"leap_raw"`

	KissCode string `json:"kiss_code,omitempty"`
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
}

func main() {
	version := flag.Int("version", 4, "NTP protocol version (2, 3 or 4)")
	timeout := flag.Duration("timeout", 5*time.Second, "query timeout")
	port := flag.Int("port", 123, "UDP port to query")
	jsonOut := flag.Bool("json", false, "emit JSON instead of formatted text")
	ipv4 := flag.Bool("4", false, "force IPv4")
	ipv6 := flag.Bool("6", false, "force IPv6")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	hosts := flag.Args()
	if len(hosts) < 1 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(0)
	}
	if *ipv4 && *ipv6 {
		fmt.Fprintln(os.Stderr, "ntpdetail: -4 and -6 are mutually exclusive")
		os.Exit(2)
	}

	network := "udp" // let the system decide, as before
	switch {
	case *ipv4:
		network = "udp4"
	case *ipv6:
		network = "udp6"
	}

	exitCode := 0
	for i, host := range hosts {
		addr := host
		if *port != 123 {
			addr = host + ":" + strconv.Itoa(*port)
		}

		res := query(host, addr, *version, *timeout, network)
		if res.Error != "" {
			exitCode = 1
		}

		if *jsonOut {
			printJSON(res)
		} else {
			printFormatted(res)
		}

		if i < len(hosts)-1 && !*jsonOut {
			fmt.Println()
		}
	}
	os.Exit(exitCode)
}

func query(host, addr string, version int, timeout time.Duration, network string) Result {
	now := time.Now()
	res := Result{
		Host:      host,
		LocalTime: now,
	}

	opts := ntp.QueryOptions{Version: version, Timeout: timeout}
	if network != "udp" {
		// QueryOptions has no built-in "force IPv4/IPv6" switch, but it
		// does let us override the dialer entirely. remoteAddress is
		// guaranteed by the library to already include a port, so a
		// plain net.Dial with the udp4/udp6 network name is enough to
		// pin the address family — net.Dial resolves the hostname
		// itself and filters to that family.
		opts.Dialer = func(localAddress, remoteAddress string) (net.Conn, error) {
			return net.Dial(network, remoteAddress)
		}
	}

	r, err := ntp.QueryWithOptions(addr, opts)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	res.OffsetTime = time.Now().Add(r.ClockOffset)
	res.XmitTime = r.Time
	res.RefTime = r.ReferenceTime
	res.RTT = r.RTT
	res.Offset = r.ClockOffset
	res.Poll = r.Poll
	res.PollExp = fromInterval(r.Poll)
	res.Precision = r.Precision
	res.PrecisionExp = fromInterval(r.Precision)
	res.Stratum = r.Stratum
	res.RefIDRaw = r.ReferenceID
	// r.ReferenceString() already handles the stratum 0 / 1 / >=2 cases
	// correctly (kiss code / reference clock name / IPv4-or-IPv6-hash),
	// so there's no need to hand-roll that decoding.
	res.RefID = r.ReferenceString()
	res.RootDelay = r.RootDelay
	res.RootDispersion = r.RootDispersion
	res.RootDistance = r.RootDistance
	res.MinError = r.MinError
	res.LeapRaw = uint8(r.Leap)
	res.Leap = leapString(r.Leap)
	res.KissCode = r.KissCode

	if verr := r.Validate(); verr != nil {
		res.Error = verr.Error()
		return res
	}
	res.Valid = true

	return res
}

func printJSON(res Result) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}

func printFormatted(res Result) {
	fmt.Printf("Host: %s\n", res.Host)

	if res.Error != "" && !res.Valid {
		// Distinguish "couldn't reach server at all" from "got a
		// response but Validate() rejected it" — both end up here,
		// but only the latter has timing fields worth printing.
		if res.XmitTime.IsZero() {
			fmt.Printf("  Failed to get time: %s\n", res.Error)
			return
		}
	}

	fmt.Printf("\n  Identity\n")
	fmt.Printf("    %-14s %v\n", "Stratum:", strat(res.Stratum))
	fmt.Printf("    %-14s %s (0x%08x)\n", "RefID:", res.RefID, res.RefIDRaw)
	fmt.Printf("    %-14s %s\n", "Leap:", res.Leap)
	if res.KissCode != "" {
		fmt.Printf("    %-14s %s\n", "KissCode:", res.KissCode)
	}

	fmt.Printf("\n  Timing\n")
	fmt.Printf("    %-14s %v\n", "LocalTime:", res.LocalTime.Format(timeFormat))
	fmt.Printf("    %-14s %v\n", "LocalUTC:", res.LocalTime.UTC().Format(timeFormat))
	fmt.Printf("    %-14s %v\n", "+Offset:", res.OffsetTime.Format(timeFormat))
	fmt.Printf("    %-14s %v\n", "+OffsetUTC:", res.OffsetTime.UTC().Format(timeFormat))
	fmt.Printf("    %-14s %v\n", "XmitTime:", res.XmitTime.Format(timeFormat))
	fmt.Printf("    %-14s %v\n", "RefTime:", res.RefTime.Format(timeFormat))
	fmt.Printf("    %-14s %v\n", "Offset:", res.Offset)
	fmt.Printf("    %-14s %v\n", "RTT:", res.RTT)
	fmt.Printf("    %-14s %v (%d)\n", "Poll:", res.Poll, res.PollExp)
	fmt.Printf("    %-14s %v (%d)\n", "Precision:", res.Precision, res.PrecisionExp)

	fmt.Printf("\n  Network Quality\n")
	fmt.Printf("    %-14s %v\n", "RootDelay:", res.RootDelay)
	fmt.Printf("    %-14s %v\n", "RootDisp:", res.RootDispersion)
	fmt.Printf("    %-14s %v\n", "RootDist:", res.RootDistance)
	fmt.Printf("    %-14s %v\n", "MinError:", res.MinError)

	fmt.Println()
	if res.Valid {
		fmt.Println("  valid for synchronization")
	} else {
		fmt.Printf("  not valid: %s\n", res.Error)
	}
}

func strat(s uint8) string {
	switch {
	case s == 0:
		return fmt.Sprintf("%d (kiss of death)", s)
	case s == 1:
		return fmt.Sprintf("%d (reference clock)", s)
	default:
		return strconv.Itoa(int(s))
	}
}

// leapString translates the LeapIndicator into the RFC 5905 meaning.
// Values per github.com/beevik/ntp: 0 = no warning, 1 = last minute of
// the month has 61 seconds, 2 = last minute has 59 seconds, 3 = clock
// unsynchronized.
func leapString(l ntp.LeapIndicator) string {
	switch l {
	case ntp.LeapNoWarning:
		return "no warning"
	case ntp.LeapAddSecond:
		return "+1 leap second this month"
	case ntp.LeapDelSecond:
		return "-1 leap second this month"
	case ntp.LeapNotInSync:
		return "not synchronized"
	default:
		return fmt.Sprintf("unknown (%d)", l)
	}
}

// fromInterval recovers the original protocol-level exponent (seconds =
// 2^exp) from the time.Duration that the beevik/ntp library hands back.
// The library only exposes the already-converted Duration, not the raw
// int8 it decoded from the wire, so this reconstructs it via log2. This
// is a "poor man's" inverse — fine for display purposes, since Poll and
// Precision exponents are always small integers and round only needs to
// undo floating-point noise from the original Duration conversion.
func fromInterval(d time.Duration) int8 {
	seconds := d.Seconds()
	if seconds <= 0 {
		return 0
	}
	exp := math.Log2(seconds)
	return int8(math.Round(exp))
}
