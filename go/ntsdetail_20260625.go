// ntsdetail establishes an NTS (Network Time Security, RFC 8915) session
// with one or more servers, performs the resulting authenticated NTP
// query, and reports the details of the response.
//
// Vibe coded improvement of ntsdetail.go - made with Claude.ai
//
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"
)

const timeFormat = "Mon Jan _2 2006  15:04:05.000000000 (MST)"

var usage = `Usage: ntsdetail [options] HOST [HOST ...]
Perform an NTS key exchange with HOST, then query the resulting NTP
server and report the details of its response.

Options:
  -version int    NTP protocol version to use: 2, 3 or 4 (default 4)
  -timeout dur    Timeout for both the NTS-KE handshake and the NTP
                  query, e.g. 2s, 500ms (default 5s)
  -4              Force IPv4
  -6              Force IPv6
  -json           Emit machine-readable JSON instead of formatted text
`

// ---------------------------------------------------------------------
// Result captures everything we report about one host, for both the
// formatted and JSON output paths.
// ---------------------------------------------------------------------

type Result struct {
	Host          string `json:"host"`
	ResolvedNTP   string `json:"resolved_ntp_server,omitempty"`

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
	timeout := flag.Duration("timeout", 5*time.Second, "timeout for NTS-KE handshake and NTP query")
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
		fmt.Fprintln(os.Stderr, "ntsdetail: -4 and -6 are mutually exclusive")
		os.Exit(2)
	}

	// "" leaves family selection up to the system, exactly as before.
	family := ""
	switch {
	case *ipv4:
		family = "4"
	case *ipv6:
		family = "6"
	}

	exitCode := 0
	for i, host := range hosts {
		res := query(host, *version, *timeout, family)
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

func query(host string, version int, timeout time.Duration, family string) Result {
	res := Result{Host: host, LocalTime: time.Now()}

	sessOpts := &nts.SessionOptions{Timeout: timeout}
	queryOpts := &ntp.QueryOptions{Version: version, Timeout: timeout}

	if family != "" {
		tcpNetwork := "tcp" + family
		udpNetwork := "udp" + family

		// SessionOptions.Dialer overrides the TLS dial used for the
		// NTS-KE handshake (a TCP connection). QueryOptions.Dialer
		// overrides the dial used for the resulting NTP query over
		// UDP. Both need to be pinned to get a consistent address
		// family end to end - one without the other would still let
		// the "wrong" family slip in on one leg of the exchange.
		sessOpts.Dialer = func(_, addr string, tlsConfig *tls.Config) (*tls.Conn, error) {
			return tls.Dial(tcpNetwork, addr, tlsConfig)
		}
		queryOpts.Dialer = func(_, addr string) (net.Conn, error) {
			return net.Dial(udpNetwork, addr)
		}
	}

	session, err := nts.NewSessionWithOptions(host, sessOpts)
	if err != nil {
		res.Error = fmt.Sprintf("NTS session could not be established: %v", err)
		return res
	}

	res.ResolvedNTP = session.Address()

	r, err := session.QueryWithOptions(queryOpts)
	if err != nil {
		res.Error = fmt.Sprintf("NTP query failed: %v", err)
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

	if res.Error != "" && res.XmitTime.IsZero() {
		// Covers both "NTS-KE handshake failed" and "NTP query
		// failed": neither leaves us with timing data worth printing.
		fmt.Printf("  %s\n", res.Error)
		return
	}

	fmt.Printf("\n  NTS\n")
	if res.ResolvedNTP != "" {
		fmt.Printf("    %-14s %s\n", "Resolved:", res.ResolvedNTP)
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
// is a "poor man's" inverse - fine for display purposes, since Poll and
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
