// ntsdetail establishes an NTS (Network Time Security, RFC 8915) session
// with one or more servers, performs the resulting authenticated NTP
// query, and reports the details of the response.
//
// Vibe coded improvement of ntsdetail.go - made with Claude.ai
//
// Version 20260702_3a
//
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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

// certTimeFormat is used for X.509 certificate validity fields, which
// per RFC 5280 §4.1.2.5.2 ("GeneralizedTime values MUST NOT include
// fractional seconds") never carry sub-second precision - unlike the
// NTP timestamps timeFormat is meant for, so printing nine zeroed
// fractional digits there would just be false precision.
const certTimeFormat = "Mon Jan _2 2006  15:04:05 (MST)"

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
  -assume-compliant-128gcm
                  Skip AES-128-GCM-SIV compliance negotiation and assume
                  the server already uses the RFC 8915-compliant key
                  exporter context (nts.SessionOptions.AssumeCompliant128GCM).
                  Default is false, which is the safe choice while
                  non-patched chrony servers (algorithm ID 15 instead of
                  30) are still in use. See:
                  https://chrony-project.org/doc/spec/nts-compliant-128gcm.html
  -request-ntp-address host
                  Ask the NTS-KE server to associate this NTP server
                  address instead of letting it choose
                  (nts.SessionOptions.RequestedNTPServerAddress). The
                  server may ignore this request.
  -request-ntp-port int
                  Port to go with -request-ntp-address
                  (nts.SessionOptions.RequestedNTPServerPort). Ignored if
                  -request-ntp-address is not set. 0 means "let the
                  server pick the port" (default).
  -override-ntp-server host:port
                  Client-side override: ignore whatever NTP server
                  address the KE server returns and always use this one
                  instead (nts.SessionOptions.Resolver). Unlike
                  -request-ntp-address, this is not a request the server
                  can decline - it fully bypasses the server's answer.
  -tls-server-name name
                  Override the SNI/certificate-validation hostname used
                  for the NTS-KE TLS handshake (tls.Config.ServerName).
                  Useful together with -override-ntp-server or a forced
                  address family when connecting to a specific anycast
                  node by IP while still validating its certificate
                  against the service's real hostname.
  -tls-ca-file path
                  PEM file with CA certificate(s) to trust for the NTS-KE
                  TLS handshake, instead of the system trust store
                  (tls.Config.RootCAs).
  -tls-insecure-skip-verify
                  Disable TLS certificate verification for the NTS-KE
                  handshake (tls.Config.InsecureSkipVerify). Diagnostic
                  use only, to isolate whether a failure is caused by
                  the certificate or by something else in the handshake
                  - never use this to trust a result. A warning is
                  printed to stderr whenever this is active.

  Note: the NTS-KE handshake always negotiates ALPN "ntske/1" and
  requires TLS 1.3 or higher, regardless of the TLS options above - the
  nts library enforces both unconditionally.
`

// ---------------------------------------------------------------------
// Result captures everything we report about one host, for both the
// formatted and JSON output paths.
// ---------------------------------------------------------------------

type Result struct {
	Host        string `json:"host"`
	ResolvedNTP string `json:"resolved_ntp_server,omitempty"`

	KEHandshake time.Duration `json:"ke_handshake_ns,omitempty"`

	// TLS details captured from the NTS-KE handshake connection. Only
	// populated when the TLS handshake completed - a failure before or
	// during it leaves these at their zero value.
	TLSVersion          string    `json:"tls_version,omitempty"`
	TLSCipherSuite      string    `json:"tls_cipher_suite,omitempty"`
	TLSALPNProtocol     string    `json:"tls_alpn_protocol,omitempty"`
	TLSPeerCertSubject  string    `json:"tls_peer_cert_subject,omitempty"`
	TLSPeerCertIssuer   string    `json:"tls_peer_cert_issuer,omitempty"`
	TLSPeerCertNotAfter time.Time `json:"tls_peer_cert_not_after,omitempty"`

	// NTSErrorKind classifies Error against the nts package's exported
	// sentinel errors (ErrAuthFailedOnClient and friends), when it
	// matches one. Empty if Error is unset or doesn't match a known NTS
	// sentinel (e.g. a plain network or TLS error).
	NTSErrorKind string `json:"nts_error_kind,omitempty"`

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
	assumeCompliant128GCM := flag.Bool("assume-compliant-128gcm", false, "skip AES-128-GCM-SIV compliance negotiation and assume the server is already RFC 8915-compliant")
	requestNTPAddress := flag.String("request-ntp-address", "", "ask the NTS-KE server to associate this NTP server address (may be ignored)")
	requestNTPPort := flag.Int("request-ntp-port", 0, "port to go with -request-ntp-address")
	overrideNTPServer := flag.String("override-ntp-server", "", "client-side override: always use this host:port instead of what the NTS-KE server returns")
	tlsServerName := flag.String("tls-server-name", "", "override the SNI/certificate-validation hostname for the NTS-KE TLS handshake")
	tlsCAFile := flag.String("tls-ca-file", "", "PEM file with CA certificate(s) to trust for the NTS-KE TLS handshake")
	tlsInsecureSkipVerify := flag.Bool("tls-insecure-skip-verify", false, "disable TLS certificate verification for the NTS-KE handshake (diagnostic use only)")
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
	if *overrideNTPServer != "" {
		if _, _, err := net.SplitHostPort(*overrideNTPServer); err != nil {
			fmt.Fprintf(os.Stderr, "ntsdetail: -override-ntp-server must be host:port: %s\n", err)
			os.Exit(2)
		}
	}

	var tlsCAPool *x509.CertPool
	if *tlsCAFile != "" {
		pem, err := os.ReadFile(*tlsCAFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ntsdetail: -tls-ca-file: %s\n", err)
			os.Exit(2)
		}
		tlsCAPool = x509.NewCertPool()
		if !tlsCAPool.AppendCertsFromPEM(pem) {
			fmt.Fprintf(os.Stderr, "ntsdetail: -tls-ca-file: no valid PEM certificates found in %s\n", *tlsCAFile)
			os.Exit(2)
		}
	}
	if *tlsInsecureSkipVerify {
		fmt.Fprintln(os.Stderr, "ntsdetail: WARNING: -tls-insecure-skip-verify is set, TLS certificate verification is disabled - results are not trustworthy for anything but isolating handshake problems")
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
		res := query(host, queryOptions{
			version:               *version,
			timeout:               *timeout,
			family:                family,
			assumeCompliant128GCM: *assumeCompliant128GCM,
			requestNTPAddress:     *requestNTPAddress,
			requestNTPPort:        *requestNTPPort,
			overrideNTPServer:     *overrideNTPServer,
			tlsServerName:         *tlsServerName,
			tlsCAPool:             tlsCAPool,
			tlsInsecureSkipVerify: *tlsInsecureSkipVerify,
		})
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

// queryOptions bundles the per-host knobs so query()'s signature doesn't
// keep growing every time a new nts.SessionOptions field becomes useful
// to expose on the command line.
type queryOptions struct {
	version               int
	timeout               time.Duration
	family                string
	assumeCompliant128GCM bool
	requestNTPAddress     string
	requestNTPPort        int
	overrideNTPServer     string
	tlsServerName         string
	tlsCAPool             *x509.CertPool
	tlsInsecureSkipVerify bool
}

// classifyNTSError checks err against the nts package's exported
// sentinel errors and returns a short machine-readable label when it
// matches one. These sentinels can originate from either the NTS-KE
// handshake or the subsequent authenticated NTP query - the nts package
// docs don't pin each one to a single phase, so this doesn't try to
// guess which. Returns "" if err is nil or doesn't match a known
// sentinel (e.g. a plain network, DNS, or TLS error).
func classifyNTSError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, nts.ErrAuthFailedOnClient):
		return "auth_failed_on_client"
	case errors.Is(err, nts.ErrAuthFailedOnServer):
		return "auth_failed_on_server (have you tried using the '-assume-compliant-128gcm' option?)"
	case errors.Is(err, nts.ErrInvalidFormat):
		return "invalid_format"
	case errors.Is(err, nts.ErrNoCookies):
		return "no_cookies"
	case errors.Is(err, nts.ErrUniqueIDMismatch):
		return "unique_id_mismatch"
	default:
		return ""
	}
}

func query(host string, o queryOptions) Result {
	res := Result{Host: host, LocalTime: time.Now()}

	sessOpts := &nts.SessionOptions{
		Timeout:                   o.timeout,
		AssumeCompliant128GCM:     o.assumeCompliant128GCM,
		RequestedNTPServerAddress: o.requestNTPAddress,
		RequestedNTPServerPort:    o.requestNTPPort,
	}
	if o.tlsServerName != "" || o.tlsCAPool != nil || o.tlsInsecureSkipVerify {
		// NewSessionWithOptions clones this config and unconditionally
		// overwrites NextProtos to ["ntske/1"] and enforces a TLS 1.3
		// floor, so we don't set either here - the library ignores
		// them anyway. ServerName, RootCAs and InsecureSkipVerify are
		// respected as given.
		sessOpts.TLSConfig = &tls.Config{
			ServerName:         o.tlsServerName,
			RootCAs:            o.tlsCAPool,
			InsecureSkipVerify: o.tlsInsecureSkipVerify,
		}
	}
	if o.overrideNTPServer != "" {
		// Resolver ignores whatever "host:port" the KE server returned
		// and always substitutes our own - a client-side override, not
		// a request the server can decline.
		sessOpts.Resolver = func(_ string) string {
			return o.overrideNTPServer
		}
	}
	queryOpts := &ntp.QueryOptions{Version: o.version, Timeout: o.timeout}

	if o.family != "" {
		udpNetwork := "udp" + o.family
		// QueryOptions.Dialer overrides the dial used for the resulting
		// NTP query over UDP, so it's still only worth setting when
		// family-forcing is actually requested.
		queryOpts.Dialer = func(_, addr string) (net.Conn, error) {
			return net.Dial(udpNetwork, addr)
		}
	}

	// SessionOptions.Dialer overrides the TLS dial used for the NTS-KE
	// handshake. We set it to capture the resulting tls.ConnectionState for reporting,
	// but we must manually enforce the timeout since tls.Dial would bypass it.
	tcpNetwork := "tcp" + o.family
	var tlsState *tls.ConnectionState
	sessOpts.Dialer = func(_, addr string, tlsConfig *tls.Config) (*tls.Conn, error) {
		// 1. Establish a raw TCP connection using the configured timeout
		dialer := &net.Dialer{
			Timeout: o.timeout,
		}
		rawConn, err := dialer.Dial(tcpNetwork, addr)
		if err != nil {
			return nil, err
		}

		// 2. Ensure ServerName is set if InsecureSkipVerify is false.
		// Since we bypass the library's internal tls.Dial, we must populate this manually.
		if tlsConfig.ServerName == "" && !tlsConfig.InsecureSkipVerify {
			h, _, err := net.SplitHostPort(addr)
			if err == nil {
				tlsConfig.ServerName = h
			} else {
				// Fallback to the original host if splitting fails
				tlsConfig.ServerName = host
			}
		}

		// 3. Wrap the raw TCP connection in a TLS client
		tlsConn := tls.Client(rawConn, tlsConfig)

		// 4. Set a deadline for the TLS handshake and execute it
		_ = tlsConn.SetDeadline(time.Now().Add(o.timeout))
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			return nil, err
		}
		// Clear the deadline after a successful handshake
		_ = tlsConn.SetDeadline(time.Time{})

		// 5. Capture the connection state for later reporting
		state := tlsConn.ConnectionState()
		tlsState = &state

		return tlsConn, nil
	}

	keStart := time.Now()
	session, err := nts.NewSessionWithOptions(host, sessOpts)
	res.KEHandshake = time.Since(keStart)

	if tlsState != nil {
		res.TLSVersion = tlsVersionName(tlsState.Version)
		res.TLSCipherSuite = tls.CipherSuiteName(tlsState.CipherSuite)
		res.TLSALPNProtocol = tlsState.NegotiatedProtocol
		if len(tlsState.PeerCertificates) > 0 {
			cert := tlsState.PeerCertificates[0]
			res.TLSPeerCertSubject = cert.Subject.String()
			res.TLSPeerCertIssuer = cert.Issuer.String()
			res.TLSPeerCertNotAfter = cert.NotAfter
		}
	}

	if err != nil {
		res.NTSErrorKind = classifyNTSError(err)
		res.Error = fmt.Sprintf("NTS session could not be established: %v", err)
		return res
	}

	res.ResolvedNTP = session.Address()

	r, err := session.QueryWithOptions(queryOpts)
	if err != nil {
		res.NTSErrorKind = classifyNTSError(err)
		res.Error = fmt.Sprintf("NTP query failed for %s: %v", res.ResolvedNTP, err)
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
		// TLS details may still be present (e.g. handshake succeeded
		// but the subsequent KE exchange or NTP auth failed), so show
		// those too when we have them.
		fmt.Printf("  %s\n", res.Error)
		if res.NTSErrorKind != "" {
			fmt.Printf("    %-14s %s\n", "ErrorKind:", res.NTSErrorKind)
		}
		printTLSDetails(res)
		return
	}

	fmt.Printf("\n  NTS\n")
	if res.ResolvedNTP != "" {
		fmt.Printf("    %-14s %s\n", "Resolved:", res.ResolvedNTP)
	}
	fmt.Printf("    %-14s %v\n", "KEHandshake:", res.KEHandshake)
	printTLSDetails(res)

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

// tlsVersionName translates a tls.ConnectionState.Version value into a
// human-readable string. The nts library enforces a TLS 1.3 floor, so
// VersionTLS13 is the expected (and currently only reachable) case, but
// this covers the older constants too rather than assuming.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// printTLSDetails prints the captured NTS-KE TLS handshake details, if
// any were captured (they won't be if the TLS dial itself failed before
// a connection was established).
func printTLSDetails(res Result) {
	if res.TLSVersion == "" {
		return
	}
	fmt.Printf("    %-14s %s / %s (ALPN %q)\n", "TLS:", res.TLSVersion, res.TLSCipherSuite, res.TLSALPNProtocol)
	if res.TLSPeerCertSubject != "" {
		fmt.Printf("    %-14s %s\n", "PeerCert:", res.TLSPeerCertSubject)
		fmt.Printf("    %-14s issuer=%s notAfter=%s\n", "", res.TLSPeerCertIssuer, res.TLSPeerCertNotAfter.Format(certTimeFormat))
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
