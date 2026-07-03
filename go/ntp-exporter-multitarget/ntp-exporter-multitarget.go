// Version: 20260635 - M. Davids, SIDN Labs
//                     Vibe coded with Claude.ai
//
// ntp-exporter implements the Prometheus "multi-target exporter" pattern
// (https://prometheus.io/docs/guides/multi-target-exporter/) for NTP and
// NTS. The host list lives in Prometheus' own scrape configuration, not
// in this binary - see the sample scrape config in the README section
// below.
//
//	GET /probe?target=HOST&module=ntp   - plain NTP query
//	GET /probe?target=HOST&module=nts   - NTS key exchange + NTP query
//	GET /probe?target=HOST&module=nts&ip_protocol=4  - force IPv4
//	GET /probe?target=HOST&module=nts&assume_compliant_128gcm=true
//	    - skip AES-128-GCM-SIV compliance negotiation for this target,
//	      overriding the -assume-compliant-128gcm default (nts module
//	      only; ignored for ntp). See:
//	      https://chrony-project.org/doc/spec/nts-compliant-128gcm.html
//	GET /metrics                         - exporter's own health/process metrics
//
// The nts module also exposes ntp_nts_cert_expiry_seconds, the Unix
// timestamp of the earliest expiry across the verified NTS-KE TLS
// certificate chain - deliberately named and shaped after blackbox_exporter's
// probe_ssl_earliest_cert_expiry so existing "metric - time() < threshold"
// alerting rules work unchanged against this exporter too.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	listenAddr            = flag.String("web.listen-address", ":9116", "Address to listen on")
	defaultTimeout        = flag.Duration("timeout", 5*time.Second, "Default probe timeout, used when Prometheus sends no scrape-timeout header")
	timeoutOffset         = flag.Float64("timeout-offset", 0.5, "Seconds subtracted from the Prometheus scrape timeout to leave room for the response to be delivered")
	assumeCompliant128GCM = flag.Bool("assume-compliant-128gcm", false, "Default for the nts module: skip AES-128-GCM-SIV compliance negotiation and assume servers already use the RFC 8915-compliant key exporter context. Overridable per probe via the assume_compliant_128gcm URL parameter. See https://chrony-project.org/doc/spec/nts-compliant-128gcm.html")
)

// probesTotal is a self-metric (on the default/exporter registry, not the
// per-probe throwaway one) so you can monitor the exporter's own usage and
// failure rate independent of any specific target.
var probesTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ntp_exporter_probes_total",
		Help: "Total number of probes handled by this exporter, by module and result",
	},
	[]string{"module", "result"},
)

func init() {
	prometheus.MustRegister(probesTotal)
}

// ---------------------------------------------------------------------
// Probers: one function per module. Each fills in a fresh registry with
// metrics for exactly one target and returns whether the probe overall
// succeeded (could reach the server and parse a response).
// ---------------------------------------------------------------------

// probeOptions bundles the per-probe knobs so the prober signature
// doesn't keep growing every time a new option is exposed.
type probeOptions struct {
	timeout               time.Duration
	family                string
	assumeCompliant128GCM bool
}

type prober func(target string, registry *prometheus.Registry, opts probeOptions) bool

var modules = map[string]prober{
	"ntp": probeNTP,
	"nts": probeNTS,
}

func probeNTP(target string, registry *prometheus.Registry, opts probeOptions) bool {
	queryOpts := ntp.QueryOptions{Version: 4, Timeout: opts.timeout}
	if opts.family != "" {
		network := "udp" + opts.family
		queryOpts.Dialer = func(_, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}

	r, err := ntp.QueryWithOptions(target, queryOpts)
	if err != nil {
		registerErrorMetric(registry, err)
		return false
	}
	registerResponseMetrics(registry, r)
	return true
}

func probeNTS(target string, registry *prometheus.Registry, opts probeOptions) bool {
	sessOpts := &nts.SessionOptions{
		Timeout:               opts.timeout,
		AssumeCompliant128GCM: opts.assumeCompliant128GCM,
	}
	queryOpts := &ntp.QueryOptions{Version: 4, Timeout: opts.timeout}
	if opts.family != "" {
		udpNetwork := "udp" + opts.family
		queryOpts.Dialer = func(_, addr string) (net.Conn, error) {
			return net.Dial(udpNetwork, addr)
		}
	}

	// Always set the Dialer - even without family-forcing - so we can
	// capture the resulting tls.ConnectionState for the cert-expiry
	// metric below; the nts library gives no other way to inspect the
	// TLS handshake it performed. "tcp"+"" is just "tcp", a no-op for
	// address-family selection when no family override was requested.
	tcpNetwork := "tcp" + opts.family
	var tlsState *tls.ConnectionState
	sessOpts.Dialer = func(_, addr string, tlsConfig *tls.Config) (*tls.Conn, error) {
		conn, err := tls.Dial(tcpNetwork, addr, tlsConfig)
		if err != nil {
			return nil, err
		}
		state := conn.ConnectionState()
		tlsState = &state
		return conn, nil
	}

	// Exposed as a metric, not just used internally, so a scrape result
	// is self-describing: with a per-target URL override in play, you
	// otherwise can't tell after the fact which mode a given scrape ran
	// with.
	assumeCompliantValue := 0.0
	if opts.assumeCompliant128GCM {
		assumeCompliantValue = 1.0
	}
	newGauge(registry, "ntp_nts_assume_compliant_128gcm", "Whether AES-128-GCM-SIV compliance negotiation was skipped for this probe (1) or performed normally (0)").Set(assumeCompliantValue)

	keStart := time.Now()
	session, err := nts.NewSessionWithOptions(target, sessOpts)
	keDuration := time.Since(keStart)
	newGauge(registry, "ntp_nts_handshake_duration_seconds", "Duration of the NTS-KE handshake in seconds").Set(keDuration.Seconds())

	// Expose the cert-expiry metric whenever we captured a TLS state at
	// all, regardless of whether the overall probe went on to succeed -
	// e.g. the TLS handshake can succeed while a later NTS-KE step
	// fails, and an operator debugging that failure benefits from
	// seeing "oh, and the cert is also about to expire" without needing
	// a separate tool.
	if tlsState != nil {
		if expiry := earliestCertExpiry(tlsState); !expiry.IsZero() {
			newGauge(registry, "ntp_nts_cert_expiry_seconds", "Unix timestamp of the earliest expiry across the verified NTS-KE TLS certificate chain").Set(float64(expiry.Unix()))
		}
	}

	if err != nil {
		registerErrorMetric(registry, err)
		return false
	}
	newInfoMetric(registry, "ntp_nts_resolved_info", "NTP server address negotiated via the NTS-KE handshake", "ntp_server", session.Address())

	r, err := session.QueryWithOptions(queryOpts)
	if err != nil {
		registerErrorMetric(registry, err)
		return false
	}
	registerResponseMetrics(registry, r)
	return true
}

// earliestCertExpiry returns the earliest NotAfter across the verified
// NTS-KE TLS certificate chain, mirroring blackbox_exporter's
// "earliest expiry" semantics: an expiring intermediate CA is just as
// much a problem as an expiring leaf certificate. Prefers the actually
// verified chain (VerifiedChains) over the raw, unverified certificates
// the server sent (PeerCertificates), falling back to the latter only
// if no verified chain is available. Returns the zero Time if neither
// is present.
func earliestCertExpiry(state *tls.ConnectionState) time.Time {
	var earliest time.Time
	consider := func(certs []*x509.Certificate) {
		for _, cert := range certs {
			if earliest.IsZero() || cert.NotAfter.Before(earliest) {
				earliest = cert.NotAfter
			}
		}
	}
	if len(state.VerifiedChains) > 0 {
		consider(state.VerifiedChains[0])
	} else {
		consider(state.PeerCertificates)
	}
	return earliest
}

// registerResponseMetrics fills in the metric set shared by both modules -
// the underlying data is the same *ntp.Response either way, NTS only adds
// the key-exchange step beforehand.
func registerResponseMetrics(registry *prometheus.Registry, r *ntp.Response) {
	newGauge(registry, "ntp_offset_seconds", "Clock offset in seconds").Set(r.ClockOffset.Seconds())
	newGauge(registry, "ntp_rtt_seconds", "Round trip time in seconds").Set(r.RTT.Seconds())
	newGauge(registry, "ntp_poll_interval_seconds", "Poll interval in seconds").Set(r.Poll.Seconds())
	newGauge(registry, "ntp_precision_seconds", "Clock precision in seconds").Set(r.Precision.Seconds())
	newGauge(registry, "ntp_stratum", "Stratum level").Set(float64(r.Stratum))
	newInfoMetric(registry, "ntp_ref_id_info", "Reference ID of the upstream source, as a label", "ref_id", r.ReferenceString())
	newGauge(registry, "ntp_root_delay_seconds", "Root delay in seconds").Set(r.RootDelay.Seconds())
	newGauge(registry, "ntp_root_dispersion_seconds", "Root dispersion in seconds").Set(r.RootDispersion.Seconds())
	newGauge(registry, "ntp_root_distance_seconds", "Root distance in seconds").Set(r.RootDistance.Seconds())
	newGauge(registry, "ntp_min_error_seconds", "Minimum error in seconds").Set(r.MinError.Seconds())
	newGauge(registry, "ntp_leap", "Leap indicator (0=no warning, 1=+1s, 2=-1s, 3=not in sync)").Set(float64(r.Leap))
	if r.KissCode != "" {
		newInfoMetric(registry, "ntp_kiss_code_info", "Kiss code if present", "kiss_code", r.KissCode)
	}

	valid := 0.0
	if r.Validate() == nil {
		valid = 1.0
	}
	newGauge(registry, "ntp_valid", "Whether the response passes NTP sanity validation (1) or not (0)").Set(valid)
}

// registerErrorMetric reports a bounded-cardinality error classification
// rather than the raw error string, which can vary per attempt (timeouts
// embed addresses, etc.) and would otherwise churn the time series.
func registerErrorMetric(registry *prometheus.Registry, err error) {
	newInfoMetric(registry, "ntp_last_error_info", "Classified error from the most recent failed probe", "error_class", classifyError(err))
}

func classifyError(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "connection_refused"
	case strings.Contains(msg, "no such host"):
		return "dns_error"
	case strings.Contains(msg, "network is unreachable"):
		return "network_unreachable"
	case strings.Contains(msg, "kiss of death") || strings.Contains(msg, "RATE"):
		return "kiss_of_death"
	case strings.Contains(msg, "key exchange"):
		return "nts_ke_error"
	default:
		return "other"
	}
}

// newGauge creates an unlabeled gauge, registers it on the given
// (per-probe, throwaway) registry, and returns it for the caller to set.
func newGauge(registry *prometheus.Registry, name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
	registry.MustRegister(g)
	return g
}

// newInfoMetric creates a gauge fixed at 1 with a single label - the
// standard Prometheus convention for exposing a piece of text (a name, an
// address, a code) as a label rather than a numeric value.
func newInfoMetric(registry *prometheus.Registry, name, help, labelName, labelValue string) {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help, ConstLabels: prometheus.Labels{labelName: labelValue}})
	registry.MustRegister(g)
	g.Set(1)
}

// ---------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------

func probeHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target parameter is missing", http.StatusBadRequest)
		return
	}

	moduleName := r.URL.Query().Get("module")
	if moduleName == "" {
		moduleName = "ntp"
	}
	prober, ok := modules[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("unknown module %q", moduleName), http.StatusBadRequest)
		return
	}

	family := ""
	switch r.URL.Query().Get("ip_protocol") {
	case "4":
		family = "4"
	case "6":
		family = "6"
	case "":
		// system default, as before
	default:
		http.Error(w, "ip_protocol must be \"4\" or \"6\"", http.StatusBadRequest)
		return
	}

	// Per-target override of the -assume-compliant-128gcm default.
	// Meaningless for the ntp module, but harmless to accept there too -
	// rejecting it would just be one more thing a scrape config has to
	// get exactly right per module.
	assumeCompliant := *assumeCompliant128GCM
	switch r.URL.Query().Get("assume_compliant_128gcm") {
	case "true":
		assumeCompliant = true
	case "false":
		assumeCompliant = false
	case "":
		// use the -assume-compliant-128gcm default, as set above
	default:
		http.Error(w, "assume_compliant_128gcm must be \"true\" or \"false\"", http.StatusBadRequest)
		return
	}

	timeout := *defaultTimeout
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		if seconds, err := strconv.ParseFloat(v, 64); err == nil {
			seconds -= *timeoutOffset
			if seconds > 0 {
				timeout = time.Duration(seconds * float64(time.Second))
			}
		}
	}

	registry := prometheus.NewRegistry()
	probeSuccess := newGauge(registry, "ntp_probe_success", "Whether the probe succeeded (1) or not (0)")
	probeDuration := newGauge(registry, "ntp_probe_duration_seconds", "Duration of the probe in seconds")

	start := time.Now()
	success := prober(target, registry, probeOptions{
		timeout:               timeout,
		family:                family,
		assumeCompliant128GCM: assumeCompliant,
	})
	probeDuration.Set(time.Since(start).Seconds())

	result := "success"
	if success {
		probeSuccess.Set(1)
	} else {
		probeSuccess.Set(0)
		result = "failure"
	}
	probesTotal.WithLabelValues(moduleName, result).Inc()

	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

func landingPageHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<html><head><title>NTP/NTS Exporter</title></head><body>
<h1>NTP/NTS Exporter</h1>
<p><a href="/probe?target=time.nl&module=ntp">Example: probe time.nl over plain NTP</a></p>
<p><a href="/probe?target=nts.time.nl&module=nts">Example: probe nts.time.nl over NTS</a></p>
<p><a href="/metrics">Exporter's own metrics</a></p>
</body></html>`)
}

func main() {
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/probe", probeHandler)
	mux.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{EnableOpenMetrics: true}))
	mux.HandleFunc("/", landingPageHandler)

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// A probe can legitimately take close to the Prometheus scrape
		// timeout (often tens of seconds); give some headroom beyond
		// the configured default so a slow probe isn't cut off by the
		// HTTP server itself before the handler gets a chance to reply.
		WriteTimeout: *defaultTimeout + 30*time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Printf("Exporter draait op http://localhost%s/probe?target=HOST&module=ntp\n", *listenAddr)
	log.Fatal(srv.ListenAndServe())
}
