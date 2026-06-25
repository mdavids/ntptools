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
//	GET /metrics                         - exporter's own health/process metrics
package main

import (
	"crypto/tls"
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
	listenAddr     = flag.String("web.listen-address", ":9116", "Address to listen on")
	defaultTimeout = flag.Duration("timeout", 5*time.Second, "Default probe timeout, used when Prometheus sends no scrape-timeout header")
	timeoutOffset  = flag.Float64("timeout-offset", 0.5, "Seconds subtracted from the Prometheus scrape timeout to leave room for the response to be delivered")
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

type prober func(target string, registry *prometheus.Registry, timeout time.Duration, family string) bool

var modules = map[string]prober{
	"ntp": probeNTP,
	"nts": probeNTS,
}

func probeNTP(target string, registry *prometheus.Registry, timeout time.Duration, family string) bool {
	opts := ntp.QueryOptions{Version: 4, Timeout: timeout}
	if family != "" {
		network := "udp" + family
		opts.Dialer = func(_, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		}
	}

	r, err := ntp.QueryWithOptions(target, opts)
	if err != nil {
		registerErrorMetric(registry, err)
		return false
	}
	registerResponseMetrics(registry, r)
	return true
}

func probeNTS(target string, registry *prometheus.Registry, timeout time.Duration, family string) bool {
	sessOpts := &nts.SessionOptions{Timeout: timeout}
	queryOpts := &ntp.QueryOptions{Version: 4, Timeout: timeout}
	if family != "" {
		tcpNetwork := "tcp" + family
		udpNetwork := "udp" + family
		sessOpts.Dialer = func(_, addr string, tlsConfig *tls.Config) (*tls.Conn, error) {
			return tls.Dial(tcpNetwork, addr, tlsConfig)
		}
		queryOpts.Dialer = func(_, addr string) (net.Conn, error) {
			return net.Dial(udpNetwork, addr)
		}
	}

	keStart := time.Now()
	session, err := nts.NewSessionWithOptions(target, sessOpts)
	keDuration := time.Since(keStart)
	newGauge(registry, "ntp_nts_handshake_duration_seconds", "Duration of the NTS-KE handshake in seconds").Set(keDuration.Seconds())
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
	success := prober(target, registry, timeout, family)
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
