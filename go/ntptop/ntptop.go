//
// M. Davids - Vibe coded.
//
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eiannone/keyboard"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/oschwald/geoip2-golang"
)

// Application version number
const version = "20260704-01"

// NTP constants for manual fast parsing
const (
	ntpHeaderLen = 48
)

// Operational limits
const (
	// maxTrackedClients: upper bound on the number of unique sources we
	// track at once, as protection against OOM from spoofed floods.
	// Measured memory usage is ~460 bytes/entry (including both dist maps
	// and the DNS/ASN/Geo strings), so 100k unique IPs costs ~44 MiB.
	maxTrackedClients = 100000

	// dnsLookupTimeout bounds both reverse-DNS lookups and the time a
	// worker stays stuck before it can move on to the next IP in the queue.
	dnsLookupTimeout = 2 * time.Second
)

type SortMode int

const (
	SortByPPS SortMode = iota
	SortByTotal
)

// MaxMindDisplayMode determines which databases are shown live
type MaxMindDisplayMode int

const (
	MMShowBoth    MaxMindDisplayMode = iota // Show ASN and Geo
	MMShowASNOnly                           // ASN only
	MMShowGeoOnly                           // Geo only
	MMShowNone                              // Show nothing
)

// IPStats holds all collected metrics per IP
type IPStats struct {
	IP          string
	TotalCount  int64
	LastCount   int64
	PPS         int64
	VersionDist map[uint8]int64 // NTP version distribution
	ModeDist    map[uint8]int64 // NTP mode distribution
	ResolvedIP  string          // Cached DNS name
	ASNMetadata string          // Cached ASN data
	GeoMetadata string          // Cached Geo data
}

type TrafficMonitor struct {
	mu     sync.RWMutex
	counts map[string]*IPStats
}

// displayRow is a read-only snapshot for the render phase. Deliberately NO
// map fields: IPStats.VersionDist/ModeDist are continuously mutated by the
// packet-capture goroutine (under monitor.mu). If we carried those maps (or
// a copy of the IPStats struct that still points to them) outside the lock,
// and formatDist() then ranged over them outside the lock, that would be an
// unsynchronized concurrent map read/write — in Go a fatal runtime crash
// (not recoverable), not just "maybe a problem". So we compute VStr/MStr
// below while the lock is still held.
type displayRow struct {
	IP          string
	TotalCount  int64
	PPS         int64
	ResolvedIP  string
	ASNMetadata string
	GeoMetadata string
	VStr        string
	MStr        string
}

// DNSCache handles asynchronous DNS and MaxMind lookups
type DNSCache struct {
	mu    sync.RWMutex
	cache map[string]string
	asn   map[string]string
	geo   map[string]string
	queue chan string
}

var (
	dnsCache    = &DNSCache{cache: make(map[string]string), asn: make(map[string]string), geo: make(map[string]string), queue: make(chan string, 1000)}
	enableDNS   = flag.Bool("dns", false, "Enable asynchronous DNS resolution for top clients")
	showVersion = flag.Bool("version", false, "Print version information and exit")
	asnDBPath   = flag.String("asn", "", "Path to MaxMind GeoLite2-ASN.mmdb file")
	geoDBPath   = flag.String("geo", "", "Path to MaxMind GeoLite2-Country.mmdb or City.mmdb file")
	// sortModeVal holds the active SortMode atomically; the default is set
	// to SortByTotal in main() (the zero value would be SortByPPS).
	sortModeVal atomic.Int32

	// Controls whether resolved names are shown in the UI
	showDNS   = true
	displayMu sync.Mutex

	// MaxMind interactive display mode state
	mmMode   = MMShowBoth
	mmModeMu sync.Mutex

	// Database handles
	asnDB *geoip2.Reader
	geoDB *geoip2.Reader
)

func main() {
	// Parse flags
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <interface>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	sortModeVal.Store(int32(SortByTotal))

	// Exit immediately and print the version if the -version flag was given
	if *showVersion {
		fmt.Printf("ntptop version %s\n", version)
		os.Exit(0)
	}

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	interfaceName := flag.Arg(0)

	// Open MaxMind databases if provided
	if *asnDBPath != "" {
		var err error
		asnDB, err = geoip2.Open(*asnDBPath)
		if err != nil {
			log.Fatalf("Error opening ASN database: %v", err)
		}
		defer asnDB.Close()
	}
	if *geoDBPath != "" {
		var err error
		geoDB, err = geoip2.Open(*geoDBPath)
		if err != nil {
			log.Fatalf("Error opening Geo database: %v", err)
		}
		defer geoDB.Close()
	}

	// Start workers if DNS or MaxMind is enabled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if *enableDNS || asnDB != nil || geoDB != nil {
		for i := 0; i < 5; i++ {
			go dnsWorker(ctx)
		}
	}

	// Open pcap handle (256 bytes snaplen is enough for IP + UDP + NTP header)
	handle, err := pcap.OpenLive(interfaceName, 256, false, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", interfaceName, err)
	}
	defer handle.Close()

	// Kernel-level filtering: UDP port 123 only
	if err := handle.SetBPFFilter("udp port 123"); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	monitor := &TrafficMonitor{
		counts: make(map[string]*IPStats),
	}

	// Packet processing goroutine
	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.Lazy = true
		packetSource.NoCopy = true

		for packet := range packetSource.Packets() {
			ipLayer := packet.NetworkLayer()
			if ipLayer == nil {
				continue
			}
			srcIP := ipLayer.NetworkFlow().Src().String()

			// Look up the transport layer for NTP payload parsing
			var ntpVersion uint8 = 0
			var ntpMode uint8 = 0
			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				payload := transportLayer.LayerPayload()
				// NTP is at least 48 bytes
				if len(payload) >= ntpHeaderLen {
					// First byte contains: Leap Indicator (2 bits), Version (3 bits), Mode (3 bits)
					firstByte := payload[0]
					ntpVersion = (firstByte >> 3) & 0x07
					ntpMode = firstByte & 0x07
				}
			}

			monitor.mu.Lock()
			// Memory protection: avoid OOM from massive floods of unique IPs
			if len(monitor.counts) > maxTrackedClients {
				// Simple reset if the map grows too large
				monitor.counts = make(map[string]*IPStats)
			}

			stats, exists := monitor.counts[srcIP]
			if !exists {
				stats = &IPStats{
					IP:          srcIP,
					VersionDist: make(map[uint8]int64),
					ModeDist:    make(map[uint8]int64),
				}
				monitor.counts[srcIP] = stats
			}
			stats.TotalCount++
			stats.VersionDist[ntpVersion]++
			stats.ModeDist[ntpMode]++
			monitor.mu.Unlock()
		}
	}()

	// Keyboard input goroutine for a genuinely interactive 'top' experience
	if err := keyboard.Open(); err == nil {
		defer keyboard.Close()
		go func() {
			for {
				char, key, err := keyboard.GetKey()
				if err != nil {
					return
				}
				if key == keyboard.KeyCtrlC || char == 'q' {
					// cancel() makes the render loop in main return via
					// ctx.Done(), after which the deferred Close() calls
					// (pcap handle, keyboard, mmdb readers) run cleanly.
					// No more os.Exit needed, which also avoids skipping
					// that cleanup.
					cancel()
					return
				}
				if char == 's' {
					if SortMode(sortModeVal.Load()) == SortByPPS {
						sortModeVal.Store(int32(SortByTotal))
					} else {
						sortModeVal.Store(int32(SortByPPS))
					}
				}
				if char == 'c' {
					monitor.mu.Lock()
					monitor.counts = make(map[string]*IPStats)
					monitor.mu.Unlock()
				}
				if char == 'd' {
					displayMu.Lock()
					showDNS = !showDNS
					displayMu.Unlock()
				}
				if char == 'm' {
					mmModeMu.Lock()
					// Rotate through the available modes
					switch mmMode {
					case MMShowBoth:
						if asnDB != nil {
							mmMode = MMShowASNOnly
						} else if geoDB != nil {
							mmMode = MMShowGeoOnly
						} else {
							mmMode = MMShowNone
						}
					case MMShowASNOnly:
						if geoDB != nil {
							mmMode = MMShowGeoOnly
						} else {
							mmMode = MMShowNone
						}
					case MMShowGeoOnly:
						mmMode = MMShowNone
					case MMShowNone:
						if asnDB != nil && geoDB != nil {
							mmMode = MMShowBoth
						} else if asnDB != nil {
							mmMode = MMShowASNOnly
						} else if geoDB != nil {
							mmMode = MMShowGeoOnly
						} else {
							mmMode = MMShowNone
						}
					}
					mmModeMu.Unlock()
				}
			}
		}()
	}

	// UI render loop
	interval := 2 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			monitor.printTop(20, interval)
		}
	}
}

func (m *TrafficMonitor) printTop(topN int, interval time.Duration) {
	m.mu.Lock()
	var list []displayRow
	var totalPackets int64

	seconds := int64(interval.Seconds())
	if seconds == 0 {
		seconds = 1
	}

	for _, stats := range m.counts {
		stats.PPS = (stats.TotalCount - stats.LastCount) / seconds
		stats.LastCount = stats.TotalCount
		totalPackets += stats.TotalCount

		// Trigger background queries if needed
		if *enableDNS || asnDB != nil || geoDB != nil {
			stats.ResolvedIP, stats.ASNMetadata, stats.GeoMetadata = dnsCache.Lookup(stats.IP)
		}

		list = append(list, displayRow{
			IP:          stats.IP,
			TotalCount:  stats.TotalCount,
			PPS:         stats.PPS,
			ResolvedIP:  stats.ResolvedIP,
			ASNMetadata: stats.ASNMetadata,
			GeoMetadata: stats.GeoMetadata,
			// Computed while monitor.mu is still held: see the explanation
			// on displayRow above.
			VStr: formatDist(stats.VersionDist, "v"),
			MStr: formatDist(stats.ModeDist, "m"),
		})
	}
	m.mu.Unlock()

	// Sort based on the selected mode
	currentSort := SortMode(sortModeVal.Load())

	displayMu.Lock()
	currentShowDNS := showDNS
	displayMu.Unlock()

	mmModeMu.Lock()
	currentMMMode := mmMode
	mmModeMu.Unlock()

	// Sort with a secondary check on IP address for maximum stability
	sort.Slice(list, func(i, j int) bool {
		if currentSort == SortByTotal {
			if list[i].TotalCount == list[j].TotalCount {
				return list[i].IP < list[j].IP // Tie: fall back to sorting by IP
			}
			return list[i].TotalCount > list[j].TotalCount
		}

		// If we're sorting by PPS
		if list[i].PPS == list[j].PPS {
			if list[i].TotalCount == list[j].TotalCount {
				return list[i].IP < list[j].IP // Tie on both PPS and total: fall back to IP
			}
			return list[i].TotalCount > list[j].TotalCount // Tie on PPS: whoever sent more historically wins
		}
		return list[i].PPS > list[j].PPS
	})

	// Clear screen via ANSI codes
	fmt.Print("\033[H\033[2J")

	// Determine the current sort label for the header
	sortStr := "Packets Per Second (PPS)"
	if currentSort == SortByTotal {
		sortStr = "Total Packets"
	}

	// Determine the MaxMind filter status for the header
	mmStatusStr := "disabled"
	if asnDB != nil || geoDB != nil {
		switch currentMMMode {
		case MMShowBoth:
			mmStatusStr = "ASN+Geo"
		case MMShowASNOnly:
			mmStatusStr = "ASN only"
		case MMShowGeoOnly:
			mmStatusStr = "Geo only"
		case MMShowNone:
			mmStatusStr = "hidden"
		}
	}

	// Show the header including the version indicator
	fmt.Printf("NTP Top - %s | Sorting by: %s | MaxMind: %s | v%s\n", time.Now().Format("15:04:05"), sortStr, mmStatusStr, version)
	fmt.Printf("Interactive Keys: [q]uit | [s]witch sort | [c]lear stats | toggle [d]ns | cycle [m]axmind\n")
	fmt.Printf("Total Unique Clients: %d | Total Packets: %d\n\n", len(list), totalPackets)

	// Wider columns (16 instead of 12) to keep them from running into each other
	fmt.Printf("%-5s%-42s%-10s%-14s%-16s%-16s\n", "RANK", "IP ADDRESS / HOSTNAME", "PPS", "TOTAL PKTS", "NTP VERSIONS", "NTP MODES")
	fmt.Printf("%-5s%-42s%-10s%-14s%-16s%-16s\n", "----", "---------------------", "---", "----------", "------------", "---------")

	for i := 0; i < len(list) && i < topN; i++ {
		rank := fmt.Sprintf("%d", i+1)
		ppsStr := fmt.Sprintf("%d/s", list[i].PPS)

		// Determine the base name (IP or hostname)
		displayTarget := list[i].IP
		if *enableDNS && currentShowDNS && list[i].ResolvedIP != "" && list[i].ResolvedIP != list[i].IP {
			displayTarget = list[i].ResolvedIP
		}

		// Dynamically assemble the metadata based on the selected rotation state
		var metaParts []string
		if (currentMMMode == MMShowBoth || currentMMMode == MMShowGeoOnly) && list[i].GeoMetadata != "" {
			metaParts = append(metaParts, list[i].GeoMetadata)
		}
		if (currentMMMode == MMShowBoth || currentMMMode == MMShowASNOnly) && list[i].ASNMetadata != "" {
			metaParts = append(metaParts, list[i].ASNMetadata)
		}

		if len(metaParts) > 0 {
			displayTarget = fmt.Sprintf("%s %s", displayTarget, strings.Join(metaParts, " "))
		}

		// Truncate the combined string if it threatens to overrun the column width
		if len(displayTarget) > 39 {
			displayTarget = displayTarget[:36] + "..."
		}

		// Aligned with the new spacing
		fmt.Printf("%-5s%-42s%-10s%-14d%-16s%-16s\n", rank, displayTarget, ppsStr, list[i].TotalCount, list[i].VStr, list[i].MStr)
	}
}

// Helper to display NTP distributions compactly and stably
func formatDist(dist map[uint8]int64, prefix string) string {
	if len(dist) == 0 {
		return "-"
	}
	var total int64
	type kv struct {
		k uint8
		v int64
	}
	var sorted []kv
	for k, v := range dist {
		total += v
		sorted = append(sorted, kv{k, v})
	}

	if total == 0 {
		return "-"
	}

	// Sort primarily by count (v), secondarily by key (k) for stability on ties
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].v == sorted[j].v {
			return sorted[i].k > sorted[j].k // Tie: highest version/mode number first
		}
		return sorted[i].v > sorted[j].v
	})

	// We show the most dominant mode/version. Round to the nearest percent
	// instead of integer truncation (which always floored, so 99.9% was
	// shown as 99%). Stays at most 3 digits (0-100), so this doesn't affect
	// the column width.
	pct := (sorted[0].v*100 + total/2) / total

	// Translate NTP modes into readable abbreviations
	if prefix == "m" {
		switch sorted[0].k {
		case 3:
			return fmt.Sprintf("Client(%d%%)", pct)
		case 4:
			return fmt.Sprintf("Server(%d%%)", pct)
		case 6:
			return fmt.Sprintf("Ctrl(%d%%)", pct)
		case 7:
			return fmt.Sprintf("Priv(%d%%)", pct)
		}
	}

	return fmt.Sprintf("%s%d(%d%%)", prefix, sorted[0].k, pct)
}

// DNS & MaxMind cache mechanisms
func (c *DNSCache) Lookup(ip string) (string, string, string) {
	c.mu.RLock()
	name, nameExists := c.cache[ip]
	asn, asnExists := c.asn[ip]
	geo, geoExists := c.geo[ip]
	c.mu.RUnlock()

	if nameExists && asnExists && geoExists {
		return name, asn, geo
	}

	// If not fully known yet, send to the background queue
	select {
	case c.queue <- ip:
	default:
	}

	if !nameExists {
		name = ip
	}
	return name, asn, geo
}

func dnsWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-dnsCache.queue:
			dnsCache.mu.RLock()
			_, nameExists := dnsCache.cache[ip]
			_, asnExists := dnsCache.asn[ip]
			_, geoExists := dnsCache.geo[ip]
			dnsCache.mu.RUnlock()

			if nameExists && asnExists && geoExists {
				continue
			}

			parsedIP := net.ParseIP(ip)

			// 1. MaxMind lookup (if database is loaded and not yet cached)
			if parsedIP != nil {
				if !geoExists && geoDB != nil {
					var geoStr string
					record, err := geoDB.Country(parsedIP)
					if err == nil && record.Country.IsoCode != "" {
						geoStr = fmt.Sprintf("[%s]", record.Country.IsoCode)
					}
					dnsCache.mu.Lock()
					dnsCache.geo[ip] = geoStr
					dnsCache.mu.Unlock()
				}

				if !asnExists && asnDB != nil {
					var asnStr string
					record, err := asnDB.ASN(parsedIP)
					if err == nil && record.AutonomousSystemNumber != 0 {
						// Clean up and shorten the organization name
						org := record.AutonomousSystemOrganization
						org = strings.ReplaceAll(org, ", Inc.", "")
						org = strings.ReplaceAll(org, " Inc.", "")
						org = strings.ReplaceAll(org, ", Llc.", "")
						org = strings.ReplaceAll(org, " Stichting", "")
						org = strings.ReplaceAll(org, "Stichting ", "")

						asnStr = fmt.Sprintf("[AS%d %s]", record.AutonomousSystemNumber, org)
					}
					dnsCache.mu.Lock()
					dnsCache.asn[ip] = asnStr
					dnsCache.mu.Unlock()
				}
			}

			// 2. DNS lookup (if enabled and not yet cached)
			if !nameExists {
				resolved := ip
				if *enableDNS {
					// Explicit timeout: without this, net.LookupAddr
					// (especially with the pure-Go resolver on Linux, which
					// doesn't benefit from whatever local caching the
					// platform resolver on macOS does) can block for
					// several seconds per IP. With only 5 workers pulling
					// both DNS and MaxMind lookups from the same queue, one
					// slow/hanging PTR lookup can clog all workers and
					// thereby also delay the (otherwise near-instant,
					// local) MaxMind lookups for other IPs in the queue.
					lookupCtx, lookupCancel := context.WithTimeout(ctx, dnsLookupTimeout)
					names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip)
					lookupCancel()
					if err == nil && len(names) > 0 {
						resolved = names[0]
						if len(resolved) > 0 && resolved[len(resolved)-1] == '.' {
							resolved = resolved[:len(resolved)-1]
						}
					}
				}
				dnsCache.mu.Lock()
				dnsCache.cache[ip] = resolved
				dnsCache.mu.Unlock()
			}
		}
	}
}
