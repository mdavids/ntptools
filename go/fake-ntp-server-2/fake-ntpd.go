package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// NTP constants
const (
	NtpEpochOffset = 2208988800 // Offset between NTP epoch (1 Jan 1900) and Unix epoch (1 Jan 1970) in seconds
	NtpPacketSize  = 48         // Standard NTP packet size in bytes
)

type Config struct {
	Port              int     `json:"port"`
	Debug             bool    `json:"debug"`
	MinPoll           int     `json:"min_poll"`
	MaxPoll           int     `json:"max_poll"`
	MinPrecision      int     `json:"min_precision"`
	MaxPrecision      int     `json:"max_precision"`
	MaxRefTimeOffset  int64   `json:"max_ref_time_offset"`
	RefIDType         string  `json:"ref_id_type"`
	MinStratum        int     `json:"min_stratum"`
	MaxStratum        int     `json:"max_stratum"`
	LeapIndicator     int     `json:"leap_indicator"`
	VersionNumber     int     `json:"version_number"`
	JitterMs          int     `json:"jitter_ms"`
	ProcessingDelayMs int     `json:"processing_delay_ms"`
	DriftModel        string  `json:"drift_model"`
	DriftPPM          float64 `json:"drift_ppm"`
	DriftStepPPM      float64 `json:"drift_step_ppm"`
	DriftUpdateSec    int     `json:"drift_update_interval_sec"`
	StateFile         string  `json:"state_file"`
	PersistState      bool    `json:"persist_state"`
}

type RuntimeState struct {
	BaseTime       time.Time `json:"base_time"`
	StartWall      time.Time `json:"start_wall"`
	LastUpdate     time.Time `json:"last_update"`
	CurrentDrift   float64   `json:"current_drift"`
	RandomSeed     int64     `json:"random_seed"`
	RequestCounter uint64    `json:"request_counter"`
}

type DriftSimulator struct {
	baseTime       time.Time
	startWall      time.Time
	model          string
	ppm            float64
	stepPPM        float64
	updateEvery    time.Duration
	lastUpdate     time.Time
	currentDrift   float64
	requestCounter uint64
}

func NewDriftSimulator(cfg Config) *DriftSimulator {
	return &DriftSimulator{
		baseTime:       time.Now(),
		startWall:      time.Now(),
		model:          cfg.DriftModel,
		ppm:            cfg.DriftPPM,
		stepPPM:        cfg.DriftStepPPM,
		updateEvery:    time.Duration(cfg.DriftUpdateSec) * time.Second,
		lastUpdate:     time.Now(),
		currentDrift:   cfg.DriftPPM,
		requestCounter: 0,
	}
}

func NewDriftSimulatorFromState(cfg Config, state *RuntimeState) *DriftSimulator {
	return &DriftSimulator{
		baseTime:       state.BaseTime,
		startWall:      state.StartWall,
		model:          cfg.DriftModel,
		ppm:            cfg.DriftPPM,
		stepPPM:        cfg.DriftStepPPM,
		updateEvery:    time.Duration(cfg.DriftUpdateSec) * time.Second,
		lastUpdate:     state.LastUpdate,
		currentDrift:   state.CurrentDrift,
		requestCounter: state.RequestCounter,
	}
}

func (d *DriftSimulator) GetState() *RuntimeState {
	return &RuntimeState{
		BaseTime:       d.baseTime,
		StartWall:      d.startWall,
		LastUpdate:     d.lastUpdate,
		CurrentDrift:   d.currentDrift,
		RequestCounter: d.requestCounter,
	}
}

func (d *DriftSimulator) Now() time.Time {
	elapsed := time.Since(d.startWall).Seconds()

	if d.model == "none" {
		return d.baseTime.Add(time.Duration(elapsed * float64(time.Second)))
	}

	if d.model == "random_walk" && time.Since(d.lastUpdate) >= d.updateEvery {
		// Use the global random source seeded by the main function
		delta := (rand.Float64()*2 - 1) * d.stepPPM
		d.currentDrift += delta
		d.lastUpdate = time.Now()
	}

	drifted := elapsed * (1.0 + d.currentDrift/1_000_000.0)
	return d.baseTime.Add(time.Duration(drifted * float64(time.Second)))
}

type NTPPacket struct {
	Settings     uint8
	Stratum      uint8
	Poll         int8
	Precision    int8
	RootDelay    uint32
	RootDisp     uint32
	RefID        uint32
	RefTimeSec   uint32
	RefTimeFrac  uint32
	OrigTimeSec  uint32
	OrigTimeFrac uint32
	RxTimeSec    uint32
	RxTimeFrac   uint32
	TxTimeSec    uint32
	TxTimeFrac   uint32
}

func loadConfig(path string) Config {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Cannot open config file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var config Config
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	// Validations
	if config.LeapIndicator < 0 || config.LeapIndicator > 3 {
		log.Fatalf("Invalid leap indicator: %d (must be 0–3)", config.LeapIndicator)
	}
	if config.VersionNumber < 1 || config.VersionNumber > 7 {
		log.Fatalf("Invalid version number: %d (must be 1–7)", config.VersionNumber)
	}
	if config.MinStratum < 0 || config.MaxStratum > 16 || config.MinStratum > config.MaxStratum {
		log.Fatalf("Invalid stratum range: %d-%d (must be 0–16 and min<=max)", config.MinStratum, config.MaxStratum)
	}
	if config.MinPrecision > config.MaxPrecision {
		log.Fatalf("Invalid precision range: %d-%d", config.MinPrecision, config.MaxPrecision)
	}
	if config.MinPoll > config.MaxPoll {
		log.Fatalf("Invalid poll range: %d-%d", config.MinPoll, config.MaxPoll)
	}

	// Set defaults for new config options
	if config.StateFile == "" {
		config.StateFile = "fake-ntpd-state.json"
	}

	return config
}

func saveState(filename string, state *RuntimeState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0o644)
}

func loadState(filename string) (*RuntimeState, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var state RuntimeState
	err = json.Unmarshal(data, &state)
	if err != nil {
		return nil, err
	}

	return &state, nil
}

func refIDFromType(refid string, strat uint8) uint32 {
	switch strat {
	case 0, 1, 16:
		return binary.BigEndian.Uint32([]byte(refid))
	default:
		return rand.Uint32()
	}
}

func refIDFromTypeWithRng(refid string, strat uint8, rng *rand.Rand) uint32 {
	switch strat {
	case 0, 1, 16:
		return binary.BigEndian.Uint32([]byte(refid))
	default:
		return rng.Uint32()
	}
}

func ntpTimestampParts(t time.Time) (sec uint32, frac uint32) {
	unixSecs := t.Unix()
	nanos := t.Nanosecond()
	fracSecs := float64(nanos) / 1e9
	sec = uint32(unixSecs + NtpEpochOffset)
	frac = uint32(fracSecs * math.Pow(2, 32))
	return
}

func parseClientInfo(req []byte) (version uint8, mode uint8, txSec uint32, txFrac uint32) {
	settings := req[0]
	version = (settings >> 3) & 0x07
	mode = settings & 0x07
	txSec = binary.BigEndian.Uint32(req[40:44])
	txFrac = binary.BigEndian.Uint32(req[44:48])
	return
}

func createFakeNTPResponse(req []byte, cfg Config, drift *DriftSimulator, rng *rand.Rand) ([]byte, time.Duration, time.Duration, time.Duration, time.Duration, time.Duration) {
	drift.requestCounter++
	realNow := time.Now()
	now := drift.Now()
	driftOffset := now.Sub(realNow)

	// Apply jitter to RxTime and TxTime using deterministic random
	jitter := time.Duration(rng.Intn(cfg.JitterMs*2+1)-cfg.JitterMs) * time.Millisecond
	processingDelay := time.Duration(cfg.ProcessingDelayMs) * time.Millisecond
	refTimeOffset := time.Duration(cfg.MaxRefTimeOffset) * time.Second

	rxTime := now.Add(jitter).Add(-processingDelay) // processing delay before txTime
	txTime := now.Add(jitter)

	// Calculate total offset from real time in the TxTime we're sending
	// (RefTime doesn't affect client sync, only TxTime matters)
	totalOffset := driftOffset + jitter

	refTime := now.Add(-time.Duration(cfg.MaxRefTimeOffset) * time.Second)

	rxSec, rxFrac := ntpTimestampParts(rxTime)
	txSec, txFrac := ntpTimestampParts(txTime)
	refSec, refFrac := ntpTimestampParts(refTime)

	li := uint8(cfg.LeapIndicator & 0x03)
	vn := uint8(cfg.VersionNumber & 0x07)
	mode := uint8(4)
	settings := (li << 6) | (vn << 3) | mode

	precision := int8(rng.Intn(cfg.MaxPrecision-cfg.MinPrecision+1) + cfg.MinPrecision)
	poll := int8(rng.Intn(cfg.MaxPoll-cfg.MinPoll+1) + cfg.MinPoll)

	stratum := uint8(rng.Intn(cfg.MaxStratum-cfg.MinStratum+1) + cfg.MinStratum)
	refid := refIDFromTypeWithRng(cfg.RefIDType, stratum, rng)

	packet := NTPPacket{
		Settings:     settings,
		Stratum:      stratum,
		Poll:         poll,
		Precision:    precision,
		RootDelay:    100 * (uint32(stratum) - 1),
		RootDisp:     200 * (uint32(stratum) - 1),
		RefID:        refid,
		RefTimeSec:   refSec,
		RefTimeFrac:  refFrac,
		OrigTimeSec:  binary.BigEndian.Uint32(req[40:44]),
		OrigTimeFrac: binary.BigEndian.Uint32(req[44:48]),
		RxTimeSec:    rxSec,
		RxTimeFrac:   rxFrac,
		TxTimeSec:    txSec,
		TxTimeFrac:   txFrac,
	}

	buf := make([]byte, NtpPacketSize)
	buf[0] = packet.Settings
	buf[1] = packet.Stratum
	buf[2] = byte(packet.Poll)
	buf[3] = byte(packet.Precision)
	binary.BigEndian.PutUint32(buf[4:], packet.RootDelay)
	binary.BigEndian.PutUint32(buf[8:], packet.RootDisp)
	binary.BigEndian.PutUint32(buf[12:], packet.RefID)
	binary.BigEndian.PutUint32(buf[16:], packet.RefTimeSec)
	binary.BigEndian.PutUint32(buf[20:], packet.RefTimeFrac)
	binary.BigEndian.PutUint32(buf[24:], packet.OrigTimeSec)
	binary.BigEndian.PutUint32(buf[28:], packet.OrigTimeFrac)
	binary.BigEndian.PutUint32(buf[32:], packet.RxTimeSec)
	binary.BigEndian.PutUint32(buf[36:], packet.RxTimeFrac)
	binary.BigEndian.PutUint32(buf[40:], packet.TxTimeSec)
	binary.BigEndian.PutUint32(buf[44:], packet.TxTimeFrac)

	return buf, totalOffset, driftOffset, jitter, processingDelay, refTimeOffset
}

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	resetState := flag.Bool("reset-state", false, "Reset saved state and start fresh")
	flag.Parse()

	cfg := loadConfig(*configPath)

	var driftSim *DriftSimulator
	var globalRng *rand.Rand
	var currentState *RuntimeState

	// Load or create state
	if cfg.PersistState && !*resetState {
		if state, err := loadState(cfg.StateFile); err == nil {
			log.Printf("Loaded state from %s", cfg.StateFile)
			driftSim = NewDriftSimulatorFromState(cfg, state)
			globalRng = rand.New(rand.NewSource(state.RandomSeed))
			currentState = state
		} else {
			log.Printf("Could not load state (%v), starting fresh", err)
		}
	}

	// Create fresh state if not loaded
	if driftSim == nil {
		seed := time.Now().UnixNano()
		rand.Seed(seed)
		globalRng = rand.New(rand.NewSource(seed))
		driftSim = NewDriftSimulator(cfg)
		currentState = driftSim.GetState()
		currentState.RandomSeed = seed
		log.Printf("Starting with fresh state (seed: %d)", seed)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Received shutdown signal, saving state...")
		if cfg.PersistState {
			state := driftSim.GetState()
			state.RandomSeed = currentState.RandomSeed
			if err := saveState(cfg.StateFile, state); err != nil {
				log.Printf("Error saving state: %v", err)
			} else {
				log.Printf("State saved to %s", cfg.StateFile)
			}
		}
		os.Exit(0)
	}()

	// timeFormat := "2006-01-02 15:04:05 MST"
	timeFormat := "Jan _2 2006  15:04:05.00000000 (MST)"

	addr := net.UDPAddr{
		Port: cfg.Port,
		IP:   net.ParseIP("0.0.0.0"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Cannot listen on UDP %d: %v", addr.Port, err)
	}
	defer conn.Close()

	log.Println("Fake NTP server started on port", addr.Port)

	for {
		buf := make([]byte, NtpPacketSize)
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil || n < NtpPacketSize {
			continue
		}

		version, mode, txSec, txFrac := parseClientInfo(buf)
		if mode != 3 {
			if cfg.Debug {
				fmt.Printf("Ignored request from %s with mode %d\n", clientAddr.IP.String(), mode)
			}
			continue
		}

		if cfg.Debug {
			txFloat := float64(txSec-NtpEpochOffset) + float64(txFrac)/math.Pow(2, 32)
			txUnixSec := int64(txFloat)
			txTime := time.Unix(txUnixSec, int64((txFloat-float64(txUnixSec))*1e9)).UTC().Format(timeFormat)
			fmt.Printf("Request from %s (NTP v%d)\n  - Client transmit timestamp: %s\n",
				clientAddr.IP.String(), version, txTime)
		}

		resp, totalOffset, driftOffset, jitter, processingDelay, refTimeOffset := createFakeNTPResponse(buf, cfg, driftSim, globalRng)
		_, err = conn.WriteToUDP(resp, clientAddr)
		if err != nil && cfg.Debug {
			log.Printf("Error sending: %v", err)
		}

		if cfg.Debug {
			fmt.Printf("Response sent - Total offset: %v | Drift: %.6f ppm (%v), Jitter: %v, Processing delay: %v, RefTime offset: %v\n",
				totalOffset, driftSim.currentDrift, driftOffset, jitter, processingDelay, refTimeOffset)
		}
	}
}
