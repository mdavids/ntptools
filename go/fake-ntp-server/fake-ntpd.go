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
        "time"
)

type Config struct {
        Port             int    `json:"port"`
        Debug            bool   `json:"debug"`
        MinPoll          int    `json:"min_poll"`
        MaxPoll          int    `json:"max_poll"`
        MinPrecision     int    `json:"min_precision"`
        MaxPrecision     int    `json:"max_precision"`
        MaxRefTimeOffset int64  `json:"max_ref_time_offset"`
        RefIDType        string `json:"ref_id_type"`
        MinStratum       int    `json:"min_stratum"`
        MaxStratum       int    `json:"max_stratum"`
        LeapIndicator    int    `json:"leap_indicator"`
        VersionNumber    int    `json:"version_number"`
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
                log.Fatalf("Kan configbestand niet openen: %v", err)
        }
        defer file.Close()

        decoder := json.NewDecoder(file)
        var config Config
        err = decoder.Decode(&config)
        if err != nil {
                log.Fatalf("Fout bij inlezen configbestand: %v", err)
        }

        if config.LeapIndicator < 0 || config.LeapIndicator > 3 {
                log.Fatalf("Ongeldige leap-indicator: %d (moet 0–3 zijn)", config.LeapIndicator)
        }
        if config.VersionNumber < 1 || config.VersionNumber > 7 {
                log.Fatalf("Ongeldig version number: %d (moet 1–7 zijn)", config.VersionNumber)
        }
        if config.MinStratum < 0 || config.MaxStratum > 16 || config.MinStratum > config.MaxStratum {
                log.Fatalf("Ongeldige stratum-range: %d-%d (moet 0–16 en min<=max)", config.MinStratum, config.MaxStratum)
        }
	if config.MinPrecision > config.MaxPrecision {
		log.Fatalf("Ongeldige precision-range: %d-%d (min moet <= max)", config.MinPrecision, config.MaxPrecision)
	}

        return config
}

func refIDFromType(typ string) uint32 {
        switch typ {
        case "XLOL":
                return binary.BigEndian.Uint32([]byte("XLOL"))
        case "RATE":
                return binary.BigEndian.Uint32([]byte("RATE"))
        case "DENY":
                return binary.BigEndian.Uint32([]byte("DENY"))
        default:
                return rand.Uint32()
        }
}

func ntpTimestampParts(t time.Time) (sec uint32, frac uint32) {
        unixSecs := t.Unix()
        nanos := t.Nanosecond()
        fracSecs := float64(nanos) / 1e9
        sec = uint32(unixSecs + 2208988800)
        frac = uint32(fracSecs * math.Pow(2, 32))
        return
}

func createFakeNTPResponse(req []byte, cfg Config) []byte {
        //now := time.Date(2040, time.February, 10, 12, 0, 0, 0, time.UTC)
        now := time.Now()
        nowSec, nowFrac := ntpTimestampParts(now)
        //nowSec, nowFrac := ntpTimestampParts(now.Add(3600 * time.Second))

        //refOffset := rand.Int63n(cfg.MaxRefTimeOffset)
        refOffset := cfg.MaxRefTimeOffset
        refTime := now.Add(-time.Duration(refOffset) * time.Second)
        refSec, refFrac := ntpTimestampParts(refTime)

        //rxTime := now.Add(-5 * time.Second) // Simuleer ontvangstmoment iets eerder
        rxTime := now
        rxSec, rxFrac := ntpTimestampParts(rxTime)

        li := uint8(cfg.LeapIndicator & 0x03)
        vn := uint8(cfg.VersionNumber & 0x07)
        mode := uint8(4)
        settings := (li << 6) | (vn << 3) | mode

	precisionRange := cfg.MaxPrecision - cfg.MinPrecision + 1
	precision := int8(rand.Intn(precisionRange) + cfg.MinPrecision)

        packet := NTPPacket{
                Settings:     settings,
                Stratum:      uint8(rand.Intn(cfg.MaxStratum-cfg.MinStratum+1) + cfg.MinStratum),
                Poll:         int8(rand.Intn(cfg.MaxPoll-cfg.MinPoll+1) + cfg.MinPoll),
                //Poll:         int8(6),
                //Precision:    precision,
                Precision:    int8(-29),
                //RootDelay:    rand.Uint32(),
                //RootDisp:     rand.Uint32(),
                RootDelay:    0,
                RootDisp:     0,                
                RefID:        refIDFromType(cfg.RefIDType),
                RefTimeSec:   refSec,
                RefTimeFrac:  refFrac,
                OrigTimeSec:  binary.BigEndian.Uint32(req[40:44]),
                OrigTimeFrac: binary.BigEndian.Uint32(req[44:48]),
                RxTimeSec:    rxSec,
                RxTimeFrac:   rxFrac,
                TxTimeSec:    nowSec,
                TxTimeFrac:   nowFrac,
        }

        buf := make([]byte, 48)
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

        return buf
}

func main() {
        configPath := flag.String("config", "config.json", "Pad naar configbestand")
        flag.Parse()
        cfg := loadConfig(*configPath)

        addr := net.UDPAddr{
                Port: cfg.Port,
                IP:   net.ParseIP("0.0.0.0"),
        }
        conn, err := net.ListenUDP("udp", &addr)
        if err != nil {
                log.Fatalf("Kan niet luisteren op UDP %d: %v", addr.Port, err)
        }
        defer conn.Close()

        log.Println("Fake NTP-server gestart op poort", addr.Port)

        for {
                buf := make([]byte, 48)
                n, clientAddr, err := conn.ReadFromUDP(buf)
                if err != nil || n < 48 {
                        continue
                }
                if cfg.Debug {
                        fmt.Printf("Verzoek ontvangen van %s\n", clientAddr)
                }

                resp := createFakeNTPResponse(buf, cfg)
                _, err = conn.WriteToUDP(resp, clientAddr)
                if err != nil && cfg.Debug {
                        log.Printf("Fout bij versturen: %v", err)
                }
        }
}
