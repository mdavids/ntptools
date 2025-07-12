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

// NTP constants
const (
        NtpEpochOffset = 2208988800 // Offset between NTP epoch (1 Jan 1900) and Unix epoch (1 Jan 1970) in seconds
        NtpPacketSize  = 48         // Standard NTP packet size in bytes
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

var nowRx time.Time

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
        if config.MinPoll > config.MaxPoll {
                log.Fatalf("Ongeldige poll-range: %d-%d (min moet <= max)", config.MinPoll, config.MaxPoll)
        }

        return config
}

func refIDFromType(refid string, strat uint8) uint32 {
        // XFUN, DENY, INIT, STEP, RATE etc.
        // Zelf zorgen voor de juiste RFC5905 match - of niet ;-)
        switch strat {
        case 0,1,16:
                return binary.BigEndian.Uint32([]byte(refid))
        default: 
                return rand.Uint32()
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

func createFakeNTPResponse(req []byte, cfg Config) []byte {

        refOffset := cfg.MaxRefTimeOffset       // refOffset := rand.Int63n(cfg.MaxRefTimeOffset)
        refTime := nowRx.Add(-time.Duration(refOffset) * time.Second)
        refSec, refFrac := ntpTimestampParts(refTime)

        rxTime := nowRx 
        //rxTime := now.Add(-time.Duration(rand.Intn(5)+1) * time.Millisecond) // Simuleer ontvangstmoment iets eerder (1–5 ms)
        rxSec, rxFrac := ntpTimestampParts(rxTime)
        
        li := uint8(cfg.LeapIndicator & 0x03)
        vn := uint8(cfg.VersionNumber & 0x07)
        mode := uint8(4)
        settings := (li << 6) | (vn << 3) | mode

        precisionRange := cfg.MaxPrecision - cfg.MinPrecision + 1
        precision := int8(rand.Intn(precisionRange) + cfg.MinPrecision)

        pollRange := cfg.MaxPoll - cfg.MinPoll + 1
        poll := int8(rand.Intn(pollRange) + cfg.MinPoll)

        time.Sleep(1 * time.Second)
        // De nowTx zo laat mogelijk
        //nowTx := time.Now()
        //nowTx := time.Date(2040, time.February, 10, 12, 0, 0, 0, time.UTC)
        nowTx := time.Now().AddDate(20, 0, 0) // 20 jaar erbij
        //nowTx := time.Now().Add(1 * time.Hour)
        // zie ook nowRx


        txSec, txFrac := ntpTimestampParts(nowTx)

        stratumRand := uint8(rand.Intn(cfg.MaxStratum-cfg.MinStratum+1) + cfg.MinStratum)
        rootRand := stratumRand
        if stratumRand == 0 {
                rootRand = 1
        }

        packet := NTPPacket{
                Settings:     settings,
                Stratum:      stratumRand,
                Poll:         poll,
                Precision:    precision,
                RootDelay:    100 * (uint32(rootRand) - 1),     // RootDelay:    rand.Uint32(),
                RootDisp:     200 * (uint32(rootRand) - 1),     // RootDisp:     rand.Uint32(),
                RefID:        refIDFromType(cfg.RefIDType, stratumRand),
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

        return buf
}

func main() {
        configPath := flag.String("config", "config.json", "Pad naar configbestand")
        flag.Parse()

        // Seed de random getallengenerator
        rand.Seed(time.Now().UnixNano())

        cfg := loadConfig(*configPath)

        timeFormat := "2006-01-02 15:04:05 MST"

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
                buf := make([]byte, NtpPacketSize)
                n, clientAddr, err := conn.ReadFromUDP(buf)
                if err != nil || n < NtpPacketSize {
                        continue
                }
                
                //nowRx = time.Now() 
                //nowRx = time.Date(2040, time.February, 10, 12, 0, 0, 0, time.UTC)
                nowRx = time.Now().AddDate(20, 0, 0) // 20 jaar erbij
                //nowRx := time.Now().Add(1 * time.Hour)
                // zie ook nowTX

                version, mode, txSec, txFrac := parseClientInfo(buf)
                if mode != 3 {
                        if cfg.Debug {
                                fmt.Printf("Genegeerd verzoek van %s met mode %d\n", clientAddr.IP.String(), mode)
                        }
                        continue
                }

                if cfg.Debug {
                        txFloat := float64(txSec - NtpEpochOffset) + float64(txFrac)/math.Pow(2, 32)
                        txUnixSec := int64(txFloat)
                        txTime := time.Unix(txUnixSec, int64((txFloat-float64(txUnixSec))*1e9)).UTC().Format(timeFormat)
                        fmt.Printf("Verzoek van %s\n  - NTP versie: %d\n  - Client transmit timestamp: %s\n",
                                clientAddr.IP.String(), version, txTime)
                }
                
                resp := createFakeNTPResponse(buf, cfg)
                _, err = conn.WriteToUDP(resp, clientAddr)
                if err != nil && cfg.Debug {
                        log.Printf("Fout bij versturen: %v", err)
                }
        }
}
