package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
	"unsafe"

	"github.com/beevik/ntp"
	"golang.org/x/sys/unix"
)

type rtcTime struct {
	TmSec   int32
	TmMin   int32
	TmHour  int32
	TmMday  int32
	TmMon   int32
	TmYear  int32
	TmWday  int32
	TmYday  int32
	TmIsdst int32
}

const (
	RTC_SET_TIME = 0x4024700a // ioctl code uit linux/rtc.h
	RTC_RD_TIME  = 0x80247009
)

func setRTC(t time.Time) error {
	rt := rtcTime{
		TmSec:  int32(t.Second()),
		TmMin:  int32(t.Minute()),
		TmHour: int32(t.Hour()),
		TmMday: int32(t.Day()),
		TmMon:  int32(t.Month()) - 1,
		TmYear: int32(t.Year() - 1900),
	}

	f, err := openRTCDevice()
	if err != nil {
		return err
	}
	defer f.Close()

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		f.Fd(),
		uintptr(RTC_SET_TIME),
		uintptr(unsafe.Pointer(&rt)),
	)
	if errno != 0 {
		return fmt.Errorf("RTC_SET_TIME ioctl fout: %v", errno)
	}
	return nil
}

func readRTC() (time.Time, error) {
	rt := rtcTime{}
	f, err := openRTCDevice()
	if err != nil {
		return time.Time{}, err
	}
	defer f.Close()

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		f.Fd(),
		uintptr(RTC_RD_TIME),
		uintptr(unsafe.Pointer(&rt)),
	)
	if errno != 0 {
		return time.Time{}, fmt.Errorf("RTC_RD_TIME ioctl fout: %v", errno)
	}

	return time.Date(int(rt.TmYear)+1900, time.Month(rt.TmMon)+1, int(rt.TmMday),
		int(rt.TmHour), int(rt.TmMin), int(rt.TmSec), 0, time.Local), nil
}

func setSystemTime(t time.Time) error {
	tv := unix.Timeval{
		Sec:  t.Unix(),
		Usec: int64(t.Nanosecond() / 1000),
	}
	return unix.Settimeofday(&tv)
}

func openRTCDevice() (*os.File, error) {
	rtcDev := "/dev/rtc"
	if _, err := os.Stat(rtcDev); os.IsNotExist(err) {
		rtcDev = "/dev/rtc0"
	}
	return os.OpenFile(rtcDev, os.O_RDWR, 0)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Gebruik: sudo ./settimediff <offset_in_seconden>")
		os.Exit(1)
	}

	offsetSec, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Fout: offset moet een geheel getal zijn.")
		os.Exit(1)
	}

	ipv6FirstDialer := func(localAddr string, remoteAddr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			return nil, err
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, err
		}

		var lastErr error
		timeout := 2 * time.Second

		for _, ip := range ips {
			if ip.To4() == nil {
				conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), port), timeout)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), port), timeout)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
		}
		return nil, lastErr
	}

	resp, err := ntp.QueryWithOptions("any.time.nl", ntp.QueryOptions{
		Timeout: 2 * time.Second,
		Port:    123,
		Dialer:  ipv6FirstDialer,
	})
	if err != nil {
		panic(err)
	}

	ntpTime := time.Now().Add(resp.ClockOffset)
	fmt.Printf("NTP tijd: %v\n", ntpTime)

	fmt.Println("RTC wordt gezet naar NTP-tijd...")
	if err := setRTC(ntpTime); err != nil {
		fmt.Printf("❌ Fout bij zetten van RTC: %v\n", err)
	} else {
		fmt.Println("✅ RTC succesvol gezet.")
	}

	systemTime := ntpTime.Add(time.Duration(offsetSec) * time.Second)
	fmt.Printf("Systeemtijd wordt gezet naar: %v (NTP + %d sec)\n", systemTime, offsetSec)
	if err := setSystemTime(systemTime); err != nil {
		fmt.Printf("❌ Fout bij zetten van systeemtijd: %v\n", err)
	} else {
		fmt.Println("✅ Systeemtijd succesvol gezet.")
	}

	rtcRead, err := readRTC()
	if err != nil {
		fmt.Printf("⚠️ Kon RTC niet uitlezen: %v\n", err)
	} else {
		fmt.Printf("📟 RTC nu: %v\n", rtcRead)
	}

	sysTime := time.Now()
	fmt.Printf("🖥️  Systeemtijd nu: %v\n", sysTime)
}
