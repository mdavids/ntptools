package main

import (
    "fmt"
    "os"
    "syscall"
    "time"
    "unsafe"
)

// struct rtc_time uit <linux/rtc.h>
type rtcTime struct {
    tm_sec   int32
    tm_min   int32
    tm_hour  int32
    tm_mday  int32
    tm_mon   int32
    tm_year  int32
    tm_wday  int32
    tm_yday  int32
    tm_isdst int32
}

func rtcReadTime(dev string) (time.Time, error) {
    file, err := os.Open(dev)
    if err != nil {
        return time.Time{}, err
    }
    defer file.Close()

    var rt rtcTime
    const RTC_RD_TIME = 0x80247009

    _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), RTC_RD_TIME, uintptr(unsafe.Pointer(&rt)))
    if errno != 0 {
        return time.Time{}, errno
    }

    // tm_year is jaren sinds 1900
    year := int(rt.tm_year) + 1900
    // tm_mon is 0-11, time.Month is 1-12
    month := time.Month(rt.tm_mon + 1)
    return time.Date(year, month, int(rt.tm_mday), int(rt.tm_hour), int(rt.tm_min), int(rt.tm_sec), 0, time.UTC), nil
}

func main() {
    rtcTime, err := rtcReadTime("/dev/rtc0")
    if err != nil {
        fmt.Println("Error reading RTC:", err)
        return
    }

    sysTime := time.Now().UTC()

    diff := sysTime.Sub(rtcTime)

    fmt.Printf("RTC time: %v\n", rtcTime)
    fmt.Printf("System time: %v\n", sysTime)
    fmt.Printf("Difference (sys - rtc): %v\n", diff)
}
