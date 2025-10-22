package main

import (
	"fmt"
	"net"
	"time"

	"github.com/beevik/ntp"
)

func main() {
	// Maak een functie die IPv6 probeert vóór IPv4
	ipv6FirstDialer := func(localAddr string, remoteAddr string) (net.Conn, error) {
		// host en port splitten
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

		// Eerst IPv6
		for _, ip := range ips {
			if ip.To4() == nil {
				conn, err := net.DialTimeout("udp", net.JoinHostPort(ip.String(), port), timeout)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
		}

		// Dan IPv4 fallback
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

	// Gebruik QueryWithOptions met onze dialer
	resp, err := ntp.QueryWithOptions("any.time.nl", ntp.QueryOptions{
		Timeout: 2 * time.Second,
		Port:    123,
		Dialer:  ipv6FirstDialer,
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("NTP tijd: %v\n", time.Now().Add(resp.ClockOffset))
}
