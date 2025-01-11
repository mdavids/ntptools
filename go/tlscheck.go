package main

//
//./tlscheck -hostname ntppool1.time.nl -port 4460 -timeout 3 -days 365
// 

import (
	"crypto/tls"
	"fmt"
	"os"
	"time"
	"log"
	"flag"
	"net"
)

func main() {
	// Command line argumenten verwerken
	hostname := flag.String("hostname", "", "De hostname of IP-adres van de server")
	port := flag.String("port", "443", "De poort van de server")
	days := flag.Int("days", 10, "Aantal dagen waar het certificaat geldig voor moet zijn")
	timeout := flag.Int("timeout", 10, "Timeout in seconden voor de verbinding")
	flag.Parse()

	if *hostname == "" {
		fmt.Println("Hostname moet opgegeven worden.")
		os.Exit(1)
	}

	// Dialer met timeout instellen
	dialer := &net.Dialer{
		Timeout: time.Duration(*timeout) * time.Second,
	}

	// TLS-configuratie, met TLS 1.2 en TLS 1.3 als ondersteunde protocollen
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, // Minimale versie TLS 1.2
		//MinVersion: tls.VersionTLS12, // Voor als 1.3 niet beschikbaar is (Go < 1.12)
	}

	// Verbinding maken via TLS met timeout en expliciete TLS-configuratie
	address := fmt.Sprintf("%s:%s", *hostname, *port)
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
		log.Fatalf("Fout bij het maken van TLS-verbinding: %v", err)
	}
	defer conn.Close()

	// Certificaat ophalen
	cert := conn.ConnectionState().PeerCertificates[0]
	expiryDate := cert.NotAfter
	daysRemaining := int(expiryDate.Sub(time.Now()).Hours() / 24)

	// Output en controle
	fmt.Printf("Certificaat is nog %d dagen geldig.\n", daysRemaining)

	if daysRemaining <= *days {
		fmt.Println("Waarschuwing: Het certificaat is bijna verlopen!")
		os.Exit(1)
	}

	os.Exit(0)
}
