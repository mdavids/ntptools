package main

import (
        "crypto/tls"
        "crypto/x509"
        "encoding/json"
        "flag"
        "fmt"
        "io/ioutil"
        "log"
        "net"
        "os"
        "os/signal"
        "time"
)

// Main function
func main() {
        // Define command-line flags
        hostname := flag.String("hostname", "", "Hostname or IP address of the server")
        port := flag.String("port", "443", "Port of the server (default: 443)")
        days := flag.Int("days", 10, "Number of days the certificate should be valid for")
        timeout := flag.Int("timeout", 10, "Connection timeout in seconds")
        customCA := flag.String("ca", "", "Path to a custom CA certificate (optional)")
        verbose := flag.Bool("verbose", false, "Display detailed certificate information")
        outputJSON := flag.Bool("json", false, "Output verbose results in JSON format regardless of the verbose option")
        flag.Usage = func() {
                fmt.Fprintf(os.Stderr, "Usage: %s -hostname <hostname> -port <port> -timeout <seconds> -days <days> -ca <custom-ca-path>\n", os.Args[0])
                flag.PrintDefaults()
        }
        flag.Parse()

        // Ensure hostname is provided
        if *hostname == "" {
                flag.Usage()
                os.Exit(1)
        }

        // Handle graceful shutdown on interrupt (Ctrl+C)
        c := make(chan os.Signal, 1)
        signal.Notify(c, os.Interrupt)
        go func() {
                <-c
                fmt.Println("\nShutting down...")
                os.Exit(0)
        }()

        // Load system root certificates
        rootCAs, err := x509.SystemCertPool()
        if err != nil || rootCAs == nil {
                log.Println("Could not load system root CAs, creating a new cert pool")
                rootCAs = x509.NewCertPool()
        }

        // Load custom CA certificate if provided
        if *customCA != "" {
                caCert, err := ioutil.ReadFile(*customCA)
                if err != nil {
                        log.Fatalf("Failed to read custom CA certificate: %v", err)
                }
                if ok := rootCAs.AppendCertsFromPEM(caCert); !ok {
                        log.Fatalf("Failed to append custom CA certificate")
                }
                log.Println("Custom CA certificate loaded successfully")
        }

        // TLS configuration
        tlsConfig := &tls.Config{
                RootCAs: rootCAs,
        }

        // Dialer with timeout settings
        dialer := &net.Dialer{
                Timeout: time.Duration(*timeout) * time.Second,
        }

        // Establish a TLS connection
        address := fmt.Sprintf("%s:%s", *hostname, *port)
        conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
        if err != nil {
                log.Fatalf("Failed to establish TLS connection: %v", err)
        }
        defer conn.Close()

        // Retrieve connection state
        state := conn.ConnectionState()
        if len(state.PeerCertificates) == 0 {
                log.Fatalf("No certificates received from server")
        }

        // Extract the server certificate (first in the chain)
        cert := state.PeerCertificates[0]
        now := time.Now().UTC()
        expiryDate := cert.NotAfter.UTC()
        daysRemaining := int(expiryDate.Sub(now).Hours() / 24)

        // Verify hostname matches the certificate
        if err := cert.VerifyHostname(*hostname); err != nil {
                log.Fatalf("Hostname %s does not match the certificate: %v", *hostname, err)
        }

        // Display results in JSON format if requested
        if *outputJSON {
                output := map[string]interface{}{
                        "hostname":      *hostname,
                        "port":          *port,
                        "valid_days":    daysRemaining,
                        "expiry_date":   expiryDate,
                        "is_near_expiry": daysRemaining <= *days,
                }
                jsonOutput, _ := json.MarshalIndent(output, "", "  ")
                fmt.Println(string(jsonOutput))
        } else {
                // Default human-readable output
                fmt.Printf("Certificate is valid for %d more days.\n", daysRemaining)
                if *verbose {
                        fmt.Printf("Subject: %s\n", cert.Subject)
                        fmt.Printf("Issuer: %s\n", cert.Issuer)
                        fmt.Printf("Serial Number: %s\n", cert.SerialNumber)
                        fmt.Printf("Expiration Date: %s\n", expiryDate)
                }
        }

        // Warn if the certificate is near expiry
        if daysRemaining <= *days {
                fmt.Println("Warning: The certificate is close to expiring!")
                os.Exit(1)
        }

        // Success
        os.Exit(0)
}
