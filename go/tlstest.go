//
// Example:
//	./tlstest nts.time.nl 4460 ntske/1
// 
// Thank you ChatGPT...
//

package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run tlstest.go <hostname> <port> [alpn_protocol]")
		return
	}

	hostname := os.Args[1]
	port := os.Args[2]
	address := fmt.Sprintf("%s:%s", hostname, port)

	// Stel tls.Config in zonder ALPN, tenzij os.Args[3] bestaat
	config := &tls.Config{}
	if len(os.Args) > 3 {
		config.NextProtos = []string{os.Args[3]} // Specificeer het ALPN-protocol als het argument aanwezig is
	}

	// Optioneel: TLS-debugging inschakelen
	// config.InsecureSkipVerify = true // Kan worden gebruikt voor testsituaties

	start := time.Now()
	conn, err := tls.Dial("tcp", address, config)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	defer conn.Close()

	elapsed := time.Since(start)

	state := conn.ConnectionState()
	printTLSConnectionInfo(state, elapsed)

	for _, cert := range state.PeerCertificates {
		printCertificateInfo(cert)
	}

	err = verifyCertificateChain(state)
	if err != nil {
		fmt.Printf("Certificate chain verification failed: %v\n", err)
	} else {
		fmt.Println("Certificate chain is valid.")
	}

	// Verkrijg het geonderhandelde protocol (dit zou "" zijn als geen ALPN is gebruikt)
	fmt.Printf("Negotiated Protocol: %s\n", state.NegotiatedProtocol)
}

func printTLSConnectionInfo(state tls.ConnectionState, elapsed time.Duration) {
	fmt.Printf("\nTLS Version: %s\n", tlsVersionName(state.Version))
	fmt.Printf("Cipher Suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("Mutual Protocol Negotiation: %t\n", state.NegotiatedProtocolIsMutual)
	fmt.Printf("Handshake Completion Time: %v\n", elapsed)
	fmt.Printf("SNI: %s\n", state.ServerName)
	fmt.Printf("OCSP Stapling: %t\n", state.OCSPResponse != nil)
}

func printCertificateInfo(cert *x509.Certificate) {
	// Certificaatinformatie afdrukken
	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	fmt.Printf("Not Before: %s\n", cert.NotBefore)
	fmt.Printf("Not After: %s\n", cert.NotAfter)
	fmt.Printf("DNS Names: %v\n", cert.DNSNames)
	printPublicKeyLength(cert.PublicKey)
	printCertificateKeyUsage(cert)

	// Certificaatvingerafdruk berekenen en afdrukken
	fingerprint := calculateFingerprint(cert)
	fmt.Printf("SHA-256 Fingerprint: %s\n", fingerprint)

	fmt.Printf("-----\n")
}

func printPublicKeyLength(pubKey interface{}) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		fmt.Printf("Public Key Type: RSA\n")
		fmt.Printf("Public Key Length: %d bits\n", key.Size()*8)
	case *ecdsa.PublicKey:
		fmt.Printf("Public Key Type: ECDSA\n")
		fmt.Printf("Public Key Length: %d bits\n", key.Params().BitSize)
	default:
		fmt.Printf("Unknown Public Key Type: %s\n", reflect.TypeOf(pubKey))
	}
}

func printCertificateKeyUsage(cert *x509.Certificate) {
	for _, usage := range cert.ExtKeyUsage {
		fmt.Printf("Extended Key Usage: %s\n", extKeyUsageName(usage))
	}
}

func extKeyUsageName(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "Server Authentication"
	case x509.ExtKeyUsageClientAuth:
		return "Client Authentication"
	case x509.ExtKeyUsageCodeSigning:
		return "Code Signing"
	case x509.ExtKeyUsageEmailProtection:
		return "Email Protection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSEC End System"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSEC Tunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSEC User"
	case x509.ExtKeyUsageTimeStamping:
		return "Time Stamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP Signing"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "Microsoft Server Gated Crypto"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "Netscape Server Gated Crypto"
	default:
		return fmt.Sprintf("Unknown (%d)", usage)
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func verifyCertificateChain(state tls.ConnectionState) error {
	// Verifieer de certificaatketen
	opts := x509.VerifyOptions{
		DNSName:       state.ServerName,
		Intermediates: x509.NewCertPool(),
	}

	for _, cert := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}

	_, err := state.PeerCertificates[0].Verify(opts)
	return err
}

func calculateFingerprint(cert *x509.Certificate) string {
	// Bereken de SHA-256 vingerafdruk van het certificaat
	hash := sha256.New()
	hash.Write(cert.Raw) // Raw bevat de DER-gecodeerde versie van het certificaat
	return hex.EncodeToString(hash.Sum(nil))
}

func checkCRL(cert *x509.Certificate) bool {
	// Optioneel: Certificaatverval controleren via CRL
	// Hier zou je een CRL-check kunnen integreren afhankelijk van de serverconfiguratie
	return false // Placeholder voor CRL-check
}
