package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	R = "\033[38;5;196m" // Light Red
	G = "\033[38;5;82m"  // Light Green
	C = "\033[38;5;117m" // Light Cyan
	W = "\033[0m"        // Reset
	Y = "\033[38;5;226m" // Light Yellow
)

type OutputConfig struct {
	FilePath string `json:"filePath"`
}

type CertificateInfo struct {
	Protocol           string              `json:"protocol"`
	Cipher             uint16              `json:"cipher"`
	Subject            map[string]string   `json:"subject"`
	Issuer             map[string]string   `json:"issuer"`
	Version            string              `json:"version"`
	SerialNumber       string              `json:"serialNumber"`
	NotBefore          string              `json:"notBefore"`
	NotAfter           string              `json:"notAfter"`
	KeyLength          int                 `json:"keyLength"`
	SignatureAlgorithm string              `json:"signatureAlgorithm"`
	Chain              []CertificateDetail `json:"chain,omitempty"`
}

type CertificateDetail struct {
	Subject            map[string]string `json:"subject"`
	Issuer             map[string]string `json:"issuer"`
	Version            string            `json:"version"`
	SerialNumber       string            `json:"serialNumber"`
	NotBefore          string            `json:"notBefore"`
	NotAfter           string            `json:"notAfter"`
	KeyLength          int               `json:"keyLength"`
	SignatureAlgorithm string            `json:"signatureAlgorithm"`
}

// logWriter appends messages to a log file
func logWriter(message string) {
	logFile, err := os.OpenFile("ssl_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	if _, err := logFile.WriteString(message + "\n"); err != nil {
		log.Fatalf("Failed to write to log file: %v", err)
	}
}

// display prints certificate information to the console
func display(data CertificateInfo) {
	fmt.Println("\n" + Y + "[+] SSL Certificate Information:" + W)
	fmt.Printf("%sProtocol: %s\n", G, data.Protocol)
	fmt.Printf("%sCipher:\n", G)
	fmt.Printf("        └╴0: %s\n", tls.CipherSuiteName(data.Cipher))

	fmt.Println(Y + "[+] Subject:" + W)
	for k, v := range data.Subject {
		fmt.Printf("        └╴%s: %s\n", k, v)
	}

	fmt.Println(Y + "[+] Issuer:" + W)
	for k, v := range data.Issuer {
		fmt.Printf("        └╴%s: %s\n", k, v)
	}

	fmt.Printf("%sVersion: %s\n", G, data.Version)
	fmt.Printf("%sSerial Number: %s\n", G, data.SerialNumber)
	fmt.Printf("%sNot Before: %s\n", G, data.NotBefore)
	fmt.Printf("%sNot After: %s\n", G, data.NotAfter)
	fmt.Printf("%sKey Length: %d bits\n", G, data.KeyLength)
	fmt.Printf("%sSignature Algorithm: %s\n", G, data.SignatureAlgorithm)

	if len(data.Chain) > 0 {
		fmt.Println(Y + "[+] Certificate Chain:" + W)
		for i, cert := range data.Chain {
			fmt.Printf("  └╴Certificate %d:\n", i)
			for k, v := range cert.Subject {
				fmt.Printf("        └╴%s: %s\n", k, v)
			}
			for k, v := range cert.Issuer {
				fmt.Printf("        └╴%s: %s\n", k, v)
			}
			fmt.Printf("        └╴Version: %s\n", cert.Version)
			fmt.Printf("        └╴Serial Number: %s\n", cert.SerialNumber)
			fmt.Printf("        └╴Not Before: %s\n", cert.NotBefore)
			fmt.Printf("        └╴Not After: %s\n", cert.NotAfter)
			fmt.Printf("        └╴Key Length: %d bits\n", cert.KeyLength)
			fmt.Printf("        └╴Signature Algorithm: %s\n", cert.SignatureAlgorithm)
		}
	}
}

// export writes the certificate information to a file in the specified format
func export(output OutputConfig, data CertificateInfo) {
	var content string
	fileExt := filepath.Ext(output.FilePath)

	if fileExt == ".txt" {
		content = formatText(data)
	} else {
		content = formatJSON(data)
	}

	if err := ioutil.WriteFile(output.FilePath, []byte(content), 0644); err != nil {
		log.Fatalf("Failed to write to output file: %v", err)
	}
	fmt.Printf("%s[+] Data exported to %s%s\n", G, output.FilePath, W)
}

// formatText formats the certificate info as a plain text string
func formatText(data CertificateInfo) string {
	content := fmt.Sprintf("Protocol: %s\n", data.Protocol)
	content += fmt.Sprintf("Cipher:\n  └╴0: %s\n", tls.CipherSuiteName(data.Cipher))
	content += "Subject:\n"
	for k, v := range data.Subject {
		content += fmt.Sprintf("  └╴%s: %s\n", k, v)
	}
	content += "Issuer:\n"
	for k, v := range data.Issuer {
		content += fmt.Sprintf("  └╴%s: %s\n", k, v)
	}
	content += fmt.Sprintf("Version: %s\n", data.Version)
	content += fmt.Sprintf("Serial Number: %s\n", data.SerialNumber)
	content += fmt.Sprintf("Not Before: %s\n", data.NotBefore)
	content += fmt.Sprintf("Not After: %s\n", data.NotAfter)
	content += fmt.Sprintf("Key Length: %d bits\n", data.KeyLength)
	content += fmt.Sprintf("Signature Algorithm: %s\n", data.SignatureAlgorithm)

	for i, cert := range data.Chain {
		content += fmt.Sprintf("Certificate %d:\n", i)
		for k, v := range cert.Subject {
			content += fmt.Sprintf("  └╴%s: %s\n", k, v)
		}
		for k, v := range cert.Issuer {
			content += fmt.Sprintf("  └╴%s: %s\n", k, v)
		}
		content += fmt.Sprintf("  └╴Version: %s\n", cert.Version)
		content += fmt.Sprintf("  └╴Serial Number: %s\n", cert.SerialNumber)
		content += fmt.Sprintf("  └╴Not Before: %s\n", cert.NotBefore)
		content += fmt.Sprintf("  └╴Not After: %s\n", cert.NotAfter)
		content += fmt.Sprintf("  └╴Key Length: %d bits\n", cert.KeyLength)
		content += fmt.Sprintf("  └╴Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	}
	return content
}

// formatJSON formats the certificate info as a JSON string
func formatJSON(data CertificateInfo) string {
	contentBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}
	return string(contentBytes)
}

// getCertificateInfo retrieves the SSL certificate info from the specified hostname
func getCertificateInfo(hostname string, timeout time.Duration) (*CertificateInfo, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", hostname, 443), timeout)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", hostname, err)
		return nil, err
	}
	defer conn.Close()

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	tlsConn := tls.Client(conn, tlsConfig)

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return nil, err
	}

	// Handle multiple certificates
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	chain := make([]CertificateDetail, len(certs))
	for i, cert := range certs {
		subject := make(map[string]string)
		for _, attr := range cert.Subject.Names {
			subject[attr.Type.String()] = attr.Value.(string)
		}

		issuer := make(map[string]string)
		for _, attr := range cert.Issuer.Names {
			issuer[attr.Type.String()] = attr.Value.(string)
		}

		chain[i] = CertificateDetail{
			Subject:            subject,
			Issuer:             issuer,
			Version:            fmt.Sprintf("%d", cert.Version),
			SerialNumber:       cert.SerialNumber.String(),
			NotBefore:          cert.NotBefore.UTC().Format(time.RFC1123),
			NotAfter:           cert.NotAfter.UTC().Format(time.RFC1123),
			KeyLength:          getKeyLength(cert.PublicKey),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		}
	}

	// Process the first certificate for main details
	cert := certs[0]
	subject := make(map[string]string)
	for _, attr := range cert.Subject.Names {
		subject[attr.Type.String()] = attr.Value.(string)
	}

	issuer := make(map[string]string)
	for _, attr := range cert.Issuer.Names {
		issuer[attr.Type.String()] = attr.Value.(string)
	}

	return &CertificateInfo{
		Protocol:           tlsConn.ConnectionState().NegotiatedProtocol,
		Cipher:             tlsConn.ConnectionState().CipherSuite,
		Subject:            subject,
		Issuer:             issuer,
		Version:            fmt.Sprintf("%d", cert.Version),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore.UTC().Format(time.RFC1123),
		NotAfter:           cert.NotAfter.UTC().Format(time.RFC1123),
		KeyLength:          getKeyLength(cert.PublicKey),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		Chain:              chain,
	}, nil
}

// getKeyLength determines the length of the public key
func getKeyLength(pubKey interface{}) int {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return key.Size() * 8 // Convert bytes to bits
	case *ecdsa.PublicKey:
		return key.Params().BitSize
	default:
		return 0 // Unknown key type
	}
}

func main() {
	if len(os.Args) < 5 {
		fmt.Println("Usage: sslinfo -d <domain> -o <output_file_path> [-t <timeout_in_seconds>]")
		return
	}

	var domain string
	var outputFilePath string
	var timeout time.Duration = 5 * time.Second // Default timeout

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-d":
			if i+1 < len(os.Args) {
				domain = os.Args[i+1]
				i++
			}
		case "-o":
			if i+1 < len(os.Args) {
				outputFilePath = os.Args[i+1]
				i++
			}
		case "-t":
			if i+1 < len(os.Args) {
				var err error
				timeoutValue := os.Args[i+1]
				timeout, err = time.ParseDuration(timeoutValue + "s")
				if err != nil {
					log.Fatalf("Invalid timeout value: %v", err)
				}
				i++
			}
		}
	}

	output := OutputConfig{
		FilePath: outputFilePath,
	}

	certInfo, err := getCertificateInfo(domain, timeout)
	if err != nil {
		fmt.Printf("%s[-] %sSSL is not present on target URL... Skipping...%s\n", R, C, W)
		logWriter("[sslinfo] SSL is not present on target URL... Skipping...")
		os.Exit(1) // Graceful exit with non-zero status
	}

	display(*certInfo)

	export(output, *certInfo)
	logWriter("[sslinfo] Completed")
}
