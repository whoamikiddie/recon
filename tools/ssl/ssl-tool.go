package main

import (
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
	R = "\033[31m"
	G = "\033[32m"
	C = "\033[36m"
	W = "\033[0m"
	Y = "\033[33m"
)

type OutputConfig struct {
	FilePath string `json:"filePath"`
}

type CertificateInfo struct {
	Protocol        string            `json:"protocol"`
	Cipher          uint16            `json:"cipher"`
	Subject         map[string]string `json:"subject"`
	Issuer          map[string]string `json:"issuer"`
	Version         string            `json:"version"`
	SerialNumber    string            `json:"serialNumber"`
	NotBefore       string            `json:"notBefore"`
	NotAfter        string            `json:"notAfter"`
	SubjectAltNames []string          `json:"subjectAltName,omitempty"`
}

func logWriter(message string) {
	logFile, err := os.OpenFile("ssl_log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	if _, err := logFile.WriteString(message + "\n"); err != nil {
		log.Fatal(err)
	}
}

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

	if len(data.SubjectAltNames) > 0 {
		fmt.Println(Y + "[+] Subject Alternative Names:" + W)
		for i, name := range data.SubjectAltNames {
			fmt.Printf("        └╴%d: %s\n", i, name)
		}
	}
}

func export(output OutputConfig, data CertificateInfo) {
	var content string
	fileExt := filepath.Ext(output.FilePath)

	if fileExt == ".txt" {
		content += fmt.Sprintf("Protocol: %s\n", data.Protocol)
		content += fmt.Sprintf("Cipher:\n")
		content += fmt.Sprintf("  └╴0: %s\n", tls.CipherSuiteName(data.Cipher))
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
		if len(data.SubjectAltNames) > 0 {
			content += "Subject Alternative Names:\n"
			for i, name := range data.SubjectAltNames {
				content += fmt.Sprintf("  └╴%d: %s\n", i, name)
			}
		}
	} else {
		var err error
		contentBytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		content = string(contentBytes)
	}

	if err := ioutil.WriteFile(output.FilePath, []byte(content), 0644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s[+] Data exported to %s%s\n", G, output.FilePath, W)
}

func getCertificateInfo(hostname string) (*CertificateInfo, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", hostname, 443), 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	tlsConn := tls.Client(conn, tlsConfig)

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	cert := tlsConn.ConnectionState().PeerCertificates[0]

	subject := make(map[string]string)
	for _, attr := range cert.Subject.Names {
		subject[attr.Type.String()] = attr.Value.(string)
	}

	issuer := make(map[string]string)
	for _, attr := range cert.Issuer.Names {
		issuer[attr.Type.String()] = attr.Value.(string)
	}

	return &CertificateInfo{
		Protocol:     tlsConn.ConnectionState().NegotiatedProtocol,
		Cipher:       tlsConn.ConnectionState().CipherSuite,
		Subject:      subject,
		Issuer:       issuer,
		Version:      fmt.Sprintf("%d", cert.Version),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore.UTC().Format(time.RFC1123),
		NotAfter:     cert.NotAfter.UTC().Format(time.RFC1123),
	}, nil
}

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: sslinfo -d <domain> -o <output_file_path>")
		return
	}

	var domain string
	var outputFilePath string

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
		}
	}

	output := OutputConfig{
		FilePath: outputFilePath,
	}

	certInfo, err := getCertificateInfo(domain)
	if err != nil {
		fmt.Printf("%s[-] %sSSL is not present on target URL... Skipping...%s\n", R, C, W)
		logWriter("[sslinfo] SSL is not present on target URL... Skipping...")
		return
	}

	display(*certInfo)

	export(output, *certInfo)
	logWriter("[sslinfo] Completed")
}
