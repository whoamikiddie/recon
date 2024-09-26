package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type WhoisServer struct {
	Servers map[string]string `json:"servers"`
}

type WhoisInfo struct {
	DomainName           string   `json:"domain_name,omitempty"`
	RegistryDomainID     string   `json:"registry_domain_id,omitempty"`
	RegistrarWHOISServer string   `json:"registrar_whois_server,omitempty"`
	RegistrarURL         string   `json:"registrar_url,omitempty"`
	UpdatedDate          string   `json:"updated_date,omitempty"`
	CreationDate         string   `json:"creation_date,omitempty"`
	RegistryExpiryDate   string   `json:"registry_expiry_date,omitempty"`
	Registrar            string   `json:"registrar,omitempty"`
	DomainStatus         string   `json:"domain_status,omitempty"`
	RegistrantName       string   `json:"registrant_name,omitempty"`
	RegistrantOrg        string   `json:"registrant_organization,omitempty"`
	RegistrantCountry    string   `json:"registrant_country,omitempty"`
	NameServers          []string `json:"name_servers,omitempty"`
}

func getWhois(domain, server string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:43", server), 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server: %w", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\r\n", domain)

	var rawResp strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		rawResp.WriteString(scanner.Text() + "\n")
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading WHOIS response: %w", err)
	}

	return rawResp.String(), nil
}

func parseWhoisData(whoisInfo string) WhoisInfo {
	lines := strings.Split(whoisInfo, "\n")
	whoisData := WhoisInfo{}
	for _, line := range lines {
		if strings.HasPrefix(line, "Domain Name:") {
			whoisData.DomainName = strings.TrimSpace(strings.TrimPrefix(line, "Domain Name:"))
		} else if strings.HasPrefix(line, "Registry Domain ID:") {
			whoisData.RegistryDomainID = strings.TrimSpace(strings.TrimPrefix(line, "Registry Domain ID:"))
		} else if strings.HasPrefix(line, "Registrar WHOIS Server:") {
			whoisData.RegistrarWHOISServer = strings.TrimSpace(strings.TrimPrefix(line, "Registrar WHOIS Server:"))
		} else if strings.HasPrefix(line, "Registrar URL:") {
			whoisData.RegistrarURL = strings.TrimSpace(strings.TrimPrefix(line, "Registrar URL:"))
		} else if strings.HasPrefix(line, "Updated Date:") {
			whoisData.UpdatedDate = strings.TrimSpace(strings.TrimPrefix(line, "Updated Date:"))
		} else if strings.HasPrefix(line, "Creation Date:") {
			whoisData.CreationDate = strings.TrimSpace(strings.TrimPrefix(line, "Creation Date:"))
		} else if strings.HasPrefix(line, "Registry Expiry Date:") {
			whoisData.RegistryExpiryDate = strings.TrimSpace(strings.TrimPrefix(line, "Registry Expiry Date:"))
		} else if strings.HasPrefix(line, "Registrar:") {
			whoisData.Registrar = strings.TrimSpace(strings.TrimPrefix(line, "Registrar:"))
		} else if strings.HasPrefix(line, "Domain Status:") {
			whoisData.DomainStatus += strings.TrimSpace(strings.TrimPrefix(line, "Domain Status:")) + "; "
		} else if strings.HasPrefix(line, "Registrant Name:") {
			whoisData.RegistrantName = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Name:"))
		} else if strings.HasPrefix(line, "Registrant Organization:") {
			whoisData.RegistrantOrg = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Organization:"))
		} else if strings.HasPrefix(line, "Registrant Country:") {
			whoisData.RegistrantCountry = strings.TrimSpace(strings.TrimPrefix(line, "Registrant Country:"))
		} else if strings.HasPrefix(line, "Name Server:") {
			whoisData.NameServers = append(whoisData.NameServers, strings.TrimSpace(strings.TrimPrefix(line, "Name Server:")))
		}
	}
	return whoisData
}

func whoisLookup(domain string, tld string, scriptPath string, output string, format string) {
	dbPath := fmt.Sprintf("%s/whois_servers.json", scriptPath)
	file, err := os.Open(dbPath)
	if err != nil {
		fmt.Printf("[-] Error: WHOIS servers database not found at %s.\n", dbPath)
		return
	}
	defer file.Close()

	var whoisServers WhoisServer
	if err := json.NewDecoder(file).Decode(&whoisServers); err != nil {
		fmt.Printf("[-] Error reading JSON: %s\n", err)
		return
	}

	fmt.Println("\n[!] WHOIS Lookup:\n")

	whoisServer, ok := whoisServers.Servers[tld]
	if !ok {
		fmt.Println("[-] Error: This domain suffix is not supported.")
		return
	}

	whoisInfoRaw, err := getWhois(fmt.Sprintf("%s.%s", domain, tld), whoisServer)
	if err != nil {
		fmt.Printf("[-] Error: %s\n", err)
		return
	}

	whoisData := parseWhoisData(whoisInfoRaw)

	if format == "json" {
		jsonOutput, _ := json.MarshalIndent(whoisData, "", "  ")
		whoisInfoRaw = string(jsonOutput)
	}

	fmt.Println(whoisInfoRaw)

	if output != "" {
		err := os.WriteFile(output, []byte(whoisInfoRaw), 0644)
		if err != nil {
			fmt.Printf("[-] Error writing to file: %s\n", err)
		} else {
			fmt.Printf("Exporting to %s with data:\n%s\n", output, whoisInfoRaw)
		}
	}

	fmt.Println("[WHOIS] Completed")
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: whoislookup -d <domain1,domain2,...> [-o <output>] [-s <script-path>] [-f <format>]")
		return
	}

	var domains []string
	output := ""
	scriptPath := "."
	format := "text"

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-d":
			i++
			if i < len(os.Args) {
				domains = strings.Split(os.Args[i], ",")
			}
		case "-o":
			i++
			if i < len(os.Args) {
				output = os.Args[i]
			}
		case "-s":
			i++
			if i < len(os.Args) {
				scriptPath = os.Args[i]
			}
		case "-f":
			i++
			if i < len(os.Args) {
				format = os.Args[i]
				if format != "text" && format != "json" {
					fmt.Println("[-] Error: Format must be 'text' or 'json'.")
					return
				}
			}
		}
	}

	for _, domain := range domains {
		domainParts := strings.Split(domain, ".")
		if len(domainParts) < 2 {
			fmt.Printf("[-] Error: Invalid domain format for '%s'. Please provide a full domain (e.g., example.com).\n", domain)
			continue
		}

		tld := domainParts[len(domainParts)-1]
		whoisLookup(domainParts[0], tld, scriptPath, output, format)
	}
}
