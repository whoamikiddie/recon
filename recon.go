package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Constant
const (
	GREEN             = "\033[32m"
	RED               = "\033[31m"
	RESET             = "\033[0m"
	ContentType       = "application/json"
	WhoisFileName     = "whois.txt"
	NSLookupFileName  = "nslookup.txt"
	SSLFileName       = "ssl.json"
	SubdomainFileName = "subdomains.txt"
)

// user agents
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...",
	// Add more user agents as needed...
}

// config file
type Config struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

// Logs
func logMessage(message string) {
	fmt.Printf("%s%s%s\n", GREEN, message, RESET)
}

func logError(err error, context string) {
	fmt.Printf("%s[ERROR] %s: %s%s\n", RED, context, err.Error(), RESET)
}

// Create dir
func createTargetDirectory(target string) string {
	baseDir := "target"
	os.MkdirAll(baseDir, os.ModePerm)
	targetDir := fmt.Sprintf("%s/%s", baseDir, target)
	os.MkdirAll(targetDir, os.ModePerm)
	return targetDir
}

// random user agent
func getRandomUserAgent() string {
	rand.Seed(time.Now().UnixNano())
	return userAgents[rand.Intn(len(userAgents))]
}

// Read config
func readConfig(filePath string) (string, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return "", "", err
	}

	return config.BotToken, config.ChatID, nil
}

// Telegram message
func sendTelegramMessage(botToken, chatID, message string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	payload := fmt.Sprintf(`{"chat_id":"%s","text":"%s","parse_mode":"Markdown"}`, chatID, message)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", ContentType)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send message to Telegram: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("failed to send message to Telegram. Status: %s, Body: %s", resp.Status, string(body))
	}
	logMessage("✅ [SUCCESS] Message sent to Telegram successfully.")
	return nil
}

// Execute shell commands
func runCommand(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// IPv4 address for a domain
func getIP(target string) (string, error) {
	ips, err := net.LookupIP(target)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found for target: %s", target)
}

func isValidIP(ip string) bool {
	ipRegex := `^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`
	re := regexp.MustCompile(ipRegex)
	return re.MatchString(ip)
}

// whois lookup
func whoisLookup(target, targetDir string, sendTelegram bool, botToken, chatID string) {
	logMessage("Running Whois Lookup... 🔧")
	_, err := runCommand(fmt.Sprintf("whois %s > %s/%s", target, targetDir, WhoisFileName))
	if err != nil {
		logError(err, "Whois command failed")
		return
	}

	if sendTelegram {
		sendFileToTelegram(fmt.Sprintf("%s/%s", targetDir, WhoisFileName), target, "Whois Lookup Result", botToken, chatID)
	}
}

// nslookup
func nslookup(target, targetDir string, sendTelegram bool, botToken, chatID string) {
	logMessage("Running NSLookup... 🔧")
	_, err := runCommand(fmt.Sprintf("nslookup %s > %s/%s", target, targetDir, NSLookupFileName))
	if err != nil {
		logError(err, "NSLookup command failed")
		return
	}

	if sendTelegram {
		sendFileToTelegram(fmt.Sprintf("%s/%s", targetDir, NSLookupFileName), target, "NSLookup Result", botToken, chatID)
	}
}

// SSL scan
func sslScan(target, targetDir string, sendTelegram bool, botToken, chatID string) {
	logMessage("Gathering SSL cert... 🔍")

	output, err := runCommand(fmt.Sprintf("sslscan --json %s", target))
	if err != nil {
		logError(err, "SSL scan failed")
		return
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/%s", targetDir, SSLFileName), []byte(output), 0644)
	if err != nil {
		logError(err, "Failed to write ssl.json")
		return
	}

	if sendTelegram {
		formattedMessage := fmt.Sprintf("*SSL Scan Result for %s:*\n```\n%s```", target, output)
		if err := sendTelegramMessage(botToken, chatID, formattedMessage); err != nil {
			logError(err, "Failed to send SSL scan result to Telegram")
		}
	}
}

// Gather subdomains
func subdomains(target, targetDir string, sendTelegram bool, botToken, chatID string) {
	logMessage("Gathering subdomains...")

	subfinderOutput, err := runCommand(fmt.Sprintf("subfinder -d %s -silent", target))
	if err != nil {
		logError(err, "subfinder failed or check if subfinder is installed")
		return
	}

	assetfinderOutput, err := runCommand(fmt.Sprintf("assetfinder --subs-only %s", target))
	if err != nil {
		logError(err, "assetfinder failed or check if assetfinder is installed")
		return
	}

	// remove duplicates
	subdomainMap := make(map[string]struct{})
	for _, line := range append(strings.Split(subfinderOutput, "\n"), strings.Split(assetfinderOutput, "\n")...) {
		line = strings.TrimSpace(line)
		if line != "" {
			subdomainMap[line] = struct{}{}
		}
	}

	var uniqueSubdomains []string
	for subdomain := range subdomainMap {
		uniqueSubdomains = append(uniqueSubdomains, subdomain)
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/%s", targetDir, SubdomainFileName), []byte(strings.Join(uniqueSubdomains, "\n")), 0644)
	if err != nil {
		logError(err, "Failed to write subdomains.txt")
		return
	}

	if sendTelegram {
		formattedMessage := fmt.Sprintf("*Subdomains for %s:*\n```\n%s```", target, strings.Join(uniqueSubdomains, "\n"))
		if err := sendTelegramMessage(botToken, chatID, formattedMessage); err != nil {
			logError(err, "Failed to send Telegram message")
		}
	}
}

func sendFileToTelegram(filePath, target, title, botToken, chatID string) {
	result, err := ioutil.ReadFile(filePath)
	if err != nil {
		logError(err, fmt.Sprintf("Failed to read %s", title))
		return
	}

	formattedMessage := fmt.Sprintf("*%s for %s:*\n```\n%s```", title, target, string(result))
	if err := sendTelegramMessage(botToken, chatID, formattedMessage); err != nil {
		logError(err, fmt.Sprintf("Failed to send %s to Telegram", title))
	}
}

// Ask  for user input
func askForConfirmation(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt + " (yes/no): ")
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(response)

	return response == "yes" || response == "y"
}

// Main func
func main() {
	rand.Seed(time.Now().UnixNano())

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the domain name or IP address: ")
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)

	targetDir := createTargetDirectory(target)

	configFilePath := "config.json"
	botToken, chatID, err := readConfig(configFilePath)
	if err != nil {
		logError(err, "Config file issue")
		return
	}

	logMessage(fmt.Sprintf("Target: %s", target))
	logMessage(fmt.Sprintf("Random User Agent: %s", getRandomUserAgent()))

	var ipAddress string
	if isValidIP(target) {
		ipAddress = target
		logMessage(fmt.Sprintf("Using provided IP Address: %s", ipAddress))
	} else {
		ipAddress, err = getIP(target)
		if err != nil {
			logError(err, "Failed to get IPv4 address")
			return
		}
		logMessage(fmt.Sprintf("Resolved IPv4 Address: %s", ipAddress))
	}

	sendTelegram := botToken != "" && chatID != "" && askForConfirmation("Do you want to send the results to Telegram?")

	whoisLookup(target, targetDir, sendTelegram, botToken, chatID)
	nslookup(target, targetDir, sendTelegram, botToken, chatID)
	sslScan(target, targetDir, sendTelegram, botToken, chatID)
	subdomains(target, targetDir, sendTelegram, botToken, chatID)

	logMessage("All tasks completed.")
}
