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
	"time"
)

// Constants for color codes
const (
	GREEN = "\033[32m"
	RESET = "\033[0m"
)

// User agents
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...",
	"Mozilla/5.0 (Linux; Android 10; SM-G975F) ...",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) ...",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) ...",
}

// Config struct
type Config struct {
	BotToken string `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

// Logging functions
func logMessage(message string) {
	fmt.Printf("%s%s%s\n", GREEN, message, RESET)
}

// Create target directory
func createTargetDirectory(target string) string {
	baseDir := "target"
	os.MkdirAll(baseDir, os.ModePerm)
	targetDir := fmt.Sprintf("%s/%s", baseDir, target)
	os.MkdirAll(targetDir, os.ModePerm)
	return targetDir
}

// Get random user agent
func getRandomUserAgent() string {
	rand.Seed(time.Now().UnixNano())
	return userAgents[rand.Intn(len(userAgents))]
}

// Read config from file
func readConfig() (string, string) {
	file, err := os.Open("config.json")
	if err != nil {
		logMessage("[ERROR] Config file issue")
		return "", ""
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		logMessage("[ERROR] Config decoding issue")
		return "", ""
	}

	return config.BotToken, config.ChatID
}

// Send Telegram message
func sendTelegramMessage(botToken, chatID, message string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	payload := fmt.Sprintf(`{"chat_id":"%s","text":"%s","parse_mode":"Markdown"}`, chatID, message)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		logMessage("[ERROR] Failed to create HTTP request")
		return
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logMessage("[ERROR] Failed to send message to Telegram")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		logMessage(fmt.Sprintf("[ERROR] Failed to send message to Telegram. Status: %s, Body: %s", resp.Status, string(body)))
	} else {
		logMessage("✅ [SUCCESS] Message sent to Telegram successfully.")
	}
}

// Execute shell commands
func runCommand(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// Get IP address
func getIP(target string) (string, error) {
	ip, err := net.LookupIP(target)
	if err != nil {
		return "", err
	}
	return ip[0].String(), nil
}

// Whois Lookup
func whoisLookup(target string, targetDir string, sendTelegram bool, botToken string, chatID string) {
	logMessage("Running Whois Lookup... 🔧")
	_, err := runCommand(fmt.Sprintf("whois %s > %s/whois.txt", target, targetDir))
	if err != nil {
		logMessage("[ERROR] Whois command failed")
		return
	}

	if sendTelegram {
		result, _ := ioutil.ReadFile(fmt.Sprintf("%s/whois.txt", targetDir))
		sendTelegramMessage(botToken, chatID, string(result))
	}
}

// NSLookup
func nslookup(target string, targetDir string, sendTelegram bool, botToken string, chatID string) {
	logMessage("Running NSLookup... 🔧")
	_, err := runCommand(fmt.Sprintf("nslookup %s > %s/nslookup.txt", target, targetDir))
	if err != nil {
		logMessage("[ERROR] NSLookup command failed")
		return
	}

	if sendTelegram {
		result, _ := ioutil.ReadFile(fmt.Sprintf("%s/nslookup.txt", targetDir))
		sendTelegramMessage(botToken, chatID, string(result))
	}
}

func ssl_scan(target string, targetDir string, sendTelegram bool, botToken string, chatId string){
	logMessage("Gathering  SSL cert ... " )
	_, err := runCommnad(fmt.Sprintf("go run  ssl-tool.go  -d " target , "-s ssl.txt" targetDir))
	if err != nil {
		logMessage("[ERROR] Ssl Failed..!)
		return
        }

	if sendTelegram{
		result, _ := ioutil.ReadFile(fmt.Sprintf("%s/ssl.txt", targetDir))
		sendTelegram(botToken, chatID, string(result))
	}
}
					 

// Main function
func main() {
	rand.Seed(time.Now().UnixNano())

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the domain name: ")
	target, _ := reader.ReadString('\n')
	target = target[:len(target)-1] // Remove newline character

	targetDir := createTargetDirectory(target)
	botToken, chatID := readConfig()

	logMessage(fmt.Sprintf("Target: %s", target))
	logMessage(fmt.Sprintf("Random User Agent: %s", getRandomUserAgent()))

	ipAddress, err := getIP(target)
	if err != nil {
		logMessage(fmt.Sprintf("[ERROR] Failed to get IP address: %s", err))
		return
	}
	logMessage(fmt.Sprintf("IP Address: %s", ipAddress))

	sendTelegram := botToken != "" && chatID != ""

	whoisLookup(target, targetDir, sendTelegram, botToken, chatID)
	nslookup(target, targetDir, sendTelegram, botToken, chatID)
}
