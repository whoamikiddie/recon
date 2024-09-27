package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"time"
)

func init() {
	rand.Seed(int64(rand.Intn(100000)))
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS X 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
}

func getUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func getRobots(domain string, enableSave bool, filename string, client *http.Client, wg *sync.WaitGroup) {
	defer wg.Done() // Signal that this goroutine is done
	fmt.Printf("Fetching robots.txt for %s...\n", domain)

	req, _ := http.NewRequest("GET", "https://"+domain+"/robots.txt", nil)
	req.Header.Set("User-Agent", getUserAgent())
	resp, err := client.Do(req)

	if err != nil {
		req.URL.Scheme = "http"
		resp, err = client.Do(req)
		if err != nil {
			log.Printf("Error fetching robots.txt: %v\n", err)
			return
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		processRobots(resp.Body, enableSave, filename, domain)
	} else {
		log.Printf("robots.txt file not found for %s. Status code: %d\n", domain, resp.StatusCode)
	}
}

func processRobots(body io.Reader, enableSave bool, filename, domain string) {
	scanner := bufio.NewScanner(body)
	var allowed, disallowed []string

	for scanner.Scan() {
		line := scanner.Text()
		extractDirectories(line, &allowed, &disallowed)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading robots.txt for %s: %v\n", domain, err)
		return
	}

	if enableSave {
		saveAsText(filename, allowed, disallowed, domain)
	}
}

func extractDirectories(line string, allowed, disallowed *[]string) {
	re := regexp.MustCompile(`(?i)^(Allow:|Disallow:)\s*(.*)`)
	matches := re.FindStringSubmatch(line)

	if len(matches) == 3 {
		directory := strings.TrimSpace(matches[2])
		if strings.HasPrefix(directory, "/") {
			if strings.EqualFold(matches[1], "Allow:") {
				*allowed = append(*allowed, directory)
			} else {
				*disallowed = append(*disallowed, directory)
			}
		}
	}
}

func saveAsText(filename string, allowed, disallowed []string, domain string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	animateSaving(domain)

	baseURL := "https://" + domain

	fmt.Fprintf(file, "Robots.txt for %s\n", domain)
	fmt.Fprintf(file, "\nAllowed URLs:\n")
	for _, dir := range allowed {
		fullURL := baseURL + dir
		if _, err := file.WriteString(fullURL + "\n"); err != nil {
			log.Printf("Error writing to file: %v\n", err)
		}
	}

	fmt.Fprintf(file, "\nDisallowed URLs:\n")
	for _, dir := range disallowed {
		fullURL := baseURL + dir
		if _, err := file.WriteString(fullURL + "\n"); err != nil {
			log.Printf("Error writing to file: %v\n", err)
		}
	}
	log.Printf("Saved directories to %s\n", filename)
}

func animateSaving(domain string) {
	message := fmt.Sprintf("Saving results for %s...", domain)
	lowerstr := message

	for x := 0; x <= len(lowerstr); x++ {
		s := "\r" + lowerstr[0:x] + lowerstr[x:] + "\033[K"
		fmt.Print(s)
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Print("\n")
}

func usage() {
	fmt.Println("Usage: go run main.go -d <domain1,domain2,...> [-s <filename>]")
	fmt.Println("Options:")
	fmt.Println("  -d, --domain    Specify one or more domains to scrape, separated by commas.")
	fmt.Println("  -s, --save      Specify a filename to save the output in text format. (default: output.txt)")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}

	var domains []string
	var enableSave bool
	var filename string = "output.txt"

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	var wg sync.WaitGroup
	client := &http.Client{}

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-d", "--domain":
			if i+1 < len(os.Args) {
				domains = strings.Split(os.Args[i+1], ",")
				i++
			} else {
				usage()
				return
			}
		case "-s", "--save":
			if i+1 < len(os.Args) {
				enableSave = true
				filename = os.Args[i+1]
				i++
			} else {
				usage()
				return
			}
		default:
			log.Println("ERROR: Incorrect argument or syntax")
			usage()
			return
		}
	}

	for _, domain := range domains {
		select {
		case <-stop:
			log.Println("Shutting down gracefully...")
			wg.Wait()
			return
		default:
			wg.Add(1)
			go getRobots(domain, enableSave, filename, client, &wg)
		}
	}
	wg.Wait()
}
