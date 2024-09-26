package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func getRobots(domain string, enableSave bool, filename string) {
	fmt.Printf("Starting RobotScraper to recollect directories and pages from robots.txt in %s\n", domain)

	resp, err := http.Get("https://" + domain + "/robots.txt")
	if err != nil {
		fmt.Printf("Error fetching robots.txt: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("File robots.txt exists:")
		scanner := bufio.NewScanner(resp.Body)

		var directories []string

		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line) // Display the line in the terminal

			if strings.HasPrefix(line, "Allow:") || strings.HasPrefix(line, "Disallow:") {
				directory := strings.TrimSpace(strings.Replace(line, "Allow:", "", 1))
				directory = strings.TrimSpace(strings.Replace(directory, "Disallow:", "", 1))

				if strings.HasPrefix(directory, "/") {
					newDomain := "https://" + domain + directory
					r2, err := http.Get(newDomain)
					if err == nil {
						fmt.Printf("Checking %s ", newDomain)
						if r2.StatusCode == 200 {
							fmt.Printf("[✓] Obtained a 200 OK success status response code in directory: %s\n", directory)
							if enableSave {
								directories = append(directories, directory)
							}
						} else if r2.StatusCode == 302 {
							fmt.Printf("[✓] Obtained a 302 Found redirect status response code in directory: %s\n", directory)
						} else {
							fmt.Printf("[✗] Obtained a %d status response code in directory: %s\n", r2.StatusCode, directory)
						}
						r2.Body.Close()
					} else {
						fmt.Printf("Error checking %s: %v\n", newDomain, err)
					}
				}
			}
		}

		if enableSave {
			file, err := os.Create(filename)
			if err != nil {
				fmt.Printf("Error creating file: %v\n", err)
				return
			}
			defer file.Close()

			for _, dir := range directories {
				file.WriteString(dir + "\n")
			}
		}
	} else {
		fmt.Printf("robots.txt file not found. Status code: %d\n", resp.StatusCode)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("ERROR: No domain or parameters found")
		return
	}

	var domain string
	var enableSave bool
	var filename string

	if os.Args[1] == "-d" || os.Args[1] == "--domain" {
		domain = os.Args[2]
		if len(os.Args) > 3 && (os.Args[3] == "-s" || os.Args[3] == "--save") {
			enableSave = true
			filename = os.Args[4]
		}
		getRobots(domain, enableSave, filename)
	} else {
		fmt.Println("ERROR: Incorrect argument or syntax")
	}
}
